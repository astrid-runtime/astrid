//! Init command — first-run distro installation and workspace setup.
//!
//! Fetches a `Distro.toml` manifest, lets the user select providers,
//! prompts for shared variables, installs all selected capsules, and
//! writes a `Distro.lock` for reproducibility.

use std::collections::HashMap;
use std::io::Write;

use anyhow::{Context, bail};
use astrid_core::dirs::AstridHome;
use indicatif::{ProgressBar, ProgressStyle};

use super::distro::lock::{
    DistroLock, DistroLockMeta, LockedCapsule, is_lock_fresh, load_lock, write_lock,
};
use super::distro::manifest::{DistroCapsule, DistroManifest, parse_manifest};
use crate::theme::Theme;

/// Default GitHub org for distro repos.
const DEFAULT_ORG: &str = "unicity-astrid";

/// Options controlling the init / `distro apply` flow.
///
/// Carries the headless and trust flags so the interactive prompts can
/// be bypassed (`--yes`), network access forbidden (`--offline`), and
/// signing posture chosen (`--allow-unsigned`, `--accept-new-key`).
#[derive(Debug, Clone, Default)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "distinct CLI flag toggles, not a state machine"
)]
pub(crate) struct InitOpts {
    /// Non-interactive: accept all defaults, never read stdin.
    pub(crate) yes: bool,
    /// Forbid all network access — install only from local/`.shuttle`.
    pub(crate) offline: bool,
    /// Allow installing a distro that ships no signature.
    pub(crate) allow_unsigned: bool,
    /// Accept and re-pin a signing key that differs from the pinned one.
    pub(crate) accept_new_key: bool,
    /// Pre-supplied variable values from `--var KEY=VALUE`.
    pub(crate) vars: HashMap<String, String>,
}

/// Parse `--var KEY=VALUE` strings into a map.
///
/// Splits on the first `=`. A missing `=` or empty key is an error.
pub(crate) fn parse_cli_vars(raw: &[String]) -> anyhow::Result<HashMap<String, String>> {
    let mut map = HashMap::new();
    for item in raw {
        let (key, value) = item
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("--var must be KEY=VALUE (got {item:?})"))?;
        if key.is_empty() {
            bail!("--var has an empty key (got {item:?})");
        }
        map.insert(key.to_string(), value.to_string());
    }
    Ok(map)
}

/// Run the init flow: workspace setup + distro-based capsule installation.
pub(crate) async fn run_init(distro_source: &str, opts: &InitOpts) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    home.ensure()?;

    // Workspace init (existing behaviour).
    init_workspace()?;

    // Offline, signed, self-contained install path.
    if distro_source.ends_with(".shuttle") {
        return run_init_from_shuttle(distro_source, opts);
    }

    // Check lockfile — if fresh, we're already initialized.
    let principal = astrid_core::PrincipalId::default();
    let lock_path = home
        .principal_home(&principal)
        .config_dir()
        .join("distro.lock");

    // Fetch and parse the distro manifest. Network is forbidden under
    // --offline unless the source resolves to a local file.
    let manifest = fetch_and_parse_manifest(distro_source, opts.offline).await?;

    // Enforce the distro's CLI-version floor BEFORE any prompting or install.
    // The manifest is fetched from the repo `main` tip, so a distro that bumps
    // its `[distro].astrid-version` would otherwise break onboarding mid-flight
    // on an older CLI; fail fast with an actionable upgrade message instead.
    super::distro::validate::enforce_astrid_version(&manifest)?;

    // Check lock freshness AFTER parsing manifest (need manifest to compare).
    if let Some(existing_lock) = load_lock(&lock_path)?
        && is_lock_fresh(&existing_lock, &manifest)
    {
        eprintln!(
            "{}",
            Theme::info(&format!(
                "{} is already installed (Distro.lock is up to date)",
                manifest
                    .distro
                    .pretty_name
                    .as_deref()
                    .unwrap_or(&manifest.distro.name),
            ))
        );
        return Ok(());
    }

    // Display distro info.
    let display_name = manifest
        .distro
        .pretty_name
        .as_deref()
        .unwrap_or(&manifest.distro.name);
    eprintln!("{}", Theme::header(&format!("Installing {display_name}")));
    if let Some(ref desc) = manifest.distro.description {
        eprintln!("  {desc}");
    }
    eprintln!();

    // Select providers (multi-select per group).
    // Extract fields we need before consuming capsules.
    let variables = manifest.variables;
    let distro_id = manifest.distro.id;
    let distro_version = manifest.distro.version;
    let schema_version = manifest.schema_version;

    let selected = select_capsules(manifest.capsules, opts.yes)?;

    // Collect variables needed by selected capsules.
    let vars = collect_variables(&variables, &selected, opts.yes, &opts.vars)?;

    // Write per-capsule env files BEFORE installing capsules so that
    // install_capsule's onboarding check finds existing values and
    // doesn't re-prompt for fields the distro already configured.
    write_env_files(&home, &selected, &vars)?;

    // Install each capsule with progress.
    let locked = install_capsules(&selected, opts.offline).await?;

    // Per-provider onboarding: for each selected llm-group capsule, run its
    // own `[env]` schema prompt so capsule-specific fields (api_key,
    // base_url) and the dynamic `model` select resolve from the installed
    // manifest — not just the shared free-text `[variables]`. Shared values
    // already written above are preserved (the prompt skips set keys).
    onboard_llm_providers(&home, &selected);

    // Write Distro.lock.
    let lock = create_lock_from_parts(schema_version, &distro_id, &distro_version, locked);
    write_lock(&lock_path, &lock)?;

    eprintln!();
    eprintln!("{}", Theme::success("Installation complete."));
    eprintln!("  Run {} to start.", Theme::prompt("astrid"));

    Ok(())
}

/// Install a distro from a signed, self-contained `.shuttle` archive.
///
/// Implemented in [`super::distro::shuttle_install`] (Part C/D): unpack
/// to a mirror, verify the signature against the trust store, then
/// install each capsule offline from the mirror.
fn run_init_from_shuttle(source: &str, opts: &InitOpts) -> anyhow::Result<()> {
    super::distro::shuttle_install::install_from_shuttle(std::path::Path::new(source), opts)
}

/// Initialize the current directory as an Astrid workspace (if not already).
fn init_workspace() -> anyhow::Result<()> {
    let cwd = std::env::current_dir()?;
    let ws = astrid_core::dirs::WorkspaceDir::from_path(&cwd);

    if !ws.dot_astrid().exists() {
        ws.ensure()?;
        let config_path = ws.dot_astrid().join("config.toml");
        if !config_path.exists() {
            std::fs::write(
                &config_path,
                "# Astrid workspace configuration\n\
                 # See docs for available options.\n",
            )?;
        }
    }
    Ok(())
}

/// Resolve a distro source string to a raw GitHub URL.
///
/// - `astralis` → `https://raw.githubusercontent.com/unicity-astrid/astralis/main/Distro.toml`
/// - `@org/repo` → `https://raw.githubusercontent.com/org/repo/main/Distro.toml`
/// - `https://...` → as-is
fn resolve_distro_url(source: &str) -> String {
    if source.starts_with("http://") || source.starts_with("https://") {
        source.to_string()
    } else if let Some(repo_path) = source.strip_prefix('@') {
        format!("https://raw.githubusercontent.com/{repo_path}/main/Distro.toml")
    } else {
        format!("https://raw.githubusercontent.com/{DEFAULT_ORG}/{source}/main/Distro.toml")
    }
}

/// Resolve a distro source string to a manifest URL or path, then parse it.
///
/// When `offline` is set, only a local file is acceptable — any source
/// that would require a network fetch is a hard error.
async fn fetch_and_parse_manifest(source: &str, offline: bool) -> anyhow::Result<DistroManifest> {
    // Local file path.
    let path = std::path::Path::new(source);
    if path.exists() && path.is_file() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return parse_manifest(&content);
    }

    if offline {
        bail!(
            "--offline: '{source}' is not a local file and network fetch is forbidden \
             (use a Distro.toml path or a .shuttle archive)"
        );
    }

    let url = resolve_distro_url(source);

    eprintln!("Fetching distro manifest...");

    let client = reqwest::Client::builder()
        .user_agent("astrid-cli")
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let response = client
        .get(&url)
        .send()
        .await
        .context("failed to fetch distro manifest")?;

    if !response.status().is_success() {
        bail!(
            "failed to fetch distro manifest from {url} (HTTP {})",
            response.status(),
        );
    }

    // Stream response body with 1 MB limit to prevent abuse from untrusted URLs.
    let mut bytes = Vec::new();
    let mut response = response;
    while let Some(chunk) = response.chunk().await? {
        bytes.extend_from_slice(&chunk);
        anyhow::ensure!(
            bytes.len() <= 1024 * 1024,
            "distro manifest exceeds 1 MB limit",
        );
    }
    let content = std::str::from_utf8(&bytes).context("distro manifest contains invalid UTF-8")?;

    parse_manifest(content)
}

/// Parse a comma-separated multi-select entry into a deduped, ordered list
/// of 1-based indices, dropping anything out of `[1, count]` or unparseable.
///
/// Order follows the user's entry; duplicates are collapsed to the first
/// occurrence so selecting `1,1,2` installs each provider once.
fn parse_provider_selection(input: &str, count: usize) -> Vec<usize> {
    let mut seen = std::collections::HashSet::new();
    input
        .split(',')
        .filter_map(|s| s.trim().parse::<usize>().ok())
        .filter(|&n| n >= 1 && n <= count)
        .filter(|&n| seen.insert(n))
        .collect()
}

/// Select which capsules to install. Capsules without a group are always
/// included. Capsules with a group are presented for multi-select
/// (interactive) or resolved from their `default` flag (`--yes`).
/// Takes ownership of the manifest's capsule list to avoid cloning.
pub(crate) fn select_capsules(
    capsules: Vec<DistroCapsule>,
    yes: bool,
) -> anyhow::Result<Vec<DistroCapsule>> {
    if yes {
        return select_capsules_headless(capsules);
    }
    let mut selected = Vec::new();
    let mut groups: HashMap<String, Vec<DistroCapsule>> = HashMap::new();

    for cap in capsules {
        if let Some(ref group) = cap.group {
            groups.entry(group.clone()).or_default().push(cap);
        } else {
            selected.push(cap);
        }
    }

    for (group_name, group_caps) in &groups {
        if group_name == "llm" {
            eprintln!("Which LLM provider(s) do you want to set up?");
        } else {
            eprintln!("Select {group_name} provider(s):");
        }
        for (i, cap) in group_caps.iter().enumerate() {
            eprintln!("  [{}] {}", i.saturating_add(1), cap.name);
        }

        eprint!("Enter numbers (comma-separated, e.g. 1,2): ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        let choices = parse_provider_selection(&input, group_caps.len());

        if choices.is_empty() {
            eprintln!("  No selection — defaulting to {}", group_caps[0].name);
            selected.push(group_caps[0].clone());
        } else {
            for idx in choices {
                selected.push(group_caps[idx.saturating_sub(1)].clone());
            }
        }
        eprintln!();
    }

    Ok(selected)
}

/// Non-interactive capsule selection (`--yes`): ungrouped capsules are
/// always taken; each group contributes its `default = true` member(s).
/// A group with no default warns and falls back to its first capsule
/// (deterministic — manifest order), so a misconfigured manifest still
/// produces a working install rather than aborting.
fn select_capsules_headless(capsules: Vec<DistroCapsule>) -> anyhow::Result<Vec<DistroCapsule>> {
    let mut selected = Vec::new();
    // Preserve manifest order within each group for deterministic
    // fallback; iterate groups in sorted order for stable warnings.
    let mut groups: HashMap<String, Vec<DistroCapsule>> = HashMap::new();
    for cap in capsules {
        match &cap.group {
            None => selected.push(cap),
            Some(group) => groups.entry(group.clone()).or_default().push(cap),
        }
    }

    let mut group_names: Vec<String> = groups.keys().cloned().collect();
    group_names.sort_unstable();
    for group_name in group_names {
        let group_caps = groups.remove(&group_name).unwrap_or_default();
        let defaults: Vec<DistroCapsule> =
            group_caps.iter().filter(|c| c.default).cloned().collect();
        if defaults.is_empty() {
            let first = group_caps
                .first()
                .ok_or_else(|| anyhow::anyhow!("group '{group_name}' has no capsules"))?;
            eprintln!(
                "{}",
                Theme::warning(&format!(
                    "group '{group_name}' has no default capsule — selecting first: {}",
                    first.name
                ))
            );
            selected.push(first.clone());
        } else {
            selected.extend(defaults);
        }
    }

    Ok(selected)
}

/// Prompt for distro-level variables needed by the selected capsules.
/// Only prompts for variables that are actually referenced by a selected capsule's env.
pub(crate) fn collect_variables(
    variables: &HashMap<String, super::distro::manifest::VariableDef>,
    selected: &[DistroCapsule],
    yes: bool,
    cli_vars: &HashMap<String, String>,
) -> anyhow::Result<HashMap<String, String>> {
    // Collect all variable references from selected capsules.
    let mut needed_vars: std::collections::HashSet<String> = std::collections::HashSet::new();
    for cap in selected {
        for value in cap.env.values() {
            for var in extract_var_refs(value) {
                needed_vars.insert(var.to_string());
            }
        }
    }

    if needed_vars.is_empty() {
        return Ok(HashMap::new());
    }

    if yes {
        return collect_variables_headless(variables, &needed_vars, cli_vars, |k| {
            std::env::var(k).ok()
        });
    }

    eprintln!("Configuration:");
    let mut vars = HashMap::new();

    // Sort for deterministic prompt order.
    let mut sorted_vars: Vec<&str> = needed_vars.iter().map(String::as_str).collect();
    sorted_vars.sort_unstable();

    for var_name in sorted_vars {
        let Some(def) = variables.get(var_name) else {
            continue;
        };

        let desc = def.description.as_deref().unwrap_or(var_name);
        let default_hint = def
            .default
            .as_ref()
            .map(|d| format!(" [{d}]"))
            .unwrap_or_default();

        eprint!("  {desc}{default_hint}: ");
        std::io::stderr().flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();

        let value = if input.is_empty() {
            def.default.clone().unwrap_or_default()
        } else {
            input.to_string()
        };

        if !value.is_empty() {
            vars.insert(var_name.to_string(), value);
        }
    }

    eprintln!();
    Ok(vars)
}

/// Non-interactive variable resolution (`--yes`).
///
/// For each needed variable, the value is taken from (in priority
/// order): a `--var KEY=VALUE` override, the `ASTRID_VAR_<KEY>` env var
/// (key uppercased), or the manifest default. A variable with none of
/// these is a hard error with an actionable message. Secret values are
/// never logged.
fn collect_variables_headless(
    variables: &HashMap<String, super::distro::manifest::VariableDef>,
    needed_vars: &std::collections::HashSet<String>,
    cli_vars: &HashMap<String, String>,
    env_lookup: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<HashMap<String, String>> {
    let mut vars = HashMap::new();
    let mut sorted: Vec<&str> = needed_vars.iter().map(String::as_str).collect();
    sorted.sort_unstable();

    for var_name in sorted {
        let env_key = format!("ASTRID_VAR_{}", var_name.to_uppercase());
        let var_def = variables.get(var_name);
        let value = cli_vars
            .get(var_name)
            .cloned()
            .or_else(|| env_lookup(&env_key))
            .or_else(|| var_def.and_then(|d| d.default.clone()))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "required variable '{var_name}' has no value \
                     (no --var {var_name}=…, no {env_key}, no default)"
                )
            })?;

        let is_secret = var_def.is_some_and(|d| d.secret);
        if is_secret {
            tracing::debug!(var = %var_name, "resolved distro variable [secret]");
        } else {
            tracing::debug!(var = %var_name, value = %value, "resolved distro variable");
        }

        vars.insert(var_name.to_string(), value);
    }

    Ok(vars)
}

/// Create a lockfile from resolved parts (avoids borrowing the full manifest).
fn create_lock_from_parts(
    schema_version: u32,
    distro_id: &str,
    distro_version: &str,
    capsules: Vec<LockedCapsule>,
) -> DistroLock {
    DistroLock {
        schema_version,
        distro: DistroLockMeta {
            id: distro_id.to_string(),
            version: distro_version.to_string(),
            resolved_at: chrono::Utc::now().to_rfc3339(),
        },
        capsules,
        manifest_hash: None,
    }
}

/// Extract `{{ var }}` references from a template string.
fn extract_var_refs(template: &str) -> Vec<&str> {
    template
        .split("{{")
        .skip(1)
        .filter_map(|s| s.split_once("}}"))
        .map(|(var, _)| var.trim())
        .filter(|var| !var.is_empty())
        .collect()
}

/// Resolve `{{ var }}` references in a template string with values.
fn resolve_template(template: &str, vars: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        let pattern = format!("{{{{ {key} }}}}");
        result = result.replace(&pattern, value);
        // Also handle no-space variant.
        let compact = format!("{{{{{key}}}}}");
        result = result.replace(&compact, value);
    }
    result
}

/// Whether a capsule `source` would have to touch the network to install.
///
/// Only GitHub-backed shapes (`@org/repo`, `github.com/…`,
/// `https://github.com/…`) are network sources; everything else — including
/// a relative local path like `capsules/cli.capsule` — installs straight
/// from disk. This is the predicate the `--offline` guard rejects on, so it
/// must NOT reject a bare relative path the way the old `starts_with('.')`
/// /`starts_with('/')` check wrongly did.
fn is_network_capsule_source(source: &str) -> bool {
    astrid_capsule_install::github_source::parse_github_source(source.trim()).is_some()
}

/// Install each selected capsule with a progress bar.
///
/// Under `offline`, a capsule whose source is GitHub-backed is a hard
/// error — the `--offline` contract forbids any network, and a remote
/// `@org/repo` capsule in a local `Distro.toml` would otherwise silently
/// fetch from GitHub. A local path (relative or absolute) installs from
/// disk and is allowed. (A fully self-contained offline install uses a
/// `.shuttle` instead.)
async fn install_capsules(
    selected: &[DistroCapsule],
    offline: bool,
) -> anyhow::Result<Vec<LockedCapsule>> {
    if offline {
        for cap in selected {
            if is_network_capsule_source(&cap.source) {
                bail!(
                    "--offline: capsule '{}' has a network/GitHub source '{}' — \
                     refusing to fetch. Use a .shuttle archive for a self-contained \
                     offline install.",
                    cap.name,
                    cap.source
                );
            }
        }
    }

    let total = selected.len();
    let pb = ProgressBar::new(total as u64);
    pb.set_style(
        ProgressStyle::with_template("  [{bar:30}] {pos}/{len} {msg}")
            .expect("valid template")
            .progress_chars("=> "),
    );

    let mut locked = Vec::with_capacity(total);
    let mut failed = Vec::new();
    let home = AstridHome::resolve()?;

    for cap in selected {
        pb.set_message(cap.name.clone());

        let refspec = super::capsule::install::RefSpec::from_capsule(cap);
        // The installer returns the ref it ACTUALLY resolved and fetched
        // (`Some` for GitHub sources, `None` for local paths). Record
        // that — never a guess derived from the manifest fields — so the
        // lock attests what was truly installed. `Some(&cap.name)` is the
        // name hint used to pick the right archive from a multi-asset
        // release.
        let resolved_ref = match super::capsule::install::install_capsule_batch(
            &cap.source,
            Some(&cap.name),
            false,
            &refspec,
        )
        .await
        {
            Ok(resolved_ref) => resolved_ref,
            Err(e) => {
                eprintln!("\n  Failed to install {}: {e}", cap.name);
                failed.push(cap.name.clone());
                pb.inc(1);
                continue;
            },
        };

        // Read the installed meta to get the wasm_hash for the lock.
        let target_dir = super::capsule::install::resolve_target_dir(&home, &cap.name, false)?;
        let meta = super::capsule::meta::read_meta(&target_dir);

        locked.push(LockedCapsule {
            name: cap.name.clone(),
            version: cap.version.clone(),
            source: cap.source.clone(),
            hash: meta
                .and_then(|m| m.wasm_hash)
                .map(|h| format!("blake3:{h}"))
                .unwrap_or_default(),
            resolved_ref,
        });

        pb.inc(1);
    }

    pb.finish_and_clear();

    if failed.is_empty() {
        eprintln!("  Installed {total} capsule(s).");
    } else {
        eprintln!(
            "  Installed {} capsule(s), {} failed: {}",
            total.saturating_sub(failed.len()),
            failed.len(),
            failed.join(", "),
        );
    }

    Ok(locked)
}

/// Write per-capsule .env.json files with resolved variable templates.
pub(crate) fn write_env_files(
    home: &AstridHome,
    selected: &[DistroCapsule],
    vars: &HashMap<String, String>,
) -> anyhow::Result<()> {
    let principal = astrid_core::PrincipalId::default();
    let env_dir = home.principal_home(&principal).env_dir();
    std::fs::create_dir_all(&env_dir)?;

    for cap in selected {
        if cap.env.is_empty() {
            continue;
        }

        let env_path = env_dir.join(format!("{}.env.json", cap.name));
        if env_path.exists() {
            // Don't overwrite existing env config — user may have customized.
            continue;
        }

        let mut resolved: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        for (key, template) in &cap.env {
            // Write all keys — even empty values. An empty string means
            // "use default" and prevents install-time onboarding from
            // re-prompting for fields the distro already configured.
            let value = resolve_template(template, vars);
            resolved.insert(key.clone(), serde_json::Value::String(value));
        }

        if !resolved.is_empty() {
            let json = serde_json::to_string_pretty(&resolved)?;
            std::fs::write(&env_path, &json)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&env_path, std::fs::Permissions::from_mode(0o600))?;
            }
        }
    }

    Ok(())
}

/// Run per-provider env onboarding for selected `group = "llm"` capsules.
///
/// Non-llm capsules are configured entirely from the distro's shared
/// `[variables]` (templated into env files before install). LLM providers,
/// by contrast, own capsule-specific fields — credentials and a model that
/// is best chosen from a live list — so each selected llm capsule runs its
/// own `[env]` schema prompt here, after install (the manifest is on disk).
///
/// The prompt skips keys that already hold a non-empty value, so any
/// `[variables]`-templated shared values survive. Dynamic `model` selects
/// (declared via `options-from`) resolve their option list live at this
/// point. A missing manifest or env error for one provider is reported and
/// skipped — it never aborts the whole install.
fn onboard_llm_providers(home: &AstridHome, selected: &[DistroCapsule]) {
    let principal = astrid_core::PrincipalId::default();
    let env_dir = home.principal_home(&principal).env_dir();

    for cap in selected {
        if cap.group.as_deref() != Some("llm") {
            continue;
        }

        let target_dir = match super::capsule::install::resolve_target_dir(home, &cap.name, false) {
            Ok(dir) => dir,
            Err(e) => {
                eprintln!("  Skipping {} onboarding: {e}", cap.name);
                continue;
            },
        };
        let manifest_path = target_dir.join("Capsule.toml");
        let manifest = match astrid_capsule::discovery::load_manifest(&manifest_path) {
            Ok(m) => m,
            Err(e) => {
                eprintln!("  Skipping {} onboarding (no manifest): {e}", cap.name);
                continue;
            },
        };

        if manifest.env.is_empty() {
            continue;
        }

        eprintln!();
        eprintln!("{}", Theme::header(&format!("Configure {}", cap.name)));
        let env_path = env_dir.join(format!("{}.env.json", cap.name));
        if let Err(e) = super::capsule::install_prompts::prompt_env_fields(
            &manifest.env,
            &env_path,
            &cap.name,
            &home.config_path(),
        ) {
            eprintln!("  Configuration for {} failed: {e}", cap.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_selection_parses_multi_select() {
        assert_eq!(parse_provider_selection("1,2", 3), vec![1, 2]);
        assert_eq!(parse_provider_selection(" 2 , 3 ", 3), vec![2, 3]);
        assert_eq!(parse_provider_selection("1", 3), vec![1]);
    }

    #[test]
    fn provider_selection_drops_out_of_range_and_garbage() {
        assert_eq!(parse_provider_selection("0,4,2,abc", 3), vec![2]);
        assert!(parse_provider_selection("", 3).is_empty());
        assert!(parse_provider_selection("9,10", 3).is_empty());
    }

    #[test]
    fn provider_selection_dedupes_preserving_order() {
        assert_eq!(parse_provider_selection("2,1,2,1", 3), vec![2, 1]);
    }

    #[test]
    fn provider_selection_preserves_entry_order() {
        // User order is honoured (3 then 1), not numeric-sorted.
        assert_eq!(parse_provider_selection("3,1", 3), vec![3, 1]);
    }

    #[test]
    fn extract_var_refs_finds_all() {
        assert_eq!(extract_var_refs("{{ foo }}"), vec!["foo"]);
        assert_eq!(extract_var_refs("{{ a }}-{{ b }}"), vec!["a", "b"],);
        assert!(extract_var_refs("no vars").is_empty());
    }

    #[test]
    fn resolve_template_replaces_vars() {
        let mut vars = HashMap::new();
        vars.insert("key".to_string(), "secret123".to_string());
        vars.insert("url".to_string(), "https://api.example.com".to_string());

        assert_eq!(resolve_template("{{ key }}", &vars), "secret123",);
        assert_eq!(
            resolve_template("prefix-{{ url }}-suffix", &vars),
            "prefix-https://api.example.com-suffix",
        );
    }

    #[test]
    fn resolve_template_handles_missing_var() {
        let vars = HashMap::new();
        // Unresolved template stays as-is.
        assert_eq!(resolve_template("{{ missing }}", &vars), "{{ missing }}",);
    }

    #[test]
    fn distro_source_resolution_bare_name() {
        assert_eq!(
            resolve_distro_url("astralis"),
            "https://raw.githubusercontent.com/unicity-astrid/astralis/main/Distro.toml",
        );
    }

    #[test]
    fn distro_source_resolution_at_prefix() {
        assert_eq!(
            resolve_distro_url("@myorg/mydistro"),
            "https://raw.githubusercontent.com/myorg/mydistro/main/Distro.toml",
        );
    }

    #[test]
    fn distro_source_resolution_full_url() {
        let url = "https://example.com/Distro.toml";
        assert_eq!(resolve_distro_url(url), url);
    }

    // ---- Part A: headless selection / variable resolution ----

    use super::super::distro::manifest::{DistroCapsule, VariableDef};

    fn cap(name: &str, group: Option<&str>, default: bool) -> DistroCapsule {
        DistroCapsule {
            name: name.to_string(),
            source: format!("@org/{name}"),
            version: "0.1.0".to_string(),
            tag: None,
            branch: None,
            rev: None,
            default,
            group: group.map(String::from),
            role: None,
            env: HashMap::new(),
        }
    }

    #[test]
    fn parse_cli_vars_splits_first_equals() {
        let raw = vec!["A=1".to_string(), "URL=https://x?y=z".to_string()];
        let map = parse_cli_vars(&raw).unwrap();
        assert_eq!(map["A"], "1");
        assert_eq!(map["URL"], "https://x?y=z");
    }

    #[test]
    fn parse_cli_vars_rejects_no_equals() {
        assert!(parse_cli_vars(&["NOEQ".to_string()]).is_err());
        assert!(parse_cli_vars(&["=value".to_string()]).is_err());
    }

    #[test]
    fn headless_select_takes_defaults_and_ungrouped() {
        let caps = vec![
            cap("cli", None, false),
            cap("openai", Some("llm"), true),
            cap("anthropic", Some("llm"), false),
        ];
        let selected = select_capsules(caps, true).unwrap();
        let names: std::collections::HashSet<&str> =
            selected.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains("cli"), "ungrouped always selected");
        assert!(names.contains("openai"), "group default selected");
        assert!(!names.contains("anthropic"), "non-default not selected");
    }

    #[test]
    fn headless_select_falls_back_to_first_when_no_default() {
        let caps = vec![
            cap("cli", None, false),
            cap("alpha", Some("llm"), false),
            cap("beta", Some("llm"), false),
        ];
        let selected = select_capsules(caps, true).unwrap();
        let names: std::collections::HashSet<&str> =
            selected.iter().map(|c| c.name.as_str()).collect();
        // First in manifest order within the group is "alpha".
        assert!(names.contains("alpha"));
        assert!(!names.contains("beta"));
    }

    fn var(secret: bool, default: Option<&str>) -> VariableDef {
        VariableDef {
            secret,
            description: None,
            default: default.map(String::from),
        }
    }

    fn cap_with_env(name: &str, key: &str, template: &str) -> DistroCapsule {
        let mut c = cap(name, None, false);
        c.env.insert(key.to_string(), template.to_string());
        c
    }

    #[test]
    fn headless_collect_uses_cli_var_override() {
        let mut variables = HashMap::new();
        variables.insert("api_key".to_string(), var(true, Some("from-default")));
        let selected = vec![cap_with_env("llm", "API_KEY", "{{ api_key }}")];
        let mut cli = HashMap::new();
        cli.insert("api_key".to_string(), "from-cli".to_string());

        let vars = collect_variables(&variables, &selected, true, &cli).unwrap();
        assert_eq!(vars["api_key"], "from-cli");
    }

    #[test]
    fn headless_collect_uses_env_then_default() {
        let mut variables = HashMap::new();
        variables.insert("base_url".to_string(), var(false, Some("https://default")));
        let mut needed = std::collections::HashSet::new();
        needed.insert("base_url".to_string());

        // No CLI var, no env → default.
        let vars =
            collect_variables_headless(&variables, &needed, &HashMap::new(), |_| None).unwrap();
        assert_eq!(vars["base_url"], "https://default");

        // Env (ASTRID_VAR_BASE_URL) beats default — injected lookup, no
        // process-global state.
        let vars = collect_variables_headless(&variables, &needed, &HashMap::new(), |k| {
            (k == "ASTRID_VAR_BASE_URL").then(|| "https://from-env".to_string())
        })
        .unwrap();
        assert_eq!(vars["base_url"], "https://from-env");
    }

    #[tokio::test]
    async fn offline_refuses_remote_capsule_source() {
        // A local Distro.toml with a remote @org/repo capsule must not
        // silently fetch under --offline.
        let selected = vec![cap("llm", None, false)]; // source "@org/llm"
        let err = install_capsules(&selected, true).await.unwrap_err();
        assert!(err.to_string().contains("--offline"), "got: {err}");
        assert!(err.to_string().contains("network/GitHub"), "got: {err}");
    }

    #[test]
    fn offline_guard_blocks_only_github_sources() {
        // GitHub-backed shapes are network sources (rejected under --offline).
        assert!(is_network_capsule_source("@org/repo"));
        assert!(is_network_capsule_source("@org/repo@1.2.0"));
        assert!(is_network_capsule_source("github.com/org/repo"));
        assert!(is_network_capsule_source("https://github.com/org/repo"));

        // Local paths are NOT network sources — including a bare relative
        // path like `capsules/cli.capsule`, which the old guard wrongly
        // rejected because it didn't start with `.` or `/`.
        assert!(!is_network_capsule_source("capsules/cli.capsule"));
        assert!(!is_network_capsule_source("./capsules/cli.capsule"));
        assert!(!is_network_capsule_source("/abs/path/cli.capsule"));
        assert!(!is_network_capsule_source("cli.capsule"));
    }

    #[test]
    fn headless_collect_errors_on_missing_required_var() {
        let mut variables = HashMap::new();
        variables.insert("api_key".to_string(), var(true, None)); // no default
        let mut needed = std::collections::HashSet::new();
        needed.insert("api_key".to_string());

        let err =
            collect_variables_headless(&variables, &needed, &HashMap::new(), |_| None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("api_key"), "got: {msg}");
        assert!(msg.contains("ASTRID_VAR_API_KEY"), "got: {msg}");
    }
}
