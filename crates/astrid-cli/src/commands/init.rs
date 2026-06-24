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

/// Default distro name when none specified.
const DEFAULT_DISTRO: &str = "astralis";

/// Default GitHub org for distro repos.
const DEFAULT_ORG: &str = "unicity-astrid";

/// Run the init flow: workspace setup + distro-based capsule installation.
pub(crate) async fn run_init(distro_source: &str) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    home.ensure()?;

    // Workspace init (existing behaviour).
    init_workspace()?;

    // Check lockfile — if fresh, we're already initialized.
    let principal = astrid_core::PrincipalId::default();
    let lock_path = home
        .principal_home(&principal)
        .config_dir()
        .join("distro.lock");

    // Fetch and parse the distro manifest.
    let manifest = fetch_and_parse_manifest(distro_source).await?;

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

    let selected = select_capsules(manifest.capsules)?;

    // Collect variables needed by selected capsules.
    let vars = collect_variables(&variables, &selected)?;

    // Write per-capsule env files BEFORE installing capsules so that
    // install_capsule's onboarding check finds existing values and
    // doesn't re-prompt for fields the distro already configured.
    write_env_files(&home, &selected, &vars)?;

    // Install each capsule with progress.
    let locked = install_capsules(&selected).await?;

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
async fn fetch_and_parse_manifest(source: &str) -> anyhow::Result<DistroManifest> {
    // Local file path.
    let path = std::path::Path::new(source);
    if path.exists() && path.is_file() {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        return parse_manifest(&content);
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
/// included. Capsules with a group are presented for multi-select.
/// Takes ownership of the manifest's capsule list to avoid cloning.
fn select_capsules(capsules: Vec<DistroCapsule>) -> anyhow::Result<Vec<DistroCapsule>> {
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

/// Prompt for distro-level variables needed by the selected capsules.
/// Only prompts for variables that are actually referenced by a selected capsule's env.
fn collect_variables(
    variables: &HashMap<String, super::distro::manifest::VariableDef>,
    selected: &[DistroCapsule],
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

/// Install each selected capsule with a progress bar.
async fn install_capsules(selected: &[DistroCapsule]) -> anyhow::Result<Vec<LockedCapsule>> {
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

        if let Err(e) =
            super::capsule::install::install_capsule_batch(&cap.source, Some(&cap.name), false)
                .await
        {
            eprintln!("\n  Failed to install {}: {e}", cap.name);
            failed.push(cap.name.clone());
            pb.inc(1);
            continue;
        }

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
fn write_env_files(
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
}
