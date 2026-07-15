//! Init command — first-run distro installation and workspace setup.
//!
//! Fetches a `Distro.toml` manifest, lets the user select providers,
//! prompts for shared variables, installs all selected capsules, and
//! writes a `Distro.lock` for reproducibility.

use std::collections::HashMap;
use std::io::Write;

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_core::dirs::AstridHome;
use indicatif::{ProgressBar, ProgressStyle};

use super::distro::lock::{
    DistroLock, DistroLockMeta, LockedCapsule, is_lock_fresh, load_lock, write_lock,
};
use super::distro::manifest::{DistroCapsule, DistroManifest, parse_manifest};
use crate::theme::Theme;

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
    /// Principal whose local home, capsule installs, env, lock, and grants
    /// this invocation provisions. The process principal is separately used
    /// to authenticate admin requests.
    pub(crate) target_principal: astrid_core::PrincipalId,
    /// Grant the target principal capsule-access for every capsule the
    /// distro installs, via the same kernel path as `astrid agent modify
    /// --add-capsule`. Only valid with a resolved distro. Opt-in: without it,
    /// `init` installs capsules but attaches no grants and
    /// prints the manual `agent modify` command for discoverability.
    pub(crate) grant_capsules: bool,
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
    let operator = crate::principal::current();
    let target = opts.target_principal.clone();

    // `--grant-capsules` is only meaningful when a distro install is
    // resolving the capsule set to grant. Reject an empty source up front so
    // the flag can never be silently honoured without a distro.
    grant::validate_grant_capsules(opts.grant_capsules, !distro_source.is_empty())?;

    // Offline, signed, self-contained install path. `--grant-capsules` is not
    // wired for `.shuttle` archives (the installed set isn't threaded back
    // here); fail loud rather than silently skip the grant the operator asked
    // for, pointing at the manual path.
    if distro_source.ends_with(".shuttle") {
        if opts.grant_capsules {
            bail!(
                "--grant-capsules is not supported for .shuttle installs yet — \
                 install first, then grant with `astrid --principal {operator} \
                 agent modify {target} \
                 --add-capsule <name>` for each installed capsule."
            );
        }
        home.ensure()?;
        let _provisioning_lock = grant::ProvisioningLock::acquire(&home, &target)?;
        init_workspace()?;
        return run_init_from_shuttle(distro_source, opts);
    }

    // Refuse an unauthorized or nonexistent grant target before creating any
    // local workspace, principal-home, env, capsule, or lock state.
    if opts.grant_capsules {
        grant::preflight_grants(&operator, &target).await?;
    }

    home.ensure()?;
    let _provisioning_lock = grant::ProvisioningLock::acquire(&home, &target)?;
    init_workspace()?;

    // Check lockfile — if fresh, we're already initialized. The lock lives
    // under the resolved principal's home, matching bootstrap's auto-init
    // freshness check (`should_auto_init`) so a scoped principal isn't
    // re-provisioned on every run.
    let lock_path = home
        .principal_home(&target)
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
        // Idempotent grant path: a re-run with `--grant-capsules` on an
        // already-installed principal still (re-)applies grants for the
        // locked capsule set. `apply_set_delta` dedups kernel-side, so a
        // principal that already holds them reports "no change" rather than
        // erroring or duplicating — and this is also how a first run whose
        // grant step failed (daemon was down) recovers on re-run.
        let installed = grant::validate_locked_capsules(&home, &target, &existing_lock.capsules)?;
        grant::apply_or_hint_grants(&operator, &target, &installed, opts.grant_capsules).await?;
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
    write_env_files(&home, &target, &selected, &vars)?;

    // Install each capsule with progress. `install_capsules` writes the
    // capsule files under `principal`'s home and returns one LockedCapsule
    // per capsule that actually installed — failures are reported and
    // dropped, so `locked.len()` is the true success count.
    let total = selected.len();
    let locked = install_capsules(&selected, opts.offline, &target).await?;
    let succeeded = locked.len();

    // Provisioning honesty: a run where every selected install FAILED must
    // not claim success, must not persist a Distro.lock, and must exit
    // non-zero. Writing a lock here would wedge recovery — the next `init`
    // would see a version-matched lock, pass the freshness gate above, and
    // short-circuit. An empty selection (nothing to install) is not a
    // failure.
    if total > 0 && succeeded == 0 {
        bail!(
            "all {total} capsule install(s) failed — not writing Distro.lock. \
             Fix the errors above and re-run `astrid init`."
        );
    }

    // Per-provider onboarding runs only on a FULL success — a partial run
    // isn't finalized, and its re-run will onboard once it converges. For
    // each selected llm-group capsule this runs its own `[env]` schema
    // prompt so capsule-specific fields (api_key, base_url) and the dynamic
    // `model` select resolve from the installed manifest — not just the
    // shared free-text `[variables]`. Shared values already written above
    // are preserved (the prompt skips set keys).
    if should_write_lock(total, succeeded) {
        onboard_llm_providers(&home, &target, &selected);
    }

    // Persist Distro.lock iff the run earned it (full success or empty
    // selection). A partial run deliberately writes NO lock so a re-run
    // actually retries the missing capsules instead of short-circuiting at
    // the freshness gate (`is_lock_fresh` diffs only distro id+version, not
    // the capsule set) — see `should_write_lock`.
    // Capture the names that actually installed BEFORE `locked` is consumed
    // into the lock — the grant set is EXACTLY this locally-resolved set, never
    // a manifest-declared string the installer didn't land (security stance:
    // grants derive from what was installed, on explicit `--grant-capsules`).
    let installed_names: Vec<String> = locked.iter().map(|c| c.name.clone()).collect();
    let lock = create_lock_from_parts(schema_version, &distro_id, &distro_version, locked);
    let wrote_lock = persist_lock_if_earned(&lock_path, total, succeeded, &lock)?;

    eprintln!();
    if wrote_lock {
        eprintln!("{}", Theme::success("Installation complete."));
        // Apply capsule grants (opt-in) or print the discoverability hint.
        // On a grant failure the capsules are already installed and the lock
        // is written; this returns Err so init exits non-zero with the exact
        // manual command to finish.
        grant::apply_or_hint_grants(&operator, &target, &installed_names, opts.grant_capsules)
            .await?;
        eprintln!("  Run {} to start.", Theme::prompt("astrid"));
        Ok(())
    } else {
        // Partial provision (0 < succeeded < total): no lock was written, so
        // a re-run retries the rest. Exit NON-ZERO so automation and the
        // in-conversation flow don't read a partial install as success —
        // `astrid init` exits 0 IFF the distro is fully provisioned.
        bail!(
            "Installation incomplete: {succeeded}/{total} capsule(s) installed — \
             re-run `astrid init` to retry the rest."
        )
    }
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

/// Resolve an explicit remote distro source string to a URL.
///
/// - `@org/repo` → `https://raw.githubusercontent.com/org/repo/main/Distro.toml`
/// - `https://...` → as-is
///
/// A bare name has no provenance and is rejected rather than being silently
/// assigned to an organization by the neutral runtime.
fn resolve_distro_url(source: &str) -> anyhow::Result<String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        Ok(source.to_string())
    } else if let Some(repo_path) = source.strip_prefix('@') {
        let mut segments = repo_path.split('/');
        let valid = matches!(
            (segments.next(), segments.next(), segments.next()),
            (Some(owner), Some(repo), None) if !owner.is_empty() && !repo.is_empty()
        );
        if !valid {
            bail!(
                "distro source '{source}' must use @owner/repo, a URL, a local Distro.toml path, or a .shuttle archive"
            );
        }
        Ok(format!(
            "https://raw.githubusercontent.com/{repo_path}/main/Distro.toml"
        ))
    } else {
        bail!(
            "distro source '{source}' must use @owner/repo, a URL, a local Distro.toml path, or a .shuttle archive"
        )
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

    let url = resolve_distro_url(source)?;

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

/// Whether a provision run should persist a `Distro.lock`.
///
/// Only a FULL success (`succeeded == total`) or an empty selection
/// (`total == 0`, nothing to install) writes a lock. A PARTIAL run writes
/// NO lock, and this is the crux of the correctness contract: the freshness
/// gate (`is_lock_fresh`) compares only the distro id + version, NOT which
/// capsules landed. A partial lock would match on version, so the next
/// `astrid init` would judge itself already provisioned and short-circuit —
/// the capsules that failed would never retry. Because `install_capsule_batch`
/// reinstalls idempotently, withholding the lock lets a re-run re-attempt
/// every capsule and converge to a full success, which then writes the lock.
/// A wholly-failed run also writes no lock (and additionally bails non-zero).
fn should_write_lock(total: usize, succeeded: usize) -> bool {
    total == 0 || succeeded == total
}

/// Persist `lock` at `lock_path` iff the run earned it (see
/// [`should_write_lock`]). Returns whether the lock was written, so the
/// caller can pick the honest completion message. Kept as a small helper so
/// the "partial run leaves no lock on disk" invariant is unit-testable
/// without a network install.
fn persist_lock_if_earned(
    lock_path: &std::path::Path,
    total: usize,
    succeeded: usize,
    lock: &DistroLock,
) -> anyhow::Result<bool> {
    if should_write_lock(total, succeeded) {
        write_lock(lock_path, lock)?;
        return Ok(true);
    }
    Ok(false)
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
    principal: &astrid_core::PrincipalId,
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
    for cap in selected {
        pb.set_message(cap.name.clone());

        let expected = CapsuleId::new(cap.name.clone())?;
        let refspec = super::capsule::install::RefSpec::from_capsule(cap);
        // The installer returns the ref it ACTUALLY resolved and fetched
        // (`Some` for GitHub sources, `None` for local paths). Record
        // that — never a guess derived from the manifest fields — so the
        // lock attests what was truly installed. `Some(&cap.name)` is the
        // name hint used to pick the right archive from a multi-asset
        // release.
        let outcome = match super::capsule::install::install_capsule_batch(
            &cap.source,
            &expected,
            false,
            &refspec,
            principal,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(e) => {
                eprintln!("\n  Failed to install {}: {e}", cap.name);
                failed.push(cap.name.clone());
                pb.inc(1);
                continue;
            },
        };
        let verified = match validate_batch_install(&expected, &cap.version, outcome) {
            Ok(verified) => verified,
            Err(e) => {
                eprintln!("\n  Failed to install {}: {e}", cap.name);
                failed.push(cap.name.clone());
                pb.inc(1);
                continue;
            },
        };

        locked.push(LockedCapsule {
            name: cap.name.clone(),
            version: verified.version,
            source: cap.source.clone(),
            hash: verified
                .wasm_hash
                .map(|h| format!("blake3:{h}"))
                .unwrap_or_default(),
            resolved_ref: verified.resolved_ref,
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

#[derive(Debug)]
struct VerifiedBatchInstall {
    version: String,
    wasm_hash: Option<String>,
    resolved_ref: Option<String>,
}

/// Require the checked installer to report one exact identity and an actual
/// version consistent with the distro's released selector.
fn validate_batch_install(
    expected: &CapsuleId,
    declared_version: &str,
    outcome: super::capsule::install::BatchInstallOutcome,
) -> anyhow::Result<VerifiedBatchInstall> {
    if outcome.installed.len() != 1 {
        let actual = outcome
            .installed
            .iter()
            .map(|installed| installed.id.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "distro declared capsule '{expected}', but the checked installer reported [{}]",
            actual
        );
    }
    let installed = outcome
        .installed
        .into_iter()
        .next()
        .expect("length checked");
    if installed.id != *expected {
        bail!(
            "distro declared capsule '{expected}', but the checked installer reported '{}'",
            installed.id
        );
    }
    if !declared_version.is_empty() && installed.version != declared_version {
        bail!(
            "capsule '{expected}' release selector declared version {declared_version}, but the installed manifest reports {}",
            installed.version
        );
    }
    Ok(VerifiedBatchInstall {
        version: installed.version,
        wasm_hash: installed.wasm_hash,
        resolved_ref: outcome.resolved_ref,
    })
}

/// Write per-capsule .env.json files with resolved variable templates.
pub(crate) fn write_env_files(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    selected: &[DistroCapsule],
    vars: &HashMap<String, String>,
) -> anyhow::Result<()> {
    let env_dir = home.principal_home(principal).env_dir();
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
fn onboard_llm_providers(
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    selected: &[DistroCapsule],
) {
    let env_dir = home.principal_home(principal).env_dir();

    for cap in selected {
        if cap.group.as_deref() != Some("llm") {
            continue;
        }

        let target_dir = match super::capsule::install::resolve_target_dir_for(
            home, principal, &cap.name, false,
        ) {
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

/// `--grant-capsules` post-install grant logic, split out to keep this
/// file under the per-file size cap.
#[path = "init_grant.rs"]
mod grant;

#[cfg(test)]
#[path = "init_tests.rs"]
mod tests;
