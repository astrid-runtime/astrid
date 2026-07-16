//! Lifecycle elicitation and post-install validation for capsule installs.

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_capsule_install::{InstallOptions, InstallOutput};
use astrid_core::dirs::AstridHome;
use astrid_events::EventBus;

use super::install::{BATCH_MODE, ManualInstallOptions};
use super::install_batch::InstalledCapsuleOutcome;
use super::install_headless::{headless_elicit_handler, write_headless_env_fields};
use super::install_prompts::{cli_elicit_handler, prompt_env_fields};

/// Run a lib-install closure with a fresh event bus and the selected elicit
/// responder. Tears the handler down before returning either `Ok` or `Err`.
pub(super) fn run_with_elicit<F>(
    opts: InstallOptions,
    prompt: &ManualInstallOptions,
    f: F,
) -> anyhow::Result<InstallOutput>
where
    F: FnOnce(InstallOptions, EventBus) -> anyhow::Result<InstallOutput>,
{
    let event_bus = EventBus::with_capacity(128);
    let receiver = event_bus.subscribe_topic("astrid.v1.elicit");
    let bus_for_handler = event_bus.clone();
    let headless_errors = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let elicit_task = tokio::runtime::Handle::try_current().ok().map(|handle| {
        if prompt.yes {
            let vars = prompt.vars.clone();
            let errors = std::sync::Arc::clone(&headless_errors);
            handle.spawn(async move {
                headless_elicit_handler(receiver, bus_for_handler, vars, errors).await;
            })
        } else {
            handle.spawn(async move {
                cli_elicit_handler(receiver, bus_for_handler).await;
            })
        }
    });
    let result = f(opts, event_bus.clone());
    if let Some(task) = elicit_task {
        task.abort();
    }
    drop(event_bus);
    let errors = headless_errors
        .lock()
        .map_err(|_| anyhow::anyhow!("headless configuration error state was poisoned"))?;
    if !errors.is_empty() {
        bail!(
            "non-interactive capsule configuration failed: {}",
            errors.join("; ")
        );
    }
    result
}

/// Validate install output, surface diagnostics, and persist manual install
/// configuration before returning the installed capsule identity.
pub(super) fn finish_install(
    output: &InstallOutput,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<InstalledCapsuleOutcome> {
    let batch = BATCH_MODE.load(std::sync::atomic::Ordering::Relaxed);
    let manifest_path = output.target_dir.join("Capsule.toml");
    let manifest = astrid_capsule::discovery::load_manifest(&manifest_path)
        .context("re-reading manifest for post-install diagnostics")?;

    let capsule_id = CapsuleId::new(manifest.package.name.clone())?;
    let meta = super::meta::read_meta(&output.target_dir)
        .context("installed capsule has no readable meta.json")?;
    if manifest.package.version != meta.version || output.installed_version != meta.version {
        bail!(
            "installed capsule '{}' version disagreement: manifest={}, meta={}, installer={}",
            capsule_id,
            manifest.package.version,
            meta.version,
            output.installed_version
        );
    }
    if output.wasm_hash != meta.wasm_hash {
        bail!(
            "installed capsule '{}' hash disagreement: installer={:?}, meta={:?}",
            capsule_id,
            output.wasm_hash,
            meta.wasm_hash
        );
    }

    let cli_commands: Vec<&astrid_capsule::manifest::CommandDef> = manifest
        .commands
        .iter()
        .filter(|command| command.kind == astrid_core::kernel_api::CommandKind::Cli)
        .collect();
    if !cli_commands.is_empty() {
        eprintln!("\nThis capsule adds CLI commands:");
        for command in cli_commands {
            let description = command.description.as_deref().unwrap_or("(no description)");
            eprintln!(
                "  {} — {description} (provider: {capsule_id})",
                command.name
            );
        }
    }

    if !batch {
        if prompt.yes {
            write_headless_env_fields(
                &manifest.env,
                &output.env_path,
                capsule_id.as_str(),
                home,
                principal,
                &prompt.vars,
            )?;
        } else if output.env_needs_prompt {
            prompt_env_fields(
                &manifest.env,
                &output.env_path,
                capsule_id.as_str(),
                &home.config_path(),
                home,
                principal,
            )?;
        }
    }

    if !batch && !output.missing_imports.is_empty() {
        let importer = capsule_id.as_str();
        eprintln!();
        for missing in &output.missing_imports {
            eprintln!(
                "  Note: {importer} needs {}/{} {}.",
                missing.namespace, missing.interface, missing.requirement
            );
        }
        eprintln!(
            "  Install the missing capsule(s) or run `astrid init` to set up a complete environment."
        );
    }

    for conflict in &output.export_conflicts {
        tracing::info!(
            interface = %conflict.interface,
            existing = %conflict.existing_capsule,
            "Shared export — both capsules will be active"
        );
    }

    if !batch {
        let skew = super::show::contracts_skew_at(&output.target_dir, home);
        super::show::print_install_skew_notice(capsule_id.as_str(), &skew);
    }

    Ok(InstalledCapsuleOutcome {
        id: capsule_id,
        version: meta.version,
        wasm_hash: meta.wasm_hash,
    })
}
