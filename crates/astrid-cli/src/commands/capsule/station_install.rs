//! Astrid-side Station archive handoff.
//!
//! The standalone Station process remains the source authority. This module
//! carries its verified lock alongside the caller-selected archive and lets
//! the kernel bind their persistence together.

use std::path::Path;

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_core::dirs::AstridHome;

use super::{
    ExpectedCapsule, InstallRequest, ManualInstallOptions, RefSpec, SourceInstallContext,
    install_capsule_inner_at, install_from_local,
};
use crate::commands::capsule::station_rollback;
use crate::commands::capsule::{live_load, station, station_handoff};

/// Manual install with an optional exact Station lock handoff.
///
/// The explicit handoff is intentionally narrower than ordinary source
/// dispatch: it accepts one local `.capsule`, canonicalizes its SHA-bound lock,
/// and forwards a typed binding for kernel-side verification and one atomic
/// lock/package transaction.
pub(crate) struct StationInstallRequest<'a> {
    pub(crate) source: &'a str,
    pub(crate) capsule: Option<&'a str>,
    pub(crate) workspace: bool,
    pub(crate) yes: bool,
    pub(crate) approve_untrusted: bool,
    pub(crate) station_lock: Option<&'a Path>,
    pub(crate) station_lock_sha256: Option<&'a str>,
    pub(crate) vars: &'a [String],
}

pub(crate) async fn install_capsule_with_options_and_station_lock(
    request: &StationInstallRequest<'_>,
) -> anyhow::Result<()> {
    let home = AstridHome::resolve()?;
    install_capsule_with_options_and_station_lock_in_home(request, &home).await
}

#[cfg(test)]
static TEST_DAEMON_INSTALL_FAIL: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static TEST_DAEMON_INSTALL_ACTIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
#[cfg(test)]
static TEST_DAEMON_INSTALL_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TEST_DAEMON_INSTALL_SOURCE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Serialize tests around the one production daemon-install seam.
#[cfg(test)]
pub(crate) struct TestLocalInstallBackendGuard(bool);

#[cfg(test)]
impl Drop for TestLocalInstallBackendGuard {
    fn drop(&mut self) {
        TEST_DAEMON_INSTALL_FAIL.store(self.0, std::sync::atomic::Ordering::Release);
        TEST_DAEMON_INSTALL_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
        TEST_DAEMON_INSTALL_CALLS.store(0, std::sync::atomic::Ordering::Release);
        *TEST_DAEMON_INSTALL_SOURCE.lock().unwrap() = None;
    }
}

#[cfg(test)]
pub(crate) fn test_local_install_backend(fail_install: bool) -> TestLocalInstallBackendGuard {
    let previous = TEST_DAEMON_INSTALL_FAIL.swap(fail_install, std::sync::atomic::Ordering::AcqRel);
    TEST_DAEMON_INSTALL_ACTIVE.store(true, std::sync::atomic::Ordering::Release);
    TEST_DAEMON_INSTALL_CALLS.store(0, std::sync::atomic::Ordering::Release);
    *TEST_DAEMON_INSTALL_SOURCE.lock().unwrap() = None;
    TestLocalInstallBackendGuard(previous)
}

#[cfg(test)]
pub(super) fn test_daemon_install_outcome(
    source: &str,
) -> Option<anyhow::Result<Vec<super::InstalledCapsuleOutcome>>> {
    if !TEST_DAEMON_INSTALL_ACTIVE.load(std::sync::atomic::Ordering::Acquire) {
        return None;
    }
    let fail = TEST_DAEMON_INSTALL_FAIL.load(std::sync::atomic::Ordering::Acquire);
    TEST_DAEMON_INSTALL_CALLS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    if let Ok(mut recorded) = TEST_DAEMON_INSTALL_SOURCE.lock() {
        *recorded = Some(source.to_owned());
    }
    let manifest = astrid_capsule_install::read_archive_manifest(Path::new(source)).ok()?;
    let id = CapsuleId::new(manifest.package.name).ok()?;
    let result = if fail {
        Err(anyhow::anyhow!("test daemon install failed after lock set"))
    } else {
        Ok(super::InstalledCapsuleOutcome {
            id,
            version: manifest.package.version,
            wasm_hash: None,
        })
    };
    Some(result.map(|installed| vec![installed]))
}

#[cfg(test)]
pub(crate) fn test_daemon_install_call() -> Option<(String, usize)> {
    let calls = TEST_DAEMON_INSTALL_CALLS.load(std::sync::atomic::Ordering::Acquire);
    (calls > 0).then(|| {
        (
            TEST_DAEMON_INSTALL_SOURCE
                .lock()
                .unwrap()
                .clone()
                .expect("call source"),
            calls,
        )
    })
}

/// Resolve one interactive owner-facing `@namespace/name` coordinate through
/// the standalone Station source authority.
pub(super) async fn install_station_source(
    context: &SourceInstallContext<'_>,
    coordinate: &str,
) -> anyhow::Result<(Vec<super::InstalledCapsuleOutcome>, Option<String>)> {
    let coordinate = format!("@{coordinate}");
    let staged = station::resolve_and_fetch(&coordinate, context.version, None)?;
    let staged_path = staged
        .path
        .to_str()
        .context("Station handoff path is not UTF-8")?;
    let station_id = CapsuleId::new(staged.lock.coordinate.name.clone())?;
    if let Some(expected) = context.expected {
        anyhow::ensure!(
            expected.id == &station_id,
            "Station lock coordinate does not match the requested capsule"
        );
    }
    let name = staged.lock.coordinate.name.as_str();
    let previous = station::load_lock(context.principal, name).await?;
    let previous_for_failure = previous.clone();
    // Daemon-owned installs carry the lock inside the kernel's atomic
    // Station transaction. Workspace installs have no daemon transaction, so
    // they keep the legacy conditional-store/rollback pair.
    let expected_hash = if context.workspace {
        None
    } else {
        previous
            .as_ref()
            .map(station::station_lock_digest)
            .transpose()?
    };
    let ids = if context.workspace {
        station::store_lock(context.principal, name, staged.lock.clone()).await?;
        match install_from_local(super::install_local::LocalInstallCall {
            source: staged_path,
            workspace: true,
            home: context.home,
            original_source: None,
            principal: context.principal,
            expected: Some(ExpectedCapsule {
                id: &station_id,
                version: Some(staged.lock.version.as_str()),
            }),
            prompt: context.prompt,
            station_binding: None,
        })
        .await
        {
            Ok(ids) => ids,
            Err(error) => {
                return Err(station_rollback::combine_install_and_restore_errors(
                    error,
                    station_rollback::restore_station_lock(
                        context.principal,
                        name,
                        previous_for_failure.as_ref(),
                        &staged.lock,
                    )
                    .await,
                ));
            },
        }
    } else {
        let binding = astrid_core::kernel_api::StationInstallBinding {
            capsule: name.to_owned(),
            lock: Box::new(staged.lock.clone()),
            expected_hash,
        };
        install_from_local(super::install_local::LocalInstallCall {
            source: staged_path,
            workspace: false,
            home: context.home,
            original_source: None,
            principal: context.principal,
            expected: Some(ExpectedCapsule {
                id: &station_id,
                version: Some(staged.lock.version.as_str()),
            }),
            prompt: context.prompt,
            station_binding: Some(&binding),
        })
        .await?
    };
    if context.workspace && ids.iter().any(|installed| installed.id.as_str() != name) {
        station_rollback::restore_station_lock(
            context.principal,
            name,
            previous.as_ref(),
            &staged.lock,
        )
        .await?;
        bail!("Station lock coordinate does not match installed capsule");
    }
    Ok((ids, None))
}

/// Re-resolve and install an existing Station lock through the normal local
/// archive installer. The Station lock, never GitHub/latest, chooses bytes.
pub(crate) async fn install_from_station_lock(
    name: &str,
    lock: &astrid_core::kernel_api::StationLock,
    workspace: bool,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    approve_untrusted: bool,
) -> anyhow::Result<Vec<super::InstalledCapsuleOutcome>> {
    let staged = station::resolve_and_fetch("", None, Some(lock))?;
    anyhow::ensure!(
        staged.lock.coordinate.name == name,
        "Station lock coordinate does not match installed capsule"
    );
    let staged_path = staged
        .path
        .to_str()
        .context("Station handoff path is not UTF-8")?;
    let expected_id = CapsuleId::new(name.to_owned())?;
    let prompt = ManualInstallOptions {
        approve_untrusted,
        ..Default::default()
    };
    let previous = if workspace {
        None
    } else {
        station::load_lock(principal, name).await?
    };
    let previous_for_failure = previous.clone();
    let expected_hash = if workspace {
        None
    } else {
        previous
            .as_ref()
            .map(station::station_lock_digest)
            .transpose()?
    };
    let station_binding = (!workspace).then(|| astrid_core::kernel_api::StationInstallBinding {
        capsule: name.to_owned(),
        lock: Box::new(staged.lock.clone()),
        expected_hash,
    });
    let ids = if workspace {
        install_from_local(super::install_local::LocalInstallCall {
            source: staged_path,
            workspace: true,
            home,
            original_source: None,
            principal,
            expected: Some(ExpectedCapsule {
                id: &expected_id,
                version: Some(staged.lock.version.as_str()),
            }),
            prompt: &prompt,
            station_binding: None,
        })
        .await
    } else {
        let binding = station_binding.as_ref().expect("bound non-workspace");
        install_from_local(super::install_local::LocalInstallCall {
            source: staged_path,
            workspace: false,
            original_source: None,
            home,
            principal,
            expected: Some(ExpectedCapsule {
                id: &expected_id,
                version: Some(staged.lock.version.as_str()),
            }),
            prompt: &prompt,
            station_binding: Some(binding),
        })
        .await
    };
    let ids = match ids {
        Ok(ids) => ids,
        Err(error) => {
            if workspace {
                return Err(station_rollback::combine_install_and_restore_errors(
                    error,
                    station_rollback::restore_station_lock(
                        principal,
                        name,
                        previous_for_failure.as_ref(),
                        &staged.lock,
                    )
                    .await,
                ));
            }
            return Err(error);
        },
    };
    if workspace && ids.iter().any(|installed| installed.id != expected_id) {
        // Workspace installs have no kernel transaction; restore the lock the
        // legacy CLI dance wrote before failing loudly.
        station_rollback::restore_station_lock(principal, name, previous.as_ref(), &staged.lock)
            .await?;
        bail!("Station installed an unexpected capsule");
    }
    Ok(ids)
}

pub(crate) async fn install_capsule_with_options_and_station_lock_in_home(
    request: &StationInstallRequest<'_>,
    home: &AstridHome,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.station_lock.is_some() == request.station_lock_sha256.is_some(),
        "--station-lock and --station-lock-sha256 must be supplied together"
    );
    let prompt =
        ManualInstallOptions::from_cli(request.yes, request.approve_untrusted, request.vars)?;
    let principal = crate::principal::current();
    let (installed, _resolved) = if let Some(lock_path) = request.station_lock {
        let lock_digest = request
            .station_lock_sha256
            .ok_or_else(|| anyhow::anyhow!("missing Station lock handoff SHA-256"))?;
        station_handoff::validate_cli_inputs(
            request.source,
            request.capsule,
            request.workspace,
            lock_digest,
        )?;
        (
            install_local_archive_with_station_lock(
                request.source,
                lock_path,
                lock_digest,
                home,
                &principal,
                &prompt,
            )
            .await?,
            None,
        )
    } else {
        install_capsule_inner_at(
            InstallRequest {
                source: request.source,
                name_hint: request.capsule,
                workspace: request.workspace,
                refspec: &RefSpec::default(),
                principal: &principal,
                expected: None,
                prompt: &prompt,
                allow_station: true,
            },
            home,
        )
        .await?
    };
    let installed_ids: Vec<String> = installed
        .iter()
        .map(|capsule| capsule.id.as_str().to_string())
        .collect();
    // Live-load: if a daemon is running, hot-load (or upgrade) each just-installed
    // capsule so it is usable without a restart. Best-effort and non-fatal — the
    // on-disk install above already succeeded standalone.
    live_load::nudge_daemon_reload(&installed_ids).await;
    Ok(())
}

/// Install one Station-verified local archive while retaining its exact
/// source lock through the daemon's atomic Station install transaction.
async fn install_local_archive_with_station_lock(
    source: &str,
    lock_path: &Path,
    station_lock_sha256: &str,
    home: &AstridHome,
    principal: &astrid_core::PrincipalId,
    prompt: &ManualInstallOptions,
) -> anyhow::Result<Vec<super::InstalledCapsuleOutcome>> {
    let archive = Path::new(source);
    let lock = station_handoff::read_lock_file(lock_path, station_lock_sha256)?;
    let mut canonical = lock;
    station::canonicalize_lock(&mut canonical)?;
    let expected_id = CapsuleId::new(canonical.coordinate.name.clone())?;
    // The daemon verifies this expectation under its per-owner/capsule
    // critical section: `None` means this operation must observe no prior
    // lock, and a stale digest fails the install before any mutation.
    let capsule_key = expected_id.as_str().to_owned();
    let previous = station::load_lock(principal, &capsule_key).await?;
    let expected_hash = previous
        .as_ref()
        .map(station::station_lock_digest)
        .transpose()?;
    let binding = astrid_core::kernel_api::StationInstallBinding {
        capsule: capsule_key,
        lock: Box::new(canonical),
        expected_hash,
    };
    let version = binding.lock.version.clone();
    let installed = install_from_local(super::install_local::LocalInstallCall {
        source: archive.to_str().context("archive path is not UTF-8")?,
        workspace: false,
        home,
        original_source: None,
        principal,
        expected: Some(ExpectedCapsule {
            id: &expected_id,
            version: Some(version.as_str()),
        }),
        prompt,
        station_binding: Some(&binding),
    })
    .await?;
    Ok(installed)
}
