//! Astrid-side Station archive handoff.
//!
//! The standalone Station process remains the source authority. This module
//! only carries its exact verified lock alongside a private archive into the
//! existing daemon-owned local installer.

use std::path::Path;

use anyhow::{Context, bail};
use astrid_capsule::capsule::CapsuleId;
use astrid_core::dirs::AstridHome;

use super::{
    ExpectedCapsule, InstallRequest, ManualInstallOptions, RefSpec, install_capsule_inner_at,
    install_from_local,
};
use crate::commands::capsule::{live_load, station, station_handoff};

/// Manual install with an optional exact Station lock handoff.
///
/// The explicit handoff is intentionally narrower than ordinary source
/// dispatch: it accepts one local `.capsule`, validates the untrusted lock and
/// exact archive bytes, then stores that lock before the daemon install.
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
/// source lock in the authenticated owner's control namespace.
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
    let staged = station_handoff::stage_verified_archive(archive, &lock)?;
    let staged_path = staged
        .path()
        .to_str()
        .context("private Station handoff path is not UTF-8")?;
    let expected_id = CapsuleId::new(lock.coordinate.name.clone())?;
    let capsule = expected_id.as_str();
    let previous = station::load_lock(principal, capsule).await?;
    let previous_for_failure = previous.clone();
    station::store_lock(principal, capsule, lock.clone()).await?;

    let installed = install_from_local(
        staged_path,
        false,
        home,
        None,
        principal,
        Some(ExpectedCapsule {
            id: &expected_id,
            version: Some(lock.version.as_str()),
        }),
        prompt,
    )
    .await;
    let installed = match installed {
        Ok(installed) => installed,
        Err(error) => {
            return Err(
                crate::commands::capsule::station_rollback::combine_install_and_restore_errors(
                    error,
                    crate::commands::capsule::station_rollback::restore_station_lock(
                        principal,
                        capsule,
                        previous_for_failure.as_ref(),
                        &lock,
                    )
                    .await,
                ),
            );
        },
    };
    if installed.iter().any(|capsule| capsule.id != expected_id) {
        crate::commands::capsule::station_rollback::restore_station_lock(
            principal,
            capsule,
            previous.as_ref(),
            &lock,
        )
        .await?;
        bail!("Station lock coordinate does not match installed capsule");
    }
    Ok(installed)
}
