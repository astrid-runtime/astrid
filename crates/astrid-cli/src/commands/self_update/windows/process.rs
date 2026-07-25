//! Exact Windows process identity and bounded updater-helper lifecycle.

use std::path::Path;

use anyhow::Context as _;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, FILETIME, HANDLE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

use super::{
    HELPER_ARM_POLL, HELPER_ARM_TIMEOUT, HELPER_REAP_TIMEOUT, PARENT_EXIT_TIMEOUT_MS,
    ProcessCreationToken, SYNCHRONIZE_ACCESS,
};

pub(super) struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns one successful OpenProcess handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordedProcessState {
    Alive,
    Gone,
}

pub(super) fn open_process_identity(process_id: u32) -> std::io::Result<OwnedHandle> {
    if process_id == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid zero process ID",
        ));
    }
    // SAFETY: scalar process ID and access mask; a successful handle is owned
    // by the wrapper for exact-handle identity queries and waits.
    let handle = unsafe {
        OpenProcess(
            SYNCHRONIZE_ACCESS | PROCESS_QUERY_LIMITED_INFORMATION,
            0,
            process_id,
        )
    };
    if handle.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

pub(super) fn process_creation_token(
    handle: &OwnedHandle,
) -> std::io::Result<ProcessCreationToken> {
    let mut creation = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    // SAFETY: all pointers reference initialized FILETIME storage and the
    // retained handle has PROCESS_QUERY_LIMITED_INFORMATION access.
    if unsafe {
        GetProcessTimes(
            handle.0,
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let token = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if token == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Windows returned a zero process creation time",
        ));
    }
    Ok(ProcessCreationToken(token))
}

pub(super) fn current_process_creation_token() -> anyhow::Result<ProcessCreationToken> {
    let process = open_process_identity(std::process::id())
        .context("failed to open the current Windows process")?;
    process_creation_token(&process).context("failed to query the current Windows process identity")
}

pub(super) fn open_parent(
    parent_pid: u32,
    expected_creation_time: ProcessCreationToken,
) -> anyhow::Result<OwnedHandle> {
    anyhow::ensure!(
        expected_creation_time.0 != 0,
        "invalid zero parent process creation token"
    );
    let parent =
        open_process_identity(parent_pid).context("failed to open exact parent update process")?;
    let actual_creation_time = process_creation_token(&parent)
        .context("failed to query exact parent update process identity")?;
    anyhow::ensure!(
        actual_creation_time == expected_creation_time,
        "parent update process identity changed before helper handoff"
    );
    Ok(parent)
}

pub(super) fn recorded_process_state(
    process_id: u32,
    expected_creation_time: ProcessCreationToken,
) -> anyhow::Result<RecordedProcessState> {
    let process = match open_process_identity(process_id) {
        Ok(process) => process,
        Err(error) if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER.cast_signed()) => {
            return Ok(RecordedProcessState::Gone);
        },
        Err(error) => {
            return Err(error).context(
                "could not determine whether the provisional Windows update parent is alive",
            );
        },
    };
    let actual_creation_time = process_creation_token(&process)
        .context("failed to query provisional Windows update parent identity")?;
    if actual_creation_time != expected_creation_time {
        return Ok(RecordedProcessState::Gone);
    }
    // SAFETY: the exact process handle remains owned for this zero-duration
    // state probe, so PID reuse cannot alter the result.
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_TIMEOUT => Ok(RecordedProcessState::Alive),
        WAIT_OBJECT_0 => Ok(RecordedProcessState::Gone),
        WAIT_FAILED => Err(std::io::Error::last_os_error())
            .context("failed probing provisional Windows update parent state"),
        other => anyhow::bail!("unexpected provisional parent wait result: {other:#010x}"),
    }
}

pub(super) fn wait_for_parent(parent: &OwnedHandle) -> anyhow::Result<()> {
    // SAFETY: the exact parent handle remains owned for this bounded wait.
    classify_parent_wait_result(unsafe { WaitForSingleObject(parent.0, PARENT_EXIT_TIMEOUT_MS) })
}

pub(super) fn classify_parent_wait_result(result: u32) -> anyhow::Result<()> {
    match result {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => anyhow::bail!("timed out waiting for the parent updater to exit"),
        WAIT_FAILED => Err(std::io::Error::last_os_error())
            .context("failed waiting for the parent updater to exit"),
        other => anyhow::bail!("unexpected parent updater wait result: {other:#010x}"),
    }
}

pub(super) fn wait_for_helper_armed(
    child: &mut std::process::Child,
    armed_path: &Path,
) -> anyhow::Result<()> {
    wait_for_helper_marker(child, armed_path, "Windows update helper")
}

pub(super) fn wait_for_helper_marker(
    child: &mut std::process::Child,
    marker_path: &Path,
    helper_name: &str,
) -> anyhow::Result<()> {
    let deadline = std::time::Instant::now()
        .checked_add(HELPER_ARM_TIMEOUT)
        .context("Windows update helper arming deadline overflow")?;
    loop {
        if astrid_core::platform_fs::read_private_file_to_string(marker_path)
            .is_ok_and(|contents| contents == "v1\n")
        {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            anyhow::bail!("{helper_name} exited before arming parent wait: {status}");
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for {helper_name} to arm parent wait");
        }
        std::thread::sleep(HELPER_ARM_POLL);
    }
}

pub(super) fn terminate_child_bounded(mut child: std::process::Child) -> anyhow::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    if let Err(kill_error) = child.kill() {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        return Err(kill_error).context("failed to terminate Windows update helper");
    }

    let deadline = std::time::Instant::now()
        .checked_add(HELPER_REAP_TIMEOUT)
        .context("Windows update helper reap deadline overflow")?;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        anyhow::ensure!(
            std::time::Instant::now() < deadline,
            "timed out reaping the terminated Windows update helper"
        );
        std::thread::sleep(HELPER_ARM_POLL);
    }
}
