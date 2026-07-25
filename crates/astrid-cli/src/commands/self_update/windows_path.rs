//! Persistent Windows PATH setup for self-managed release installations.
//!
//! This module deliberately targets the directory containing the running
//! release binaries. Package-manager installations remain package-manager
//! owned, and incomplete/direct single-binary layouts are never advertised as
//! complete Astrid installations.

use std::ffi::{OsStr, OsString};
use std::io::IsTerminal;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::ptr;

use anyhow::{Context, bail, ensure};
use windows_sys::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_MORE_DATA, ERROR_SUCCESS, HKEY};
use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_EXPAND_SZ,
    REG_OPTION_NON_VOLATILE, REG_SAM_FLAGS, REG_SZ, REG_VALUE_TYPE, RegCloseKey, RegCreateKeyExW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    HWND_BROADCAST, SMTO_ABORTIFHUNG, SMTO_BLOCK, SendMessageTimeoutW, WM_SETTINGCHANGE,
};
use windows_sys::core::w;

use crate::theme::Theme;

use super::InstallMethod;

const USER_ENVIRONMENT_KEY: windows_sys::core::PCWSTR = w!("Environment");
const MACHINE_ENVIRONMENT_KEY: windows_sys::core::PCWSTR =
    w!("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment");
const PATH_VALUE_NAME: windows_sys::core::PCWSTR = w!("Path");
const PATH_LOCK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const PATH_LOCK_POLL: std::time::Duration = std::time::Duration::from_millis(25);
const BROADCAST_GLOBAL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const BROADCAST_WINDOW_TIMEOUT_MS: u32 = 250;
const MAX_REGISTRY_PATH_BYTES: u32 = 1024 * 1024;
const BACKSLASH: u16 = 92;
const FORWARD_SLASH: u16 = 47;
const PATH_SEPARATOR: u16 = 59;
const WINDOWS_MANAGED_BINARIES: [&str; 4] = [
    "astrid.exe",
    "astrid-daemon.exe",
    "astrid-build.exe",
    "astrid-emit.exe",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathValueKind {
    Plain,
    Expandable,
}

impl PathValueKind {
    fn from_registry(kind: REG_VALUE_TYPE) -> anyhow::Result<Self> {
        match kind {
            REG_SZ => Ok(Self::Plain),
            REG_EXPAND_SZ => Ok(Self::Expandable),
            other => bail!(
                "persistent PATH has unsupported registry type {other}; expected REG_SZ or REG_EXPAND_SZ"
            ),
        }
    }

    const fn registry_type(self) -> REG_VALUE_TYPE {
        match self {
            Self::Plain => REG_SZ,
            Self::Expandable => REG_EXPAND_SZ,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PathValue {
    contents: OsString,
    kind: PathValueKind,
}

#[derive(Debug)]
struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a successfully opened registry-key handle owned
        // by this guard and is closed exactly once here.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}

/// Add the complete self-managed release directory to the persistent User PATH.
pub(super) fn ensure_path_setup(
    exe: &Path,
    method: InstallMethod,
    yes: bool,
) -> anyhow::Result<()> {
    if method != InstallMethod::SelfManaged {
        return Ok(());
    }

    let Some(install_dir) = complete_install_dir(exe) else {
        println!(
            "{}",
            Theme::warning(
                "Astrid is not changing your User PATH because the running executable is not beside all four release executables.",
            )
        );
        return Ok(());
    };

    let proposed_update = {
        let user_key = open_user_environment()?;
        let user_path = read_path_value(&user_key)?;
        let machine_key = open_key(HKEY_LOCAL_MACHINE, MACHINE_ENVIRONMENT_KEY, KEY_QUERY_VALUE)
            .context("cannot open the persistent Machine environment")?;
        let machine_path = read_path_value(&machine_key)?;
        plan_path_update(
            user_path.as_ref(),
            machine_path.as_ref(),
            &install_dir,
            expand_environment,
        )?
    };
    if proposed_update.is_none() {
        return Ok(());
    }

    if !yes && std::io::stdin().is_terminal() {
        eprint!(
            "\n{} is not in your persistent User or Machine PATH. Add it to your User PATH? [Y/n] ",
            install_dir.display()
        );
        std::io::Write::flush(&mut std::io::stderr())?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let input = input.trim();
        if !input.is_empty() && !input.eq_ignore_ascii_case("y") {
            println!(
                "{}",
                Theme::dimmed(&format!(
                    "Skipped. Add {} to your User PATH manually.",
                    install_dir.display()
                ))
            );
            return Ok(());
        }
    }

    // Registry PATH has no compare-and-swap operation. Serialize every Astrid
    // writer across processes after interactive input is complete, then re-read
    // immediately before the write and verify immediately afterward. An
    // unrelated installer that ignores this lock can still race the final
    // RegSetValueExW call; post-write verification detects an immediate
    // overwrite, but Windows exposes no atomic merge with arbitrary writers.
    let _path_lock = acquire_path_update_lock()?;
    let user_key = open_user_environment()?;
    let machine_key = open_key(HKEY_LOCAL_MACHINE, MACHINE_ENVIRONMENT_KEY, KEY_QUERY_VALUE)
        .context("cannot open the persistent Machine environment")?;
    // The prompt can leave a registry value stale. Re-read both scopes while
    // holding the Astrid writer lock immediately before mutation.
    let latest_user_path = read_path_value(&user_key)?;
    let latest_machine_path = read_path_value(&machine_key)?;
    let Some(update) = plan_path_update(
        latest_user_path.as_ref(),
        latest_machine_path.as_ref(),
        &install_dir,
        expand_environment,
    )?
    else {
        return Ok(());
    };
    write_path_value(&user_key, &update)?;
    let persisted = match read_path_value(&user_key)? {
        Some(value) => path_value_contains(&value.contents, &install_dir, &mut expand_environment)?,
        None => false,
    };
    ensure!(
        persisted,
        "persistent User PATH changed concurrently before Astrid could verify its update"
    );
    if let Err(error) = notify_environment_change() {
        println!(
            "{}",
            Theme::warning(&format!(
                "Updated the persistent User PATH, but Windows could not notify every running application: {error}. New terminals will still receive it."
            ))
        );
    }

    println!(
        "{}",
        Theme::success(&format!(
            "Added {} to your persistent User PATH",
            install_dir.display()
        ))
    );
    println!("  Restart your terminal to use the updated PATH.");
    Ok(())
}

fn complete_install_dir(exe: &Path) -> Option<PathBuf> {
    let install_dir = exe.parent()?.to_path_buf();
    WINDOWS_MANAGED_BINARIES
        .iter()
        .all(|name| install_dir.join(name).is_file())
        .then_some(install_dir)
}

fn plan_path_update<F>(
    user: Option<&PathValue>,
    machine: Option<&PathValue>,
    install_dir: &Path,
    mut expand: F,
) -> anyhow::Result<Option<PathValue>>
where
    F: FnMut(&OsStr) -> anyhow::Result<OsString>,
{
    if let Some(value) = user
        && path_value_contains(&value.contents, install_dir, &mut expand)?
    {
        return Ok(None);
    }
    if let Some(value) = machine
        && path_value_contains(&value.contents, install_dir, &mut expand)?
    {
        return Ok(None);
    }

    let kind = user.map_or(PathValueKind::Plain, |value| value.kind);
    let contents = append_path(user.map(|value| value.contents.as_os_str()), install_dir);
    Ok(Some(PathValue { contents, kind }))
}

fn path_value_contains<F>(
    path_value: &OsStr,
    install_dir: &Path,
    expand: &mut F,
) -> anyhow::Result<bool>
where
    F: FnMut(&OsStr) -> anyhow::Result<OsString>,
{
    let expanded_target = expand(install_dir.as_os_str())?;
    for entry in std::env::split_paths(path_value) {
        if entry.as_os_str().is_empty() {
            continue;
        }
        let expanded_entry = expand(entry.as_os_str())?;
        if paths_equal_case_insensitive(&expanded_entry, &expanded_target)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn append_path(existing: Option<&OsStr>, install_dir: &Path) -> OsString {
    let mut updated = existing.unwrap_or_default().to_os_string();
    if !updated.is_empty() && updated.encode_wide().next_back() != Some(PATH_SEPARATOR) {
        updated.push(";");
    }
    updated.push(install_dir);
    updated
}

pub(super) fn paths_equal_case_insensitive(left: &OsStr, right: &OsStr) -> anyhow::Result<bool> {
    let left = normalize_path(left);
    let right = normalize_path(right);
    let left: Vec<u16> = left.encode_wide().collect();
    let right: Vec<u16> = right.encode_wide().collect();
    let left_len = i32::try_from(left.len()).context("PATH entry is too long to compare")?;
    let right_len = i32::try_from(right.len()).context("PATH entry is too long to compare")?;

    // SAFETY: Both pointers remain valid for their supplied element counts,
    // and `CompareStringOrdinal` does not retain them.
    let ordering =
        unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) };
    ensure!(
        ordering != 0,
        "Windows failed to compare persistent PATH entries"
    );
    Ok(ordering == CSTR_EQUAL)
}

/// Lexically normalize separators, dot segments, and trailing separators
/// without requiring a PATH entry to exist on disk.
fn normalize_path(path: &OsStr) -> OsString {
    let mut normalized = PathBuf::new();
    for component in Path::new(path).components() {
        match component {
            Component::CurDir => {},
            Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            },
            _ => normalized.push(component.as_os_str()),
        }
    }

    let mut wide: Vec<u16> = normalized.as_os_str().encode_wide().collect();
    for unit in &mut wide {
        if *unit == FORWARD_SLASH {
            *unit = BACKSLASH;
        }
    }
    strip_verbatim_prefix(&mut wide);
    while wide.len() > 3 && wide.last() == Some(&BACKSLASH) {
        wide.pop();
    }
    OsString::from_wide(&wide)
}

fn strip_verbatim_prefix(path: &mut Vec<u16>) {
    const VERBATIM: &[u16] = &[92, 92, 63, 92];
    const VERBATIM_UNC: &[u16] = &[92, 92, 63, 92, 85, 78, 67, 92];
    if path.starts_with(VERBATIM_UNC) {
        path.splice(..VERBATIM_UNC.len(), [BACKSLASH, BACKSLASH]);
    } else if path.starts_with(VERBATIM) {
        path.drain(..VERBATIM.len());
    }
}

fn expand_environment(input: &OsStr) -> anyhow::Result<OsString> {
    let mut source: Vec<u16> = input.encode_wide().collect();
    ensure!(
        !source.contains(&0),
        "persistent PATH entry contains an embedded NUL"
    );
    source.push(0);

    // Environment variables can change between the sizing and copy calls, so
    // retry when Windows reports a larger required capacity.
    let mut required = unsafe { ExpandEnvironmentStringsW(source.as_ptr(), ptr::null_mut(), 0) };
    ensure!(
        required != 0,
        "cannot size expanded persistent PATH entry: {}",
        std::io::Error::last_os_error()
    );
    loop {
        let capacity = usize::try_from(required).context("expanded PATH entry is too long")?;
        let mut expanded = vec![0u16; capacity];
        let written =
            unsafe { ExpandEnvironmentStringsW(source.as_ptr(), expanded.as_mut_ptr(), required) };
        ensure!(
            written != 0,
            "cannot expand persistent PATH entry: {}",
            std::io::Error::last_os_error()
        );
        if written > required {
            required = written;
            continue;
        }
        let length = expanded
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(usize::try_from(written).context("expanded PATH entry is too long")?);
        expanded.truncate(length);
        return Ok(OsString::from_wide(&expanded));
    }
}

fn open_user_environment() -> anyhow::Result<RegistryKey> {
    let mut key = ptr::null_mut();
    let mut disposition = 0;
    // SAFETY: All pointer arguments either point to valid writable storage or
    // are explicitly optional null pointers. The returned handle is owned by
    // `RegistryKey`.
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            USER_ENVIRONMENT_KEY,
            0,
            ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_QUERY_VALUE | KEY_SET_VALUE,
            ptr::null(),
            &mut key,
            &mut disposition,
        )
    };
    win32_status(status).context("cannot open the persistent User environment")?;
    Ok(RegistryKey(key))
}

fn acquire_path_update_lock() -> anyhow::Result<std::fs::File> {
    let root = astrid_core::platform_fs::default_astrid_home_root()?;
    let lock_dir = root.join("locks");
    astrid_core::platform_fs::ensure_private_directory(&lock_dir)?;
    let lock_path = lock_dir.join("user-path.lock");
    let deadline = std::time::Instant::now()
        .checked_add(PATH_LOCK_TIMEOUT)
        .context("persistent PATH lock deadline overflow")?;
    loop {
        match astrid_core::platform_fs::try_acquire_private_file_lock(
            &lock_path,
            "another Astrid PATH update",
        )? {
            Some(lock) => return Ok(lock),
            None if std::time::Instant::now() < deadline => {
                std::thread::sleep(PATH_LOCK_POLL);
            },
            None => bail!("timed out waiting for another Astrid PATH update"),
        }
    }
}

fn open_key(
    root: HKEY,
    subkey: windows_sys::core::PCWSTR,
    access: REG_SAM_FLAGS,
) -> anyhow::Result<RegistryKey> {
    let mut key = ptr::null_mut();
    // SAFETY: `subkey` is a static NUL-terminated string, `key` is writable,
    // and the returned handle is owned by `RegistryKey`.
    let status = unsafe { RegOpenKeyExW(root, subkey, 0, access, &mut key) };
    win32_status(status)?;
    Ok(RegistryKey(key))
}

fn read_path_value(key: &RegistryKey) -> anyhow::Result<Option<PathValue>> {
    let mut kind = 0;
    let mut bytes = 0;
    // SAFETY: This sizing call supplies no data buffer, and the out-parameters
    // point to valid writable values.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            PATH_VALUE_NAME,
            ptr::null(),
            &mut kind,
            ptr::null_mut(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
        return Err(std::io::Error::from_raw_os_error(status.cast_signed()))
            .context("cannot inspect persistent PATH");
    }
    ensure!(
        bytes <= MAX_REGISTRY_PATH_BYTES,
        "persistent PATH exceeds the one-megabyte safety limit"
    );
    ensure!(
        bytes % 2 == 0,
        "persistent PATH registry data is not valid UTF-16"
    );

    let initial_bytes = usize::try_from(bytes).context("persistent PATH is too large")?;
    let mut data = vec![0u16; initial_bytes.div_ceil(2).max(1)];
    loop {
        let mut available =
            u32::try_from(data.len() * 2).context("persistent PATH is too large")?;
        // SAFETY: `data` is writable for `available` bytes and all other
        // pointers reference valid storage.
        let status = unsafe {
            RegQueryValueExW(
                key.0,
                PATH_VALUE_NAME,
                ptr::null(),
                &mut kind,
                data.as_mut_ptr().cast(),
                &mut available,
            )
        };
        if status == ERROR_MORE_DATA {
            ensure!(
                available <= MAX_REGISTRY_PATH_BYTES,
                "persistent PATH exceeds the one-megabyte safety limit"
            );
            let available = usize::try_from(available).context("persistent PATH is too large")?;
            data.resize(available.div_ceil(2).max(1), 0);
            continue;
        }
        win32_status(status).context("cannot read persistent PATH")?;
        ensure!(
            available % 2 == 0,
            "persistent PATH registry data is not valid UTF-16"
        );
        data.truncate(usize::try_from(available).context("persistent PATH is too large")? / 2);
        break;
    }

    if let Some(nul) = data.iter().position(|unit| *unit == 0) {
        data.truncate(nul);
    }
    Ok(Some(PathValue {
        contents: OsString::from_wide(&data),
        kind: PathValueKind::from_registry(kind)?,
    }))
}

fn write_path_value(key: &RegistryKey, path: &PathValue) -> anyhow::Result<()> {
    let mut data: Vec<u16> = path.contents.encode_wide().collect();
    ensure!(
        !data.contains(&0),
        "refusing to write a persistent PATH containing an embedded NUL"
    );
    data.push(0);
    let bytes = u32::try_from(data.len() * 2).context("persistent PATH is too large")?;
    ensure!(
        bytes <= MAX_REGISTRY_PATH_BYTES,
        "persistent PATH exceeds the one-megabyte safety limit"
    );

    // SAFETY: `data` is readable for `bytes`, and the registry key remains
    // valid for the duration of the call.
    let status = unsafe {
        RegSetValueExW(
            key.0,
            PATH_VALUE_NAME,
            0,
            path.kind.registry_type(),
            data.as_ptr().cast(),
            bytes,
        )
    };
    win32_status(status).context("cannot update the persistent User PATH")
}

fn notify_environment_change() -> anyhow::Result<()> {
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let _worker = std::thread::Builder::new()
        .name("astrid-path-notify".to_owned())
        .spawn(move || {
            let mut result = 0usize;
            // SAFETY: Microsoft requires synchronous SendMessageTimeout for
            // WM_SETTINGCHANGE because its below-WM_USER lParam is a pointer.
            // The pointed-to string is static and NUL-terminated, so it remains
            // live even if the caller enforces its global deadline and detaches
            // this bounded-per-window worker.
            let sent = unsafe {
                SendMessageTimeoutW(
                    HWND_BROADCAST,
                    WM_SETTINGCHANGE,
                    0,
                    USER_ENVIRONMENT_KEY as isize,
                    SMTO_ABORTIFHUNG | SMTO_BLOCK,
                    BROADCAST_WINDOW_TIMEOUT_MS,
                    &mut result,
                )
            };
            let outcome = if sent == 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            };
            let _ = sender.send(outcome);
        })
        .context("cannot start the Windows environment-notification worker")?;

    match receiver.recv_timeout(BROADCAST_GLOBAL_TIMEOUT) {
        Ok(result) => result.context("WM_SETTINGCHANGE notification failed"),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            bail!("WM_SETTINGCHANGE exceeded the five-second global notification budget")
        },
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            bail!("Windows environment-notification worker exited unexpectedly")
        },
    }
}

fn win32_status(status: u32) -> anyhow::Result<()> {
    if status == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(status.cast_signed()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expand_test_variables(value: &OsStr) -> anyhow::Result<OsString> {
        let text = value.to_string_lossy();
        ensure!(
            !text.contains("%INVALID%"),
            "test expansion received an invalid variable"
        );
        Ok(OsString::from(text.replace(
            "%LOCALAPPDATA%",
            r"C:\Users\alice\AppData\Local",
        )))
    }

    #[test]
    fn persistent_path_match_expands_and_normalizes_case() {
        let value = OsStr::new(r"C:\Windows\System32;%LOCALAPPDATA%\Astrid\Runtime\bin\;C:\Other");
        assert!(
            path_value_contains(
                value,
                Path::new(r"c:/users/ALICE/appdata/local/astrid/runtime/bin"),
                &mut expand_test_variables,
            )
            .unwrap()
        );
    }

    #[test]
    fn machine_path_prevents_a_redundant_user_path_write() {
        let machine = PathValue {
            contents: OsString::from(r"C:\Windows;C:\Astrid\bin"),
            kind: PathValueKind::Expandable,
        };
        assert_eq!(
            plan_path_update(
                None,
                Some(&machine),
                Path::new(r"c:\astrid\bin"),
                expand_test_variables,
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn append_is_minimal_and_preserves_user_registry_type() {
        let user = PathValue {
            contents: OsString::from(r"%LOCALAPPDATA%\Tools"),
            kind: PathValueKind::Expandable,
        };
        let update = plan_path_update(
            Some(&user),
            None,
            Path::new(r"C:\Astrid\bin"),
            expand_test_variables,
        )
        .unwrap()
        .unwrap();
        assert_eq!(update.kind, PathValueKind::Expandable);
        assert_eq!(
            update.contents,
            OsString::from(r"%LOCALAPPDATA%\Tools;C:\Astrid\bin")
        );

        let plain = PathValue {
            contents: OsString::from(r"C:\Tools;"),
            kind: PathValueKind::Plain,
        };
        let update = plan_path_update(
            Some(&plain),
            None,
            Path::new(r"C:\Astrid\bin"),
            expand_test_variables,
        )
        .unwrap()
        .unwrap();
        assert_eq!(update.kind, PathValueKind::Plain);
        assert_eq!(update.contents, OsString::from(r"C:\Tools;C:\Astrid\bin"));
    }

    #[test]
    fn empty_user_path_uses_plain_string_without_a_leading_separator() {
        let update = plan_path_update(
            None,
            None,
            Path::new(r"C:\Astrid\bin"),
            expand_test_variables,
        )
        .unwrap()
        .unwrap();
        assert_eq!(update.kind, PathValueKind::Plain);
        assert_eq!(update.contents, OsString::from(r"C:\Astrid\bin"));
    }

    #[test]
    fn complete_install_requires_all_release_companions() {
        let temp = tempfile::tempdir().unwrap();
        let exe = temp.path().join("astrid.exe");
        for name in WINDOWS_MANAGED_BINARIES {
            std::fs::write(temp.path().join(name), b"test").unwrap();
        }
        assert_eq!(complete_install_dir(&exe), Some(temp.path().to_path_buf()));

        std::fs::remove_file(temp.path().join("astrid-emit.exe")).unwrap();
        assert_eq!(complete_install_dir(&exe), None);
    }

    #[test]
    fn package_manager_installs_return_before_registry_access() {
        let nonexistent = Path::new(r"Z:\definitely-missing\astrid.exe");
        ensure_path_setup(nonexistent, InstallMethod::Cargo, false).unwrap();
        ensure_path_setup(nonexistent, InstallMethod::Homebrew, false).unwrap();
    }
}
