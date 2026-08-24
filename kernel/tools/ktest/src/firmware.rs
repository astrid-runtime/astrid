//! Firmware discovery for the M1 UEFI pflash pair.
//!
//! Evidence on this host is executable-relative share, package-prefix (Homebrew
//! is one prefix), well-known OVMF paths, and env overrides. QEMU 11.0.2 does
//! not support `-print-datadir`; that probe is used only when the binary
//! accepts it. This run does not claim datadir portability.
//!
//! Operators may override with `ASTRID_QEMU_FIRMWARE_CODE` /
//! `ASTRID_QEMU_FIRMWARE_VARS`, or a directory via `ASTRID_QEMU_FIRMWARE_DIR`.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, bail};

const ENV_CODE: &str = "ASTRID_QEMU_FIRMWARE_CODE";
const ENV_VARS: &str = "ASTRID_QEMU_FIRMWARE_VARS";
const ENV_DIR: &str = "ASTRID_QEMU_FIRMWARE_DIR";

/// Known (code, vars) filename pairs used by QEMU/OVMF packages.
pub const FIRMWARE_PAIRS: &[(&str, &str)] = &[
    ("edk2-x86_64-code.fd", "edk2-i386-vars.fd"),
    ("OVMF_CODE.fd", "OVMF_VARS.fd"),
    ("OVMF_CODE_4M.fd", "OVMF_VARS_4M.fd"),
    ("QEMU_EFI.fd", "QEMU_VARS.fd"),
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Firmware {
    pub code: PathBuf,
    pub vars: PathBuf,
}

pub fn discover() -> Result<Firmware> {
    discover_with(|key: &str| std::env::var(key), lookup_dirs)
}

/// Injected discovery for tests. `env` returns variable values; `dirs` returns
/// search directories after env overrides.
pub fn discover_with<E, D>(env: E, dirs: D) -> Result<Firmware>
where
    E: Fn(&str) -> Result<String, std::env::VarError>,
    D: Fn() -> Vec<PathBuf>,
{
    match (env(ENV_CODE), env(ENV_VARS)) {
        (Ok(code), Ok(vars)) => {
            return require_pair(PathBuf::from(code), PathBuf::from(vars));
        },
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
            bail!("{ENV_CODE} and {ENV_VARS} must be set together");
        },
        (Err(_), Err(_)) => {},
    }

    let mut search = Vec::new();
    if let Ok(dir) = env(ENV_DIR) {
        search.push(PathBuf::from(dir));
    }
    search.extend(dirs());
    for dir in &search {
        if let Some(fw) = probe_dir(dir) {
            return Ok(fw);
        }
    }
    bail!(
        "could not find a UEFI firmware pair (code+vars). Set {ENV_CODE} and {ENV_VARS}, or {ENV_DIR}, or install QEMU/OVMF firmware"
    )
}

pub fn probe_dir(dir: &Path) -> Option<Firmware> {
    for (code_name, vars_name) in FIRMWARE_PAIRS {
        let code = dir.join(code_name);
        let vars = dir.join(vars_name);
        if code.is_file() && vars.is_file() {
            return Some(Firmware { code, vars });
        }
    }
    None
}

fn require_pair(code: PathBuf, vars: PathBuf) -> Result<Firmware> {
    if !code.is_file() {
        bail!("firmware code is not a file: {}", code.display());
    }
    if !vars.is_file() {
        bail!("firmware vars is not a file: {}", vars.display());
    }
    Ok(Firmware { code, vars })
}

/// Default search directories. Homebrew is included, never exclusive.
pub fn lookup_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = qemu_print_datadir_if_supported() {
        dirs.push(dir);
    }
    if let Some(dir) = qemu_share_next_to_binary() {
        dirs.push(dir);
    }
    if let Some(dir) = brew_qemu_share() {
        dirs.push(dir);
    }
    dirs.extend(
        [
            "/opt/homebrew/share/qemu",
            "/usr/local/share/qemu",
            "/usr/share/qemu",
            "/usr/share/OVMF",
            "/usr/share/edk2/ovmf",
            "/usr/share/edk2-ovmf/x64",
            "/usr/share/edk2-ovmf",
            "/usr/share/qemu/firmware",
        ]
        .into_iter()
        .map(PathBuf::from),
    );
    dirs
}

/// Parse `-print-datadir` output. Unsupported binaries (QEMU 11.0.2 prints
/// "invalid option") must yield `None`; that is not an error.
pub fn datadir_from_qemu_output(success: bool, stdout: &str) -> Option<PathBuf> {
    if !success {
        return None;
    }
    let text = stdout.trim();
    if text.is_empty() {
        return None;
    }
    Some(PathBuf::from(text))
}

fn qemu_print_datadir_if_supported() -> Option<PathBuf> {
    let out = Command::new(crate::machine::QEMU_BIN)
        .arg("-print-datadir")
        .output()
        .ok()?;
    datadir_from_qemu_output(out.status.success(), &String::from_utf8_lossy(&out.stdout))
}

fn qemu_share_next_to_binary() -> Option<PathBuf> {
    let path = which(crate::machine::QEMU_BIN)?;
    let parent = path.parent()?;
    Some(parent.join("..").join("share").join("qemu"))
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn brew_qemu_share() -> Option<PathBuf> {
    let out = Command::new("brew")
        .args(["--prefix", "qemu"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let prefix = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if prefix.is_empty() {
        return None;
    }
    Some(PathBuf::from(prefix).join("share").join("qemu"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;

    static TMP_LOCK: Mutex<()> = Mutex::new(());

    fn write_pair(dir: &Path, code_name: &str, vars_name: &str) {
        fs::write(dir.join(code_name), b"code").unwrap();
        fs::write(dir.join(vars_name), b"vars").unwrap();
    }

    #[test]
    fn probe_dir_finds_edk2_pair() {
        let _g = TMP_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join("astrid-ktest-fw-edk2");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        write_pair(&dir, "edk2-x86_64-code.fd", "edk2-i386-vars.fd");
        let fw = probe_dir(&dir).expect("pair");
        assert!(fw.code.ends_with("edk2-x86_64-code.fd"));
        assert!(fw.vars.ends_with("edk2-i386-vars.fd"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn probe_dir_finds_ovmf_pair() {
        let _g = TMP_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join("astrid-ktest-fw-ovmf");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        write_pair(&dir, "OVMF_CODE.fd", "OVMF_VARS.fd");
        let fw = probe_dir(&dir).expect("pair");
        assert!(fw.code.ends_with("OVMF_CODE.fd"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn env_pair_overrides_search_dirs() {
        let _g = TMP_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join("astrid-ktest-fw-env");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let code = dir.join("custom-code.fd");
        let vars = dir.join("custom-vars.fd");
        fs::write(&code, b"c").unwrap();
        fs::write(&vars, b"v").unwrap();
        let env = |k: &str| match k {
            "ASTRID_QEMU_FIRMWARE_CODE" => Ok(code.display().to_string()),
            "ASTRID_QEMU_FIRMWARE_VARS" => Ok(vars.display().to_string()),
            _ => Err(std::env::VarError::NotPresent),
        };
        let fw = discover_with(env, Vec::new).expect("override");
        assert_eq!(fw.code, code);
        assert_eq!(fw.vars, vars);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_env_is_searched_before_defaults() {
        let _g = TMP_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join("astrid-ktest-fw-direnv");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        write_pair(&dir, "OVMF_CODE.fd", "OVMF_VARS.fd");
        let env = |k: &str| {
            if k == ENV_DIR {
                Ok(dir.display().to_string())
            } else {
                Err(std::env::VarError::NotPresent)
            }
        };
        let fw = discover_with(env, || vec![PathBuf::from("/nonexistent")]).expect("dir");
        assert!(fw.code.ends_with("OVMF_CODE.fd"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn homebrew_is_a_candidate_not_the_only_path() {
        let dirs = [
            "/opt/homebrew/share/qemu",
            "/usr/share/OVMF",
            "/usr/share/qemu",
        ];
        assert!(dirs.contains(&"/opt/homebrew/share/qemu"));
        assert!(dirs.iter().any(|d| *d != "/opt/homebrew/share/qemu"));
    }

    #[test]
    fn missing_pair_is_an_error() {
        let env = |_k: &str| Err(std::env::VarError::NotPresent);
        let err = discover_with(env, Vec::new).unwrap_err();
        assert!(
            err.to_string()
                .contains("could not find a UEFI firmware pair")
        );
    }

    #[test]
    fn unsupported_print_datadir_is_skipped() {
        assert_eq!(
            datadir_from_qemu_output(
                false,
                "qemu-system-x86_64: -print-datadir: invalid option\n"
            ),
            None
        );
        assert_eq!(datadir_from_qemu_output(true, "   \n"), None);
        assert_eq!(
            datadir_from_qemu_output(true, "/usr/share/qemu\n"),
            Some(PathBuf::from("/usr/share/qemu"))
        );
    }
}
