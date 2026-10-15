//! Disposable native-process sandbox probe shared by CLI setup and daemon.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

/// Exercise the Linux native-process sandbox's mount, namespace and grant-FD
/// shape from the current executable's actual security context.
///
/// The caller must also verify the intended daemon executable separately:
/// an `AppArmor` profile attached to the CLI says nothing about the daemon.
#[must_use]
pub fn probe_native_process_sandbox() -> bool {
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
    #[cfg(target_os = "linux")]
    {
        if super::bwrap::unsafe_legacy_astrid_profile() {
            return false;
        }
        let Ok(root) = tempfile::Builder::new()
            .prefix("astrid-sandbox-probe-")
            .tempdir_in("/var/tmp")
        else {
            return false;
        };
        let readonly = root.path().join("readonly");
        let writable = root.path().join("writable");
        if std::fs::create_dir(&readonly).is_err() || std::fs::create_dir(&writable).is_err() {
            return false;
        }
        let (Ok(read_fd), Ok(write_fd)) = (File::open(&readonly), File::open(&writable)) else {
            return false;
        };
        production_shaped_bwrap_probe(root.path(), &readonly, &writable)
            .stdin(Stdio::from(read_fd))
            .stdout(Stdio::from(write_fd))
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

#[cfg(target_os = "linux")]
fn production_shaped_bwrap_probe(root: &Path, readonly: &Path, writable: &Path) -> Command {
    let mut command = Command::new(super::bwrap::packaged_bwrap_path().unwrap_or("/usr/bin/bwrap"));
    command
        .arg("--ro-bind")
        .arg("/")
        .arg("/")
        .arg("--dev")
        .arg("/dev")
        .arg("--proc")
        .arg("/proc")
        .arg("--bind")
        .arg(root)
        .arg(root)
        .arg("--tmpfs")
        .arg("/tmp")
        .arg("--ro-bind-fd")
        .arg("0")
        .arg(readonly)
        .arg("--bind-fd")
        .arg("1")
        .arg(writable)
        .arg("--unshare-all")
        .arg("--share-net")
        .arg("--die-with-parent")
        .arg("/bin/true");
    command
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn probe_uses_production_mount_namespace_and_descriptor_shape() {
        let command = production_shaped_bwrap_probe(
            Path::new("/var/tmp/astrid-probe"),
            Path::new("/var/tmp/astrid-probe/readonly"),
            Path::new("/var/tmp/astrid-probe/writable"),
        );
        let args: Vec<_> = command
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        for expected in [
            "--ro-bind",
            "--dev",
            "--proc",
            "--bind",
            "--tmpfs",
            "--ro-bind-fd",
            "--bind-fd",
            "--unshare-all",
            "--share-net",
            "--die-with-parent",
        ] {
            assert!(args.iter().any(|arg| arg == expected), "missing {expected}");
        }
        assert!(
            args.windows(3)
                .any(|part| part == ["--ro-bind-fd", "0", "/var/tmp/astrid-probe/readonly"])
        );
        assert!(
            args.windows(3)
                .any(|part| part == ["--bind-fd", "1", "/var/tmp/astrid-probe/writable"])
        );
        assert_eq!(args.last().map(String::as_str), Some("/bin/true"));
    }

    #[test]
    #[ignore = "requires a Linux host that permits Bubblewrap namespaces"]
    fn live_probe_executes_native_sandbox() {
        assert!(probe_native_process_sandbox());
    }
}
