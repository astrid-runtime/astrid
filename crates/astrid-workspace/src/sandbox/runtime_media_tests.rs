//! Native sandbox coverage for durable runtime media, using synthetic files only.
use super::*;

const PROBE_HOME: &str = "ASTRID_TEST_RUNTIME_MEDIA_HOME";
const MARKER: &[u8] = b"qa-private-runtime-media";

#[cfg(target_os = "linux")]
#[test]
fn attached_legacy_profile_blocks_capsule_native_wrapper() {
    if !super::bwrap::unsafe_legacy_astrid_profile() {
        return; // The Ubuntu QA run attaches the retired profile to exercise this branch.
    }
    let worktree = tempfile::tempdir_in("/var/tmp").expect("disposable worktree");
    let result = SandboxCommand::wrap(Command::new("/bin/true"), worktree.path());
    assert!(
        result.is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied),
        "an attached legacy profile must refuse the capsule native-process path"
    );
}

#[test]
fn runtime_media_remains_private_in_native_processes() {
    let temp_root = if cfg!(target_os = "linux") {
        PathBuf::from("/var/tmp")
    } else {
        std::env::temp_dir()
    };
    let tmp = tempfile::Builder::new()
        .prefix("astrid-media-")
        .tempdir_in(temp_root)
        .expect("isolated home");
    let root = tmp.path().canonicalize().expect("canonical home");
    let home = astrid_core::dirs::AstridHome::from_path(&root);
    for path in [
        home.storage_volume_path(),
        home.retired_root_storage_volume_path(),
    ] {
        std::fs::write(path, MARKER).expect("synthetic volume");
    }
    let output = Command::new(std::env::current_exe().expect("test executable"))
        .args([
            "--exact",
            "sandbox::runtime_media_tests::runtime_media_child",
            "--nocapture",
        ])
        .env("ASTRID_HOME", &root)
        .env(PROBE_HOME, &root)
        .output()
        .expect("native sandbox probe");
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn runtime_media_child() {
    let Some(root) = std::env::var_os(PROBE_HOME).map(PathBuf::from) else {
        return;
    };
    let home = astrid_core::dirs::AstridHome::from_path(&root);
    for path in [
        home.storage_volume_path(),
        home.retired_root_storage_volume_path(),
    ] {
        let mut command = Command::new("/bin/sh");
        // Reading an empty Linux mask may succeed; it must never return media bytes.
        command.args(["-c", "cat \"$1\"; printf changed > \"$1\"", "qa-media"]);
        command.arg(&path);
        let output = SandboxCommand::wrap(command, &root)
            .expect("wrap native command")
            .output()
            .expect("run native command");
        assert!(
            !output
                .stdout
                .windows(MARKER.len())
                .any(|bytes| bytes == MARKER),
            "native child read private media at {}",
            path.display()
        );
        assert_eq!(
            std::fs::read(&path).expect("host media"),
            MARKER,
            "native child changed private media at {}",
            path.display()
        );
    }
    let command = Command::new("/bin/echo");
    let volume = home.storage_volume_path();
    for path in [&volume, &root] {
        for writable in [false, true] {
            let paths = std::slice::from_ref(path);
            let (read, write) = if writable {
                (&[][..], paths)
            } else {
                (paths, &[][..])
            };
            let error = SandboxCommand::wrap_with_process_paths(
                &command,
                &root,
                &[],
                &[],
                read,
                write,
                false,
            )
            .expect_err("explicit grant must not reopen sensitive media");
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
    }
    let injection = RoInjection {
        source: root.join("public-injection"),
        target: volume.clone(),
    };
    std::fs::write(&injection.source, b"public").expect("injection source");
    let error = SandboxCommand::wrap_with_injections(command, &root, &[injection], &[])
        .expect_err("injection target must not reopen sensitive media");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_alias_grants_rejected(&root, &volume);
    #[cfg(target_os = "macos")]
    assert_seatbelt_retarget_remains_private(&root, &volume);
    let mut healthy = Command::new("/bin/sh");
    healthy.args([
        "-c",
        "printf healthy > qa-workspace-file; cat qa-workspace-file",
    ]);
    healthy.current_dir(&root);
    let output = SandboxCommand::wrap(healthy, &root)
        .expect("healthy sandbox")
        .output()
        .expect("healthy command");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"healthy");
}

#[cfg(target_os = "macos")]
fn assert_seatbelt_retarget_remains_private(root: &Path, volume: &Path) {
    let safe = root.join("seatbelt-safe");
    std::fs::write(&safe, b"safe").expect("initial safe grant");
    let alias = root.join("seatbelt-mutable-grant");
    std::os::unix::fs::symlink(&safe, &alias).expect("initial safe alias");
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "cat \"$1\"; printf changed > \"$1\"", "qa-retarget"]);
    command.arg(&alias);
    let mut wrapped = SandboxCommand::wrap_with_process_paths(
        &command,
        root,
        &[],
        &[],
        std::slice::from_ref(&alias),
        std::slice::from_ref(&alias),
        false,
    )
    .expect("safe alias is initially authorized");
    std::fs::remove_file(&alias).expect("remove safe alias");
    std::os::unix::fs::symlink(volume, &alias).expect("retarget to private media");
    let output = wrapped.output().expect("run Seatbelt retarget probe");
    assert!(
        !output
            .stdout
            .windows(MARKER.len())
            .any(|bytes| bytes == MARKER),
        "retargeted grant exposed private media"
    );
    assert_eq!(std::fs::read(volume).expect("host media"), MARKER);
}

fn assert_alias_grants_rejected(root: &Path, volume: &Path) {
    let alias = root.join("aliased-volume");
    std::os::unix::fs::symlink(volume, &alias).expect("synthetic alias");
    let command = Command::new("/bin/echo");
    for writable in [false, true] {
        let paths = std::slice::from_ref(&alias);
        let (read, write) = if writable {
            (&[][..], paths)
        } else {
            (paths, &[][..])
        };
        let error =
            SandboxCommand::wrap_with_process_paths(&command, root, &[], &[], read, write, false)
                .expect_err("alias grant must not reopen sensitive media");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
    let injection = RoInjection {
        source: root.join("public-injection"),
        target: alias,
    };
    let error = SandboxCommand::wrap_with_injections(command, root, &[injection], &[])
        .expect_err("aliased injection target must not reopen sensitive media");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

    let protected_dir = astrid_core::dirs::AstridHome::from_path(root).keys_dir();
    std::fs::create_dir(&protected_dir).expect("synthetic protected directory");
    let alias_dir = root.join("aliased-directory");
    std::os::unix::fs::symlink(&protected_dir, &alias_dir).expect("directory alias");
    let not_yet_existing_target = alias_dir.join("new-file");
    let injection = RoInjection {
        source: root.join("public-injection"),
        target: not_yet_existing_target,
    };
    let error =
        SandboxCommand::wrap_with_injections(Command::new("/bin/echo"), root, &[injection], &[])
            .expect_err("missing target beneath an alias must not reopen a protected directory");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

    assert_cow_alias_grants_rejected(root);
    #[cfg(target_os = "linux")]
    assert_bind_source_stays_fixed_after_alias_change(root, volume);
}

fn assert_cow_alias_grants_rejected(root: &Path) {
    let cow_mask = root.join("cow-private");
    std::fs::create_dir(&cow_mask).expect("synthetic copy-on-write mask");
    let cow_alias = root.join("cow-alias");
    std::os::unix::fs::symlink(&cow_mask, &cow_alias).expect("copy-on-write alias");
    for writable in [false, true] {
        let paths = std::slice::from_ref(&cow_alias);
        let (read, write) = if writable {
            (&[][..], paths)
        } else {
            (paths, &[][..])
        };
        let error = SandboxCommand::wrap_with_process_paths(
            &Command::new("/bin/echo"),
            root,
            &[],
            std::slice::from_ref(&cow_mask),
            read,
            write,
            false,
        )
        .expect_err("alias grant must not reopen copy-on-write state");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }
    let injection = RoInjection {
        source: root.join("public-injection"),
        target: cow_alias,
    };
    let error = SandboxCommand::wrap_with_injections(
        Command::new("/bin/echo"),
        root,
        &[injection],
        std::slice::from_ref(&cow_mask),
    )
    .expect_err("injection must not reopen copy-on-write state");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
}

#[cfg(target_os = "linux")]
fn assert_bind_source_stays_fixed_after_alias_change(root: &Path, volume: &Path) {
    let private_home = astrid_core::dirs::AstridHome::from_path(root).home_dir();
    std::fs::create_dir_all(&private_home).expect("synthetic principal home");
    let safe = private_home.join("safe-grant");
    std::fs::write(&safe, b"safe").expect("safe bind source");
    let mutable_alias = private_home.join("mutable-grant");
    std::os::unix::fs::symlink(&safe, &mutable_alias).expect("initial safe alias");
    let mut command = Command::new("/bin/cat");
    command.arg(&safe);
    let mut wrapped = SandboxCommand::wrap_with_process_paths(
        &command,
        root,
        &[],
        &[],
        std::slice::from_ref(&mutable_alias),
        &[],
        false,
    )
    .expect("safe alias is initially authorized");
    std::fs::remove_file(&mutable_alias).expect("remove safe alias");
    std::os::unix::fs::symlink(volume, &mutable_alias).expect("retarget to private media");
    let output = wrapped.output().expect("run captured bind after retarget");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"safe");
    assert_eq!(std::fs::read(volume).expect("host media"), MARKER);

    let writable = private_home.join("safe-write-grant");
    std::fs::write(&writable, b"before").expect("synthetic writable grant");
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf after > \"$1\"; cat \"$1\"", "qa-write"]);
    command.arg(&writable);
    let output = SandboxCommand::wrap_with_process_paths(
        &command,
        root,
        &[],
        &[],
        &[],
        std::slice::from_ref(&writable),
        false,
    )
    .expect("writable principal grant")
    .output()
    .expect("run writable grant");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"after");
    assert_eq!(
        std::fs::read(&writable).expect("host writable file"),
        b"after"
    );
}

#[test]
fn runtime_media_is_in_sensitive_path_inventory() {
    let tmp = tempfile::tempdir().expect("isolated home");
    let home = astrid_core::dirs::AstridHome::from_path(tmp.path());
    for path in [
        home.storage_volume_path(),
        home.retired_root_storage_volume_path(),
    ] {
        assert!(!SandboxCommand::sensitive_astrid_paths_in(&home).contains(&path));
        std::fs::write(&path, MARKER).expect("synthetic volume");
        assert!(
            SandboxCommand::sensitive_astrid_paths_in(&home).contains(&path),
            "existing runtime media must be masked: {}",
            path.display()
        );
    }
}
