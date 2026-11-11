//! Creation must not expose rollback bytes through an inherited ACL.

#[test]
fn anonymous_scratch_is_private_even_under_inherited_acl() {
    const PROBE: &str = "ASTRID_TEST_SCRATCH_ACL_PROBE";
    if std::env::var_os(PROBE).is_some() {
        match super::create_private_scratch_file() {
            Ok(file) => super::super::macos_acl::validate(&file)
                .expect("scratch handle exposed an inherited ACL before returning"),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied),
        }
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    assert!(
        std::process::Command::new("/bin/chmod")
            .args([
                "+a",
                "everyone allow read,readattr,file_inherit,directory_inherit"
            ])
            .arg(directory.path())
            .status()
            .unwrap()
            .success()
    );
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "platform_fs::private_scratch::tests::anonymous_scratch_is_private_even_under_inherited_acl", "--nocapture"])
        .env(PROBE, "1")
        .env("TMPDIR", directory.path())
        .output().unwrap();
    assert!(
        output.status.success(),
        "unsafe scratch: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
