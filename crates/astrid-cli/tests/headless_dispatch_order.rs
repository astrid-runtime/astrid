use std::process::{Command, Stdio};

#[test]
fn headless_auto_approve_is_rejected_before_the_update_notice() {
    let root = tempfile::tempdir().unwrap();
    let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid-home"));
    home.ensure().unwrap();
    let checked_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    std::fs::create_dir_all(home.var_dir()).unwrap();
    std::fs::write(
        home.var_dir().join("update-check.json"),
        format!(
            "{{\"checked_at\":{checked_at},\"latest_version\":\"999.0.0\",\
             \"channel\":\"stable\"}}"
        ),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_astrid"))
        .args(["--yes", "run", "hello"])
        .env("ASTRID_HOME", home.root())
        .env("HOME", root.path())
        .env_remove("ASTRID_CLIENT_CONFIG_PATH")
        .stdin(Stdio::null())
        .output()
        .expect("run astrid with a fresh update cache");

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("headless approval automation is unsupported"));
    assert!(stderr.contains("correlated"));
    assert!(!stderr.contains("Update available"));
}

#[test]
fn nested_run_auto_approve_is_rejected_before_the_update_notice() {
    for flag in ["--yes", "--yolo", "--autonomous"] {
        let root = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(root.path().join("astrid-home"));
        home.ensure().unwrap();
        let checked_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::create_dir_all(home.var_dir()).unwrap();
        std::fs::write(
            home.var_dir().join("update-check.json"),
            format!(
                "{{\"checked_at\":{checked_at},\"latest_version\":\"999.0.0\",\
                 \"channel\":\"stable\"}}"
            ),
        )
        .unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_astrid"))
            .args(["run", "hello", flag])
            .env("ASTRID_HOME", home.root())
            .env("HOME", root.path())
            .env_remove("ASTRID_CLIENT_CONFIG_PATH")
            .stdin(Stdio::null())
            .output()
            .expect("run astrid with a fresh update cache");

        assert_eq!(output.status.code(), Some(1), "unexpected exit for {flag}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("headless approval automation is unsupported"),
            "missing unsupported rejection for {flag}: {stderr}"
        );
        assert!(
            stderr.contains("correlated"),
            "missing correlation for {flag}"
        );
        assert!(
            !stderr.contains("Update available"),
            "unexpected update banner for {flag}: {stderr}"
        );
    }
}
