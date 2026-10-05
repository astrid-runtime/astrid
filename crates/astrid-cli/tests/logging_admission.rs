use std::process::{Command, Stdio};

#[test]
fn cli_logging_does_not_materialize_a_stopped_runtime_before_principal_validation() {
    for prompt in [None, Some("not dispatched")] {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("runtime");
        astrid_core::platform_fs::ensure_private_directory(&home).unwrap();
        let volume = home.join("astrid.volume");
        let original = b"unopened fixture volume";
        std::fs::write(&volume, original).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_astrid"));
        command
            .current_dir(root.path())
            .env("ASTRID_HOME", &home)
            .env_remove("ASTRID_RUN_DIR")
            .env_remove("ASTRID_PRINCIPAL_ID")
            .env_remove("AOS_PRINCIPAL_ID")
            .args(["--principal", "invalid/principal"])
            .stdin(Stdio::null());
        if let Some(prompt) = prompt {
            command.args(["--prompt", prompt]);
        }
        let output = command.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
        assert_eq!(std::fs::read(volume).unwrap(), original);
        let entries: Vec<_> = std::fs::read_dir(&home)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, [std::ffi::OsString::from("astrid.volume")]);
    }
}
