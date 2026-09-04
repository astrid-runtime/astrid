use std::process::{Command, Stdio};

use serde::Serialize;

#[derive(Serialize)]
struct LockDistro {
    id: &'static str,
    version: &'static str,
    #[serde(rename = "resolved-at")]
    resolved_at: &'static str,
}

#[derive(Serialize)]
struct LockCapsule {
    name: &'static str,
    version: &'static str,
    source: &'static str,
    hash: String,
    resolved_ref: &'static str,
}

#[derive(Serialize)]
struct DistroLock {
    #[serde(rename = "schema-version")]
    schema_version: u32,
    distro: LockDistro,
    #[serde(rename = "capsule")]
    capsules: Vec<LockCapsule>,
    #[serde(rename = "manifest-hash")]
    manifest_hash: String,
}

#[test]
fn clean_stop_preserves_a_pin_created_in_the_mounted_projection() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("astrid-home");
    let run_dir = root.path().join("astrid-run");
    let client_config = root.path().join("client.toml");
    std::fs::write(&client_config, "run_idle_secs = 120\n").unwrap();

    let shuttle = write_signed_shuttle(root.path(), "pin-survival");
    std::fs::create_dir_all(&run_dir).unwrap();
    let missing_pin_stderr = root.path().join("missing-pin.stderr");
    let missing_pin = astrid(root.path(), &home, &run_dir, &client_config)
        .args(["distro", "apply", "--offline", "--yes"])
        .arg(&shuttle)
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(&missing_pin_stderr).unwrap())
        .status()
        .unwrap();
    let missing_pin_stderr = std::fs::read_to_string(missing_pin_stderr).unwrap();
    assert!(!missing_pin.success(), "{missing_pin_stderr}");
    assert!(
        missing_pin_stderr.contains("no signing-key pin"),
        "product apply bypassed pin-first admission: {missing_pin_stderr}"
    );
    assert!(!home.join("trust/pin-survival.pub").exists());

    let started = detached(astrid(root.path(), &home, &run_dir, &client_config).arg("start"))
        .status()
        .unwrap();
    assert!(started.success());

    let pin = home.join("trust/pin-survival.pub");
    std::fs::create_dir_all(pin.parent().unwrap()).unwrap();
    std::fs::write(&pin, b"ed25519:operator-published-pin\n").unwrap();

    let stopped = detached(astrid(root.path(), &home, &run_dir, &client_config).arg("stop"))
        .status()
        .unwrap();
    assert!(stopped.success());
    assert_stopped_volume_only(&home);
    assert!(!run_dir.exists());

    let restarted = detached(astrid(root.path(), &home, &run_dir, &client_config).arg("restart"))
        .status()
        .unwrap();
    assert!(restarted.success());
    assert_eq!(
        std::fs::read_to_string(&pin).unwrap(),
        "ed25519:operator-published-pin\n"
    );

    let final_stop = detached(astrid(root.path(), &home, &run_dir, &client_config).arg("stop"))
        .status()
        .unwrap();
    assert!(final_stop.success());
    assert_stopped_volume_only(&home);
    assert!(!run_dir.exists());
}

fn astrid(
    root: &std::path::Path,
    home: &std::path::Path,
    run_dir: &std::path::Path,
    client_config: &std::path::Path,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_astrid"));
    command
        .current_dir(root)
        .env("ASTRID_HOME", home)
        .env("ASTRID_RUN_DIR", run_dir)
        .env("ASTRID_CLIENT_CONFIG_PATH", client_config)
        .env("HOME", root);
    command
}

fn detached(command: &mut Command) -> &mut Command {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
}

fn assert_stopped_volume_only(home: &std::path::Path) {
    let mut entries = std::fs::read_dir(home)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    assert_eq!(entries.len(), 1, "stopped root retained sidecars");
    assert_eq!(
        entries[0].file_name(),
        std::ffi::OsStr::new("astrid.volume")
    );
    assert!(entries[0].metadata().unwrap().is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            entries[0].metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

fn write_signed_shuttle(root: &std::path::Path, distro_id: &'static str) -> std::path::PathBuf {
    let key = astrid_crypto::KeyPair::generate();
    let public_key = key.export_public_key();
    let public_wire = format!("ed25519:{}", public_key.to_base64());
    let capsule = b"disposable-capsule-not-installed";
    let manifest = format!(
        "schema-version = 1\n\n\
         [distro]\nid = \"{distro_id}\"\nname = \"Pin Survival\"\nversion = \"0.1.0\"\n\n\
         [distro.signing]\npubkey = \"{public_wire}\"\n\n\
         [[capsule]]\nname = \"astrid-capsule-cli\"\nsource = \"@test/cli\"\n\
         version = \"0.1.0\"\nrole = \"uplink\"\n"
    );
    let manifest = manifest.into_bytes();
    let lock = DistroLock {
        schema_version: 1,
        distro: LockDistro {
            id: distro_id,
            version: "0.1.0",
            resolved_at: "1970-01-01T00:00:00+00:00",
        },
        capsules: vec![LockCapsule {
            name: "astrid-capsule-cli",
            version: "0.1.0",
            source: "@test/cli",
            hash: format!("blake3:{}", blake3::hash(capsule).to_hex()),
            resolved_ref: "v0.1.0",
        }],
        manifest_hash: format!("blake3:{}", blake3::hash(&manifest).to_hex()),
    };
    let lock_bytes = serde_json::to_vec(&lock).unwrap();
    let mut digest = blake3::Hasher::new();
    digest.update(b"astrid-distro-lock-sig-v1\x00");
    digest.update(&lock_bytes);
    let signature = hex::encode(key.sign(digest.finalize().as_bytes()).as_bytes());
    let lock_toml = toml::to_string_pretty(&lock).unwrap();

    let path = root.join(format!("{distro_id}.shuttle"));
    let output = std::fs::File::create(&path).unwrap();
    let encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (name, bytes) in [
        ("Distro.toml", manifest.as_slice()),
        ("Distro.lock", lock_toml.as_bytes()),
        ("Distro.sig", signature.as_bytes()),
        ("capsules/astrid-capsule-cli.capsule", capsule.as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, name, bytes).unwrap();
    }
    archive.into_inner().unwrap().finish().unwrap();
    path
}

#[test]
fn run_dir_equal_to_home_fails_start_without_deleting_durable_media() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("astrid-home");
    let client_config = root.path().join("client.toml");
    std::fs::write(&client_config, "run_idle_secs = 120\n").unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("astrid.volume"), b"disposable-durable-media").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            home.join("astrid.volume"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    let output = astrid(root.path(), &home, &home, &client_config)
        .arg("start")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "start accepted root override: {stderr}"
    );
    assert!(
        stderr.contains("ASTRID_RUN_DIR overlaps the Astrid durable root"),
        "unexpected startup failure: {stderr}"
    );
    assert_stopped_volume_only(&home);
}

#[test]
fn run_dir_equal_to_home_fails_all_lifecycle_commands_without_stale_marker_mutation() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("astrid-home");
    let client_config = root.path().join("client.toml");
    std::fs::write(&client_config, "run_idle_secs = 120\n").unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("astrid.volume"), b"disposable-durable-media").unwrap();
    let run_dir = home.join("run");
    std::fs::create_dir_all(&run_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            home.join("astrid.volume"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let stale_files = [
        (run_dir.join("system.ready"), b"ready".as_slice()),
        (run_dir.join("system.pid"), b"424242".as_slice()),
        (run_dir.join("system.token"), b"token".as_slice()),
    ];
    for (path, contents) in &stale_files {
        std::fs::write(path, *contents).unwrap();
    }

    for command in ["start", "status", "stop", "restart"] {
        let output = astrid(root.path(), &home, &home, &client_config)
            .arg(command)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{command} accepted root override: {stderr}"
        );
        assert!(
            stderr.contains("ASTRID_RUN_DIR overlaps the Astrid durable root"),
            "unexpected {command} failure: {stderr}"
        );
        assert_rejected_stale_fixture_unchanged(&home, &run_dir, &stale_files);
    }
}

#[test]
fn external_run_dir_lifecycle_admits_valid_paths_but_rejects_overrides_early() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("astrid-home");
    let run_dir = root.path().join("astrid-run");
    let client_config = root.path().join("client.toml");
    std::fs::write(&client_config, "run_idle_secs = 120\n").unwrap();
    std::fs::create_dir_all(&run_dir).unwrap();

    let started = detached(astrid(root.path(), &home, &run_dir, &client_config).arg("start"))
        .status()
        .unwrap();
    assert!(started.success());

    let status = astrid(root.path(), &home, &run_dir, &client_config)
        .arg("status")
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(String::from_utf8_lossy(&status.stdout).contains("Astrid daemon"));

    let already_running = astrid(root.path(), &home, &run_dir, &client_config)
        .arg("start")
        .output()
        .unwrap();
    assert!(already_running.status.success());
    let already_running_text = format!(
        "{}{}",
        String::from_utf8_lossy(&already_running.stdout),
        String::from_utf8_lossy(&already_running.stderr)
    );
    assert!(already_running_text.contains("already running"));

    for (override_path, expected_error) in [
        (home.clone(), "overlaps the Astrid durable root"),
        (std::path::PathBuf::from("run"), "must be an absolute path"),
    ] {
        let rejected = astrid(root.path(), &home, &override_path, &client_config)
            .arg("start")
            .output()
            .unwrap();
        assert!(!rejected.status.success());
        let rejected_stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            rejected_stderr.contains(expected_error),
            "override was not rejected at admission: {rejected_stderr}"
        );
        assert!(!rejected_stderr.contains("already running"));
    }

    let restarted = detached(astrid(root.path(), &home, &run_dir, &client_config).arg("restart"))
        .status()
        .unwrap();
    assert!(restarted.success());

    let stopped = detached(astrid(root.path(), &home, &run_dir, &client_config).arg("stop"))
        .status()
        .unwrap();
    assert!(stopped.success());
    assert_stopped_volume_only(&home);
    assert!(!run_dir.exists());
}

#[test]
fn mcp_lifecycle_rejects_root_run_dir_before_stale_marker_mutation() {
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("astrid-home");
    let client_config = root.path().join("client.toml");
    std::fs::write(&client_config, "run_idle_secs = 120\n").unwrap();
    std::fs::create_dir_all(&home).unwrap();
    std::fs::write(home.join("astrid.volume"), b"disposable-durable-media").unwrap();
    let run_dir = home.join("run");
    std::fs::create_dir_all(&run_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(
            home.join("astrid.volume"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }
    let stale_files = [
        (run_dir.join("system.ready"), b"ready".as_slice()),
        (run_dir.join("system.pid"), b"424242".as_slice()),
        (run_dir.join("system.token"), b"token".as_slice()),
    ];
    for (path, contents) in &stale_files {
        std::fs::write(path, *contents).unwrap();
    }

    for command in [
        vec![
            "serve".to_owned(),
            "--workspace".to_owned(),
            root.path().display().to_string(),
        ],
        vec!["gateway".to_owned()],
        vec!["ready".to_owned(), "--format".to_owned(), "json".to_owned()],
    ] {
        let mut command_line = astrid(root.path(), &home, &home, &client_config);
        let output = bounded_mcp(&mut command_line, &command);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "mcp {:?} accepted root override: {}{}",
            command,
            String::from_utf8_lossy(&output.stdout),
            stderr
        );
        assert!(
            stderr.contains("ASTRID_RUN_DIR overlaps the Astrid durable root"),
            "unexpected mcp {:?} failure: {}{}",
            command,
            String::from_utf8_lossy(&output.stdout),
            stderr
        );
        assert_rejected_stale_fixture_unchanged(&home, &run_dir, &stale_files);
        assert!(
            !run_dir.join("mcp-gateway.sock").exists()
                && !run_dir.join("mcp-gateway.ready").exists()
                && !run_dir.join("mcp-gateway.lifecycle.lock").exists()
                && !run_dir.join("mcp-gateway.start.lock").exists()
                && !run_dir.join("mcp-gateway.starting").exists()
                && !run_dir.join("mcp-gateway.startup.json").exists(),
            "rejected mcp {command:?} created a gateway marker"
        );
    }
}

fn bounded_mcp(command: &mut Command, args: &[String]) -> std::process::Output {
    let mut child = command
        .arg("mcp")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(10))
        .expect("valid admission timeout");
    let status = loop {
        match child.try_wait().unwrap() {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                child.kill().unwrap();
                panic!("astrid mcp {args:?} did not fail admission promptly");
            },
            None => std::thread::sleep(std::time::Duration::from_millis(25)),
        }
    };
    let stdout = child.stdout.take().map(|mut stdout| {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut stdout, &mut bytes).unwrap();
        bytes
    });
    let stderr = child.stderr.take().map(|mut stderr| {
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut stderr, &mut bytes).unwrap();
        bytes
    });
    std::process::Output {
        status,
        stdout: stdout.unwrap_or_default(),
        stderr: stderr.unwrap_or_default(),
    }
}

fn assert_rejected_stale_fixture_unchanged(
    home: &std::path::Path,
    run_dir: &std::path::Path,
    stale_files: &[(std::path::PathBuf, &[u8])],
) {
    let names = |path: &std::path::Path| {
        let mut names: Vec<String> = std::fs::read_dir(path)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    assert_eq!(names(home), ["astrid.volume", "run"]);
    assert_eq!(
        names(run_dir),
        ["system.pid", "system.ready", "system.token"]
    );
    let volume = home.join("astrid.volume");
    assert!(volume.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(volume).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    for (path, contents) in stale_files {
        assert_eq!(
            std::fs::read(path).unwrap(),
            *contents,
            "rejected command mutated stale marker {}",
            path.display()
        );
    }
}
