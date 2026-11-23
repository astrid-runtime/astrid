use super::super::{build_manifest_content, discover_opaque_assets, pack_capsule_archive};
use super::*;
use std::fs;
use std::path::PathBuf;

#[test]
fn preserves_a_pinned_worker_in_the_generated_manifest() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("assets")).unwrap();
    let wasm = source.path().join("controller.wasm");
    fs::write(&wasm, b"\0asm\x01\0\0\0").unwrap();
    let worker = b"pinned worker";
    fs::write(source.path().join("assets/worker.wasm"), worker).unwrap();
    let hash = blake3::hash(worker).to_hex();
    fs::write(source.path().join("Capsule.toml"), format!(
        "[package]\nname = 'controller'\nversion = '1.0.0'\n[[component]]\nid = 'main'\nfile = 'controller.wasm'\ntype = 'executable'\n[[component]]\nid = 'worker'\nfile = 'assets/worker.wasm'\ntype = 'compute-worker'\nhash = 'blake3:{hash}'\n"
    )).unwrap();
    let (manifest, _pins) =
        build_manifest_content(source.path(), &wasm, "controller", "1.0.0", "controller")
            .expect("a pinned prebuilt worker must remain packaged with the one built executable");
    assert!(manifest.contains("assets/worker.wasm"));
}

#[test]
fn packs_one_cdylib_with_pinned_prebuilt_worker_and_assets() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("assets")).unwrap();
    let wasm_path = source.path().join("renamed_controller.wasm");
    fs::write(&wasm_path, b"\0asm\x01\0\0\0").unwrap();
    let worker = b"prebuilt compute worker";
    let kernel = b"immutable kernel asset";
    fs::write(source.path().join("assets/worker.wasm"), worker).unwrap();
    fs::write(source.path().join("assets/kernel.img"), kernel).unwrap();
    let worker_hash = blake3::hash(worker).to_hex();
    let kernel_hash = blake3::hash(kernel).to_hex();
    fs::write(
        source.path().join("Capsule.toml"),
        format!(
            "[package]\nname = \"realm\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"controller\"\nfile = \"old_controller.wasm\"\ntype = \"executable\"\n\n[[component]]\nid = \"worker\"\nfile = \"assets/worker.wasm\"\ntype = \"compute-worker\"\nhash = \"blake3:{worker_hash}\"\n\n[[component.asset]]\nid = \"kernel\"\nfile = \"assets/kernel.img\"\nhash = \"blake3:{kernel_hash}\"\n"
        ),
    )
    .unwrap();
    let (manifest, pins) = build_manifest_content(
        source.path(),
        &wasm_path,
        "realm",
        "1.0.0",
        "renamed_controller",
    )
    .unwrap();
    assert!(manifest.contains("file = \"renamed_controller.wasm\""));
    assert!(manifest.contains("file = \"assets/worker.wasm\""));
    assert!(manifest.contains("file = \"assets/kernel.img\""));
    let archive_path = source.path().join("realm.capsule");
    let assets = discover_opaque_assets(source.path()).unwrap();
    let asset_refs = assets.iter().map(PathBuf::as_path).collect::<Vec<_>>();
    pack_capsule_archive(
        &archive_path,
        &manifest,
        Some(&wasm_path),
        source.path(),
        &asset_refs,
        None,
    )
    .unwrap();
    pins.verify_archive(&archive_path).unwrap();
    let decoder = flate2::read::GzDecoder::new(File::open(&archive_path).unwrap());
    let mut archive = tar::Archive::new(decoder);
    let mut observed = std::collections::BTreeMap::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let name = entry.path().unwrap().to_string_lossy().into_owned();
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut entry, &mut bytes).unwrap();
        observed.insert(name, bytes);
    }
    assert_eq!(observed["assets/worker.wasm"], worker);
    assert_eq!(observed["assets/kernel.img"], kernel);
    assert_eq!(observed["Capsule.toml"], manifest.as_bytes());
    assert_eq!(observed["renamed_controller.wasm"], b"\0asm\x01\0\0\0");
    drop(archive); // Windows cannot replace an archive while this reader holds it open.
    let key = astrid_crypto::KeyPair::generate();
    crate::artifact::sign_archive(&archive_path, &key).unwrap();
    assert!(matches!(
        crate::artifact::verify_archive(&archive_path).unwrap(),
        crate::artifact::ArtifactVerification::Signed(_)
    ));
    assert_eq!(
        crate::artifact::read_archive_text(&archive_path, "assets/worker.wasm")
            .unwrap()
            .as_bytes(),
        worker
    );

    let (_, old_pins) = build_manifest_content(
        source.path(),
        &wasm_path,
        "realm",
        "1.0.0",
        "renamed_controller",
    )
    .unwrap();
    // A source file changed after the first check cannot become a signed
    // package under its old manifest pin.
    fs::write(source.path().join("assets/worker.wasm"), b"changed").unwrap();
    let changed_path = source.path().join("changed.capsule");
    pack_capsule_archive(
        &changed_path,
        &manifest,
        Some(&wasm_path),
        source.path(),
        &asset_refs,
        None,
    )
    .unwrap();
    assert!(
        old_pins
            .verify_archive(&changed_path)
            .unwrap_err()
            .to_string()
            .contains("hash mismatch")
    );
}

#[test]
fn rejects_unpinned_or_ambiguous_prebuilt_components() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("assets")).unwrap();
    let wasm_path = source.path().join("controller.wasm");
    fs::write(&wasm_path, b"\0asm\x01\0\0\0").unwrap();
    fs::write(source.path().join("assets/worker.wasm"), b"worker").unwrap();
    let pin = blake3::hash(b"worker").to_hex();
    let base = "[package]\nname = \"realm\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"controller\"\nfile = \"controller.wasm\"\ntype = \"executable\"\n\n[[component]]\nid = \"worker\"\nfile = \"assets/worker.wasm\"\ntype = \"compute-worker\"\n";
    let cases = [
        (String::new(), "require a blake3 hash"),
        (
            format!("hash = \"blake3:{}\"\n", blake3::hash(b"tampered").to_hex()),
            "hash mismatch",
        ),
        (
            format!("hash = \"blake3:{pin}\"\nentrypoint = \"assets/worker.wasm\"\n"),
            "both `file` and `entrypoint`",
        ),
        (
            format!(
                "hash = \"blake3:{pin}\"\n[[component.asset]]\nid = \"duplicate\"\nfile = \"assets/worker.wasm\"\nhash = \"blake3:{pin}\"\n"
            ),
            "repeats packaged",
        ),
        (
            format!(
                "hash = \"blake3:{pin}\"\n[[component]]\nid = \"other\"\nfile = \"assets/worker.wasm\"\ntype = \"executable\"\n"
            ),
            "exactly one cdylib",
        ),
    ];
    for (suffix, expected) in cases {
        fs::write(
            source.path().join("Capsule.toml"),
            format!("{base}{suffix}"),
        )
        .unwrap();
        let error =
            build_manifest_content(source.path(), &wasm_path, "realm", "1.0.0", "controller")
                .unwrap_err();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}

#[cfg(unix)]
#[test]
fn rejects_prebuilt_asset_symlink_and_path_escape() {
    use std::os::unix::fs::symlink;
    let source = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("assets")).unwrap();
    fs::write(outside.path().join("worker.wasm"), b"worker").unwrap();
    symlink(
        outside.path().join("worker.wasm"),
        source.path().join("assets/worker.wasm"),
    )
    .unwrap();
    let wasm_path = source.path().join("controller.wasm");
    fs::write(&wasm_path, b"\0asm\x01\0\0\0").unwrap();
    let pin = blake3::hash(b"worker").to_hex();
    let manifest = |path: &str| {
        format!(
            "[package]\nname = \"realm\"\nversion = \"1.0.0\"\n[[component]]\nid = \"controller\"\nfile = \"controller.wasm\"\n[[component]]\nid = \"worker\"\nfile = \"{path}\"\ntype = \"compute-worker\"\nhash = \"blake3:{pin}\"\n"
        )
    };
    fs::write(
        source.path().join("Capsule.toml"),
        manifest("assets/worker.wasm"),
    )
    .unwrap();
    assert!(
        build_manifest_content(source.path(), &wasm_path, "realm", "1.0.0", "controller")
            .unwrap_err()
            .to_string()
            .contains("symlink")
    );
    fs::write(
        source.path().join("Capsule.toml"),
        manifest("assets/../outside.wasm"),
    )
    .unwrap();
    assert!(
        build_manifest_content(source.path(), &wasm_path, "realm", "1.0.0", "controller")
            .unwrap_err()
            .to_string()
            .contains("canonical relative path")
    );
}

#[test]
fn existing_single_component_types_and_extensions_remain_compatible() {
    let source = tempfile::tempdir().unwrap();
    for kind in [
        "",
        "type = ''",
        "type = 'executable'",
        "type = 'library'",
        "type = 'custom'",
    ] {
        let mut doc = format!(
            "[[component]]\nid = 'legacy'\nentrypoint = 'old.wasm'\n{kind}\n[[component.asset]]\nfile = 'opaque-data'\n"
        ).parse::<DocumentMut>().unwrap();
        let pins = bind_manifest_to_packaged_wasm(&mut doc, source.path(), "new.wasm").unwrap();
        assert_eq!(doc["component"][0]["entrypoint"].as_str(), Some("new.wasm"));
        assert_eq!(
            doc["component"][0]["asset"][0]["file"].as_str(),
            Some("opaque-data")
        );
        // No new archive read or pin pass is added for an existing single component.
        pins.verify_archive(&source.path().join("not-opened.capsule"))
            .unwrap();
    }
}

#[test]
fn asset_paths_have_one_canonical_spelling() {
    for path in ["assets/a", "assets/nested/worker.wasm"] {
        validate_asset_path(path).unwrap();
    }
    for path in [
        "assets//a",
        "assets/./a",
        "assets/a/",
        "assets/../a",
        "./assets/a",
        "/assets/a",
        "assets",
        "skills/a",
        "assets\\a",
        "assets/\0a",
        "assets/.",
        "assets/..",
        "assets/",
        "C:/assets/a",
    ] {
        assert!(
            validate_asset_path(path).is_err(),
            "accepted noncanonical {path:?}"
        );
    }
}

#[test]
fn missing_or_linked_archive_worker_cannot_satisfy_its_pin() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("assets")).unwrap();
    fs::write(source.path().join("assets/worker.wasm"), b"worker").unwrap();
    let hash = blake3::hash(b"worker").to_hex();
    let manifest = format!(
        "[[component]]\nid = 'main'\nfile = 'main.wasm'\n[[component]]\nid = 'worker'\nfile = 'assets/worker.wasm'\ntype = 'compute-worker'\nhash = 'blake3:{hash}'\n"
    );
    for linked in [false, true] {
        let pins = bind_manifest_to_packaged_wasm(
            &mut manifest.parse::<DocumentMut>().unwrap(),
            source.path(),
            "main.wasm",
        )
        .unwrap();
        let archive_path = source.path().join("incomplete.capsule");
        let gzip = flate2::write::GzEncoder::new(
            File::create(&archive_path).unwrap(),
            flate2::Compression::fast(),
        );
        let mut archive = tar::Builder::new(gzip);
        if linked {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_link_name("elsewhere").unwrap();
            header.set_size(0);
            header.set_cksum();
            archive
                .append_data(&mut header, "assets/worker.wasm", &b""[..])
                .unwrap();
        }
        archive.into_inner().unwrap().finish().unwrap();
        let error = pins.verify_archive(&archive_path).unwrap_err().to_string();
        assert!(
            error.contains(if linked {
                "not a regular"
            } else {
                "missing from archive"
            }),
            "{error}"
        );
    }
}

#[test]
fn build_dispatch_packages_and_signs_pinned_worker_bytes() {
    if !super::super::tests::rust_target_is_installed("wasm32-unknown-unknown") {
        eprintln!("requires the installed wasm32-unknown-unknown target");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("source");
    fs::create_dir_all(source.join("src")).unwrap();
    fs::create_dir(source.join(".cargo")).unwrap();
    fs::create_dir(source.join("assets")).unwrap();
    fs::write(source.join("Cargo.toml"), "[package]\nname = 'pinned-dispatch-probe'\nversion = '1.0.0'\nedition = '2024'\n[lib]\ncrate-type = ['cdylib']\n").unwrap();
    fs::write(
        source.join(".cargo/config.toml"),
        "[build]\ntarget = 'wasm32-unknown-unknown'\n",
    )
    .unwrap();
    fs::write(
        source.join("src/lib.rs"),
        "#[unsafe(no_mangle)] pub extern \"C\" fn answer() -> u32 { 42 }\n",
    )
    .unwrap();
    let worker = b"exact prebuilt worker bytes";
    fs::write(source.join("assets/worker.wasm"), worker).unwrap();
    let hash = blake3::hash(worker).to_hex();
    fs::write(source.join("Capsule.toml"), format!(
        "[package]\nname = 'pinned-dispatch-probe'\nversion = '1.0.0'\n[[component]]\nid = 'main'\nfile = 'old.wasm'\ntype = 'executable'\n[[component]]\nid = 'worker'\nfile = 'assets/worker.wasm'\ntype = 'compute-worker'\nhash = 'blake3:{hash}'\n"
    )).unwrap();
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args([
        "--exact",
        "rust::component_pins::tests::build_dispatch_probe",
        "--ignored",
        "--nocapture",
    ]);
    for (key, _) in std::env::vars_os() {
        if key
            .to_str()
            .is_some_and(|key| key.starts_with("ASTRID_") || key.starts_with("AOS_"))
        {
            command.env_remove(key);
        }
    }
    let output = command
        .env("ASTRID_HOME", root.path().join("home"))
        .env("ASTRID_BUILD_PIN_PROBE", &source)
        .current_dir(&source)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("pinned build completed"));
    let archive = source.join("dist/pinned-dispatch-probe.capsule");
    assert!(matches!(
        crate::artifact::verify_archive(&archive).unwrap(),
        crate::artifact::ArtifactVerification::Signed(_)
    ));
    assert_eq!(
        crate::artifact::read_archive_text(&archive, "assets/worker.wasm")
            .unwrap()
            .as_bytes(),
        worker
    );
}

#[test]
#[ignore = "owned subprocess for build_dispatch_packages_and_signs_pinned_worker_bytes"]
fn build_dispatch_probe() {
    let source = std::env::var("ASTRID_BUILD_PIN_PROBE").expect("explicit disposable source");
    crate::build::run_build(Some(&source), Some("dist"), None, None).unwrap();
    println!("pinned build completed");
}

#[cfg(unix)]
#[test]
fn non_regular_sources_are_rejected_before_open() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("assets")).unwrap();
    let pipe = source.path().join("assets/worker.wasm");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .unwrap()
            .success()
    );
    let error = validate_source_path(source.path(), "assets/worker.wasm").unwrap_err();
    assert!(error.to_string().contains("regular file"));
}

#[cfg(unix)]
#[test]
fn replacing_a_validated_source_with_a_fifo_cannot_block_open() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("assets")).unwrap();
    let path = source.path().join("assets/worker.wasm");
    fs::write(&path, b"worker").unwrap();
    validate_source_path(source.path(), "assets/worker.wasm").unwrap();
    fs::remove_file(&path).unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader_path = path.clone();
    let reader = std::thread::spawn(move || {
        sender
            .send(open_pinned_source(&reader_path).map(|_| ()))
            .unwrap();
    });
    let observed = receiver.recv_timeout(std::time::Duration::from_secs(1));
    // A broken blocking open must not leave a stuck test thread: pair its read
    // with an owned writer, reap it, then fail the bounded observation.
    let writer = if matches!(observed, Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
        Some(fs::OpenOptions::new().write(true).open(&path).unwrap())
    } else {
        None
    };
    reader.join().unwrap();
    drop(writer);
    let error = observed
        .expect("pinned source open must not wait for a FIFO writer")
        .unwrap_err();
    assert!(error.to_string().contains("regular file"));
}

#[cfg(unix)]
#[test]
fn replacing_a_validated_leaf_with_a_symlink_is_refused_at_open() {
    let source = tempfile::tempdir().unwrap();
    fs::create_dir(source.path().join("assets")).unwrap();
    let path = source.path().join("assets/worker.wasm");
    fs::write(&path, b"worker").unwrap();
    validate_source_path(source.path(), "assets/worker.wasm").unwrap();
    fs::remove_file(&path).unwrap();
    let target = source.path().join("replacement");
    fs::write(&target, b"worker").unwrap();
    std::os::unix::fs::symlink(&target, &path).unwrap();
    assert!(open_pinned_source(&path).is_err());
}
