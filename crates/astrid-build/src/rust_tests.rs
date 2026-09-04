use super::*;
use serde_json::json;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn getrandom_injection_is_wasm_only() {
    assert!(inject_getrandom_for_target(GETRANDOM_TARGET));
    assert!(!inject_getrandom_for_target("wasm32-wasip2"));
    assert!(!inject_getrandom_for_target("aarch64-apple-darwin"));
    assert_eq!(
        getrandom_rustflags_override(
            "wasm32-wasip2",
            &["--cfg=from-config".to_owned()],
            None,
            None,
            None,
            None,
        ),
        None
    );
}

#[test]
fn inherited_rustflags_and_environment_precedence_are_preserved() {
    let config = vec!["--cfg=from-config".to_owned()];
    let (key, value) = getrandom_rustflags_override(
        GETRANDOM_TARGET,
        &config,
        Some("--cfg=from-encoded"),
        Some("--cfg=from-plain"),
        Some("--cfg=from-target-env"),
        Some("--cfg=from-build-env"),
    )
    .unwrap();
    assert_eq!(key, "CARGO_ENCODED_RUSTFLAGS");
    assert_eq!(
        value,
        format!("--cfg=from-encoded{RUSTFLAGS_SEP}{GETRANDOM_CUSTOM_CFG}")
    );

    let (key, value) = getrandom_rustflags_override(
        GETRANDOM_TARGET,
        &config,
        None,
        Some("--cfg=from-plain"),
        Some("--cfg=from-target-env"),
        Some("--cfg=from-build-env"),
    )
    .unwrap();
    assert_eq!(key, "RUSTFLAGS");
    assert_eq!(value, format!("--cfg=from-plain {GETRANDOM_CUSTOM_CFG}"));

    let target_key = cargo_target_rustflags_env_key(GETRANDOM_TARGET);
    let (key, value) = getrandom_rustflags_override(
        GETRANDOM_TARGET,
        &config,
        None,
        None,
        Some("--cfg=from-target-env"),
        Some("--cfg=from-build-env"),
    )
    .unwrap();
    assert_eq!(key, target_key);
    assert_eq!(
        value,
        format!("--cfg=from-target-env {GETRANDOM_CUSTOM_CFG}")
    );

    let (key, value) =
        getrandom_rustflags_override(GETRANDOM_TARGET, &config, None, None, None, None).unwrap();
    assert_eq!(key, "CARGO_ENCODED_RUSTFLAGS");
    assert_eq!(
        value,
        format!("--cfg=from-config{RUSTFLAGS_SEP}{GETRANDOM_CUSTOM_CFG}")
    );

    let (key, value) = getrandom_rustflags_override(
        GETRANDOM_TARGET,
        &config,
        None,
        None,
        None,
        Some("--cfg=from-build-env"),
    )
    .unwrap();
    assert_eq!(key, "CARGO_BUILD_RUSTFLAGS");
    assert_eq!(
        value,
        format!("--cfg=from-build-env {GETRANDOM_CUSTOM_CFG}")
    );

    let repeated = vec![
        "-C".to_owned(),
        "opt-level=3".to_owned(),
        "-C".to_owned(),
        "debuginfo=2".to_owned(),
        GETRANDOM_CUSTOM_CFG.to_owned(),
    ];
    let (key, value) =
        getrandom_rustflags_override(GETRANDOM_TARGET, &repeated, None, None, None, None).unwrap();
    assert_eq!(key, "CARGO_ENCODED_RUSTFLAGS");
    assert_eq!(value, repeated.join(RUSTFLAGS_SEP));
}

#[test]
fn missing_getrandom_config_still_builds_dependency_with_injected_backend() {
    if !rust_target_is_installed(GETRANDOM_TARGET) {
        eprintln!(
            "skipping dependency build falsifier: {GETRANDOM_TARGET} target is not installed"
        );
        return;
    }

    let project = tempfile::tempdir().unwrap();
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(project.path().join("src")).unwrap();
    fs::create_dir_all(project.path().join("control-dep/src")).unwrap();
    fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname = \"missing-getrandom-config\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\ncontrol-dep = { path = \"control-dep\" }\ngetrandom = \"0.4\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("control-dep/Cargo.toml"),
        "[package]\nname = \"control-dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("control-dep/src/lib.rs"),
        "#[cfg(not(control_cfg))]\ncompile_error!(\"Cargo cfg-expression rustflags were dropped before this dependency\");\n\npub fn assert_cfg() {}\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n\n[target.'cfg(target_arch = \"wasm32\")']\nrustflags = [\"--check-cfg=cfg(control_cfg)\", \"--cfg=control_cfg\"]\n",
    )
    .unwrap();
    assert!(
        cargo_config_has_matching_target_rustflags_with_home(
            project.path(),
            None,
            GETRANDOM_TARGET,
        )
        .unwrap()
    );
    fs::write(
        project.path().join("src/lib.rs"),
        "pub fn random() -> [u8; 1] {\n    control_dep::assert_cfg();\n    let mut out = [0; 1];\n    getrandom::fill(&mut out).unwrap();\n    out\n}\n\n#[unsafe(no_mangle)]\npub unsafe extern \"Rust\" fn __getrandom_v03_custom(_dest: *mut u8, _len: usize) -> Result<(), getrandom::Error> {\n    Err(getrandom::Error::UNSUPPORTED)\n}\n",
    )
    .unwrap();

    let (meta, _crate_name, _version, wasm_name, package_id) =
        resolve_package_metadata(project.path()).unwrap();
    let compiled = compile_wasm(project.path(), &package_id, &wasm_name).unwrap();
    assert_eq!(compiled.target, GETRANDOM_TARGET);
    let expected = locate_wasm_binary(&meta, GETRANDOM_TARGET, &wasm_name).unwrap();
    assert_eq!(compiled.path, expected);
    assert!(compiled.path.is_file());
}

#[test]
fn build_config_rustflags_reach_path_dependency_with_getrandom_backend() {
    if !rust_target_is_installed(GETRANDOM_TARGET) {
        eprintln!(
            "skipping [build].rustflags dependency build falsifier: {GETRANDOM_TARGET} target is not installed"
        );
        return;
    }

    let project = tempfile::tempdir().unwrap();
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(project.path().join("src")).unwrap();
    fs::create_dir_all(project.path().join("control-dep/src")).unwrap();
    fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname = \"build-config-getrandom\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\ncontrol-dep = { path = \"control-dep\" }\ngetrandom = \"0.4\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("control-dep/Cargo.toml"),
        "[package]\nname = \"control-dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("control-dep/src/lib.rs"),
        "#[cfg(not(caller_cfg))]\ncompile_error!(\"[build].rustflags were dropped before this dependency\");\n\npub fn assert_cfg() {}\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\nrustflags = [\"--check-cfg=cfg(caller_cfg)\", \"--cfg=caller_cfg\"]\n",
    )
    .unwrap();
    fs::write(
        project.path().join("src/lib.rs"),
        "pub fn random() -> [u8; 1] {\n    control_dep::assert_cfg();\n    let mut out = [0; 1];\n    getrandom::fill(&mut out).unwrap();\n    out\n}\n\n#[unsafe(no_mangle)]\npub unsafe extern \"Rust\" fn __getrandom_v03_custom(_dest: *mut u8, _len: usize) -> Result<(), getrandom::Error> {\n    Err(getrandom::Error::UNSUPPORTED)\n}\n",
    )
    .unwrap();

    let (config_flags, has_matching_target_rustflags) =
        cargo_config_rustflags_for_target_with_home(project.path(), None, GETRANDOM_TARGET)
            .unwrap();

    let (meta, _crate_name, _version, wasm_name, package_id) =
        resolve_package_metadata(project.path()).unwrap();
    let compiled = compile_wasm_with_target(
        project.path(),
        &package_id,
        &wasm_name,
        GETRANDOM_TARGET.to_owned(),
        &config_flags,
        has_matching_target_rustflags,
        &RustflagsEnvironment::default(),
    )
    .unwrap();
    assert_eq!(
        config_flags,
        vec![
            "--check-cfg=cfg(caller_cfg)".to_owned(),
            "--cfg=caller_cfg".to_owned(),
        ]
    );
    assert!(!has_matching_target_rustflags);
    assert_eq!(compiled.target, GETRANDOM_TARGET);
    let expected = locate_wasm_binary(&meta, GETRANDOM_TARGET, &wasm_name).unwrap();
    assert_eq!(compiled.path, expected);
    assert!(compiled.path.is_file());
}

#[test]
fn included_config_rustflags_precede_including_config() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(
        project.path().join(".cargo/included.toml"),
        "[build]\nrustflags = [\"--cfg=included\"]\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "include = [\"included.toml\"]\n\n[build]\nrustflags = [\"--cfg=includer\"]\n",
    )
    .unwrap();

    let (flags, has_matching_target_rustflags) = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap();
    assert_eq!(
        flags,
        vec!["--cfg=included".to_owned(), "--cfg=includer".to_owned()]
    );
    assert!(!has_matching_target_rustflags);
}

#[test]
fn nested_included_configs_follow_include_order() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(
        project.path().join(".cargo/first.toml"),
        "include = [\"second.toml\"]\n\n[build]\nrustflags = [\"--cfg=first\"]\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/second.toml"),
        "[build]\nrustflags = [\"--cfg=second\"]\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "include = [\"first.toml\"]\n\n[build]\nrustflags = [\"--cfg=root\"]\n",
    )
    .unwrap();

    let (flags, _) = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap();
    assert_eq!(
        flags,
        vec![
            "--cfg=second".to_owned(),
            "--cfg=first".to_owned(),
            "--cfg=root".to_owned(),
        ]
    );
}

#[test]
fn self_including_cargo_config_fails_closed() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "include = [\"config.toml\"]\n",
    )
    .unwrap();

    let error = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap_err();
    assert!(error.to_string().contains("include cycle"));
}

#[test]
fn required_cargo_config_include_missing_fails() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "include = [\"missing.toml\"]\n",
    )
    .unwrap();

    let error = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not exist"));
}

#[test]
fn optional_missing_cargo_config_include_is_allowed() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "include = [{ path = \"missing.toml\", optional = true }]\n\n[build]\nrustflags = [\"--cfg=root\"]\n",
    )
    .unwrap();

    let (flags, _) = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap();
    assert_eq!(flags, vec!["--cfg=root".to_owned()]);
}

#[test]
fn dotted_relative_cargo_config_includes_are_supported() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo/sub")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(
        project.path().join(".cargo/included.toml"),
        "[build]\nrustflags = [\"--cfg=included\"]\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "include = [\"./sub/../included.toml\"]\n\n[build]\nrustflags = [\"--cfg=includer\"]\n",
    )
    .unwrap();

    let (flags, _) = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap();
    assert_eq!(
        flags,
        vec!["--cfg=included".to_owned(), "--cfg=includer".to_owned()]
    );
}

#[test]
fn absolute_cargo_config_includes_are_supported() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    let included = project.path().join(".cargo/included.toml");
    fs::write(&included, "[build]\nrustflags = [\"--cfg=included\"]\n").unwrap();
    let absolute_include = included.canonicalize().unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        format!(
            "include = [{}]\n\n[build]\nrustflags = [\"--cfg=includer\"]\n",
            toml_edit::Value::from(absolute_include.to_string_lossy().as_ref())
        ),
    )
    .unwrap();

    let (flags, _) = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap();
    assert_eq!(
        flags,
        vec!["--cfg=included".to_owned(), "--cfg=includer".to_owned()]
    );
}

#[test]
fn mutually_including_cargo_configs_fail_closed() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(
        project.path().join(".cargo/first.toml"),
        "include = [\"second.toml\"]\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/second.toml"),
        "include = [\"config.toml\"]\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "include = [\"first.toml\"]\n",
    )
    .unwrap();

    let error = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap_err();
    assert!(error.to_string().contains("include cycle"));
}

#[test]
fn malformed_cargo_includes_fail() {
    let project = tempfile::tempdir().unwrap();
    let cargo_home = project.path().join("cargo-home");
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();
    fs::write(project.path().join(".cargo/config.toml"), "include = [1]\n").unwrap();
    let error = cargo_config_rustflags_for_target_with_home(
        project.path(),
        Some(&cargo_home),
        GETRANDOM_TARGET,
    )
    .unwrap_err();
    assert!(error.to_string().contains("non-string or non-table"));
}

#[test]
fn include_only_rustflags_reach_path_dependency_with_getrandom_backend() {
    if !rust_target_is_installed(GETRANDOM_TARGET) {
        eprintln!(
            "skipping included rustflags dependency build falsifier: {GETRANDOM_TARGET} target is not installed"
        );
        return;
    }

    let project = tempfile::tempdir().unwrap();
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(project.path().join("src")).unwrap();
    fs::create_dir_all(project.path().join("control-dep/src")).unwrap();
    fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname = \"include-getrandom\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\ncontrol-dep = { path = \"control-dep\" }\ngetrandom = \"0.4\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("control-dep/Cargo.toml"),
        "[package]\nname = \"control-dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("control-dep/src/lib.rs"),
        "#[cfg(not(caller_cfg))]\ncompile_error!(\"included [build].rustflags were dropped before this dependency\");\n\npub fn assert_cfg() {}\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/included.toml"),
        "[build]\nrustflags = [\"--check-cfg=cfg(caller_cfg)\", \"--cfg=caller_cfg\"]\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "include = [\"included.toml\"]\n\n[build]\ntarget = \"wasm32-unknown-unknown\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("src/lib.rs"),
        "pub fn random() -> [u8; 1] {\n    control_dep::assert_cfg();\n    let mut out = [0; 1];\n    getrandom::fill(&mut out).unwrap();\n    out\n}\n\n#[unsafe(no_mangle)]\npub unsafe extern \"Rust\" fn __getrandom_v03_custom(_dest: *mut u8, _len: usize) -> Result<(), getrandom::Error> {\n    Err(getrandom::Error::UNSUPPORTED)\n}\n",
    )
    .unwrap();

    let (config_flags, has_matching_target_rustflags) =
        cargo_config_rustflags_for_target_with_home(project.path(), None, GETRANDOM_TARGET)
            .unwrap();

    let (meta, _crate_name, _version, wasm_name, package_id) =
        resolve_package_metadata(project.path()).unwrap();
    let compiled = compile_wasm_with_target(
        project.path(),
        &package_id,
        &wasm_name,
        GETRANDOM_TARGET.to_owned(),
        &config_flags,
        has_matching_target_rustflags,
        &RustflagsEnvironment::default(),
    )
    .unwrap();
    assert_eq!(
        config_flags,
        vec![
            "--check-cfg=cfg(caller_cfg)".to_owned(),
            "--cfg=caller_cfg".to_owned(),
        ]
    );
    assert!(!has_matching_target_rustflags);
    assert_eq!(compiled.target, GETRANDOM_TARGET);
    let expected = locate_wasm_binary(&meta, GETRANDOM_TARGET, &wasm_name).unwrap();
    assert_eq!(compiled.path, expected);
    assert!(compiled.path.is_file());
}

#[test]
fn build_env_and_getrandom_cfg_reach_dependency_without_target_flags() {
    if !rust_target_is_installed(GETRANDOM_TARGET) {
        eprintln!(
            "skipping CARGO_BUILD_RUSTFLAGS regression: {GETRANDOM_TARGET} target is not installed"
        );
        return;
    }

    let project = tempfile::tempdir().unwrap();
    fs::create_dir_all(project.path().join(".cargo")).unwrap();
    fs::create_dir_all(project.path().join("src")).unwrap();
    fs::create_dir_all(project.path().join("control-dep/src")).unwrap();
    fs::write(
        project.path().join("Cargo.toml"),
        "[package]\nname = \"build-env-getrandom\"\nversion = \"0.1.0\"\nedition = \"2024\"\n\n[lib]\ncrate-type = [\"cdylib\"]\n\n[dependencies]\ncontrol-dep = { path = \"control-dep\" }\ngetrandom = \"0.4\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("control-dep/Cargo.toml"),
        "[package]\nname = \"control-dep\"\nversion = \"0.1.0\"\nedition = \"2024\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("control-dep/src/lib.rs"),
        "#[cfg(not(caller_cfg))]\ncompile_error!(\"CARGO_BUILD_RUSTFLAGS did not reach this dependency\");\n\npub fn assert_cfg() {}\n",
    )
    .unwrap();
    fs::write(
        project.path().join(".cargo/config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
    )
    .unwrap();
    fs::write(
        project.path().join("src/lib.rs"),
        "pub fn random() -> [u8; 1] {\n    control_dep::assert_cfg();\n    let mut out = [0; 1];\n    getrandom::fill(&mut out).unwrap();\n    out\n}\n\n#[unsafe(no_mangle)]\npub unsafe extern \"Rust\" fn __getrandom_v03_custom(_dest: *mut u8, _len: usize) -> Result<(), getrandom::Error> {\n    Err(getrandom::Error::UNSUPPORTED)\n}\n",
    )
    .unwrap();

    assert!(
        !cargo_config_has_matching_target_rustflags_with_home(
            project.path(),
            None,
            GETRANDOM_TARGET,
        )
        .unwrap()
    );
    let (meta, _crate_name, _version, wasm_name, package_id) =
        resolve_package_metadata(project.path()).unwrap();
    let compiled = compile_wasm_with_target(
        project.path(),
        &package_id,
        &wasm_name,
        GETRANDOM_TARGET.to_owned(),
        &[],
        false,
        &RustflagsEnvironment {
            build: Some("--check-cfg=cfg(caller_cfg) --cfg=caller_cfg".to_owned()),
            ..RustflagsEnvironment::default()
        },
    )
    .unwrap();
    assert_eq!(compiled.target, GETRANDOM_TARGET);
    let expected = locate_wasm_binary(&meta, GETRANDOM_TARGET, &wasm_name).unwrap();
    assert_eq!(compiled.path, expected);
    assert!(compiled.path.is_file());
}

#[test]
fn exact_target_rustflags_entry_is_detected_for_getrandom_merge() {
    let project = tempfile::tempdir().unwrap();
    let cargo_dir = project.path().join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    fs::write(
        cargo_dir.join("config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n\n[target.wasm32-unknown-unknown]\nrustflags = []\n",
    )
    .unwrap();

    assert!(
        cargo_config_has_matching_target_rustflags_with_home(
            project.path(),
            None,
            GETRANDOM_TARGET,
        )
        .unwrap()
    );
}

#[test]
fn nonmatching_target_cfg_is_not_detected_for_getrandom_merge() {
    let project = tempfile::tempdir().unwrap();
    let cargo_dir = project.path().join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    fs::write(
        cargo_dir.join("config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n\n[target.'cfg(target_os = \"linux\")']\nrustflags = [\"--cfg=linux_only\"]\n",
    )
    .unwrap();

    assert!(
        !cargo_config_has_matching_target_rustflags_with_home(
            project.path(),
            None,
            GETRANDOM_TARGET,
        )
        .unwrap()
    );
}

fn rust_target_is_installed(target: &str) -> bool {
    let Ok(output) = std::process::Command::new("rustc")
        .args(["--print", "target-libdir", "--target", target])
        .output()
    else {
        return false;
    };
    if !output.status.success() {
        return false;
    }
    let Ok(libdir) = std::str::from_utf8(&output.stdout) else {
        return false;
    };
    fs::read_dir(libdir.trim()).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().starts_with("libcore-"))
    })
}

#[test]
fn unavailable_target_is_detected_without_installing_toolchains() {
    assert!(!rust_target_is_installed(
        "astrid-test-target-that-does-not-exist"
    ));
}

#[test]
fn local_config_target_and_rustflags_are_read() {
    let dir = tempfile::tempdir().unwrap();
    let cargo_dir = dir.path().join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    fs::write(
        cargo_dir.join("config.toml"),
        "[build]\n\
             target = \"wasm32-unknown-unknown\"\n\n\
             [target.wasm32-unknown-unknown]\n\
             rustflags = [\"--cfg=getrandom_backend=\\\"custom\\\"\"]\n",
    )
    .unwrap();

    let (target, flags) = cargo_config_target_and_rustflags_with_home(dir.path(), None).unwrap();
    assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
    assert_eq!(flags, vec![GETRANDOM_CUSTOM_CFG.to_owned()]);
}

#[test]
fn string_form_rustflags_are_preserved() {
    let dir = tempfile::tempdir().unwrap();
    let cargo_dir = dir.path().join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    fs::write(
        cargo_dir.join("config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\nrustflags = \"-C opt-level=3\"\n",
    )
    .unwrap();

    let (target, flags) = cargo_config_target_and_rustflags_with_home(dir.path(), None).unwrap();
    assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
    assert_eq!(flags, vec!["-C".to_owned(), "opt-level=3".to_owned()]);
}

#[test]
fn ancestor_and_cargo_home_config_hierarchy_is_preserved() {
    let root = tempfile::tempdir().unwrap();
    let cargo_home = root.path().join("cargo-home");
    let ancestor = root.path().join("ancestor");
    let capsule = ancestor.join("workspace").join("capsule");
    fs::create_dir_all(capsule.join(".cargo")).unwrap();
    fs::create_dir_all(ancestor.join(".cargo")).unwrap();
    fs::create_dir_all(&cargo_home).unwrap();

    fs::write(
        cargo_home.join("config.toml"),
        "[build]\ntarget = \"wasm32-wasip2\"\nrustflags = [\"--cfg=from-cargo-home\"]\n",
    )
    .unwrap();
    fs::write(
        ancestor.join(".cargo/config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n\n[target.wasm32-unknown-unknown]\nrustflags = [\"--cfg=from-ancestor\"]\n",
    )
    .unwrap();

    let (target, flags) =
        cargo_config_target_and_rustflags_with_home(&capsule, Some(&cargo_home)).unwrap();
    assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
    assert_eq!(flags, vec!["--cfg=from-ancestor".to_owned()]);

    fs::remove_file(ancestor.join(".cargo/config.toml")).unwrap();
    let (target, flags) =
        cargo_config_target_and_rustflags_with_home(&capsule, Some(&cargo_home)).unwrap();
    assert_eq!(target.as_deref(), Some("wasm32-wasip2"));
    assert_eq!(flags, vec!["--cfg=from-cargo-home".to_owned()]);
}

#[test]
fn nearest_config_overrides_parent_without_erasing_unrelated_values() {
    let root = tempfile::tempdir().unwrap();
    let ancestor = root.path().join("ancestor");
    let capsule = ancestor.join("capsule");
    fs::create_dir_all(capsule.join(".cargo")).unwrap();
    fs::create_dir_all(ancestor.join(".cargo")).unwrap();
    fs::write(
        ancestor.join(".cargo/config.toml"),
        "[build]\ntarget = \"wasm32-wasip2\"\nrustflags = [\"--cfg=parent\"]\n",
    )
    .unwrap();
    fs::write(
        capsule.join(".cargo/config.toml"),
        "[target.wasm32-unknown-unknown]\nrustflags = [\"--cfg=child-target\"]\n",
    )
    .unwrap();

    let (target, flags) = cargo_config_target_and_rustflags_with_home(&capsule, None).unwrap();
    assert_eq!(target.as_deref(), Some("wasm32-wasip2"));
    assert_eq!(flags, vec!["--cfg=parent".to_owned()]);
}

#[test]
fn array_rustflags_are_joined_across_config_hierarchy() {
    let root = tempfile::tempdir().unwrap();
    let ancestor = root.path().join("ancestor");
    let capsule = ancestor.join("capsule");
    fs::create_dir_all(capsule.join(".cargo")).unwrap();
    fs::create_dir_all(ancestor.join(".cargo")).unwrap();
    fs::write(
        ancestor.join(".cargo/config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n\n[target.wasm32-unknown-unknown]\nrustflags = [\"--cfg=parent\"]\n",
    )
    .unwrap();
    fs::write(
        capsule.join(".cargo/config.toml"),
        "[target.wasm32-unknown-unknown]\nrustflags = [\"--cfg=child\"]\n",
    )
    .unwrap();

    let (target, flags) = cargo_config_target_and_rustflags_with_home(&capsule, None).unwrap();
    assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
    assert_eq!(
        flags,
        vec!["--cfg=parent".to_owned(), "--cfg=child".to_owned()]
    );
}

#[test]
fn extensionless_cargo_config_wins_when_both_names_exist() {
    let dir = tempfile::tempdir().unwrap();
    let cargo_dir = dir.path().join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    fs::write(
        cargo_dir.join("config.toml"),
        "[build]\ntarget = \"wasm32-wasip2\"\n",
    )
    .unwrap();
    fs::write(
        cargo_dir.join("config"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
    )
    .unwrap();

    let (target, _) = cargo_config_target_and_rustflags_with_home(dir.path(), None).unwrap();
    assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
}

#[test]
fn environment_target_selects_matching_config_rustflags() {
    let dir = tempfile::tempdir().unwrap();
    let cargo_dir = dir.path().join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    fs::write(
        cargo_dir.join("config.toml"),
        "[build]\ntarget = \"wasm32-wasip2\"\nrustflags = [\"--cfg=build\"]\n\n[target.wasm32-unknown-unknown]\nrustflags = [\"--cfg=target\"]\n",
    )
    .unwrap();

    let (config_target, _) = cargo_config_target_and_rustflags_with_home(dir.path(), None).unwrap();
    assert_eq!(config_target.as_deref(), Some("wasm32-wasip2"));
    let (_, flags) = cargo_config_target_and_rustflags_for_target_with_home(
        dir.path(),
        None,
        Some(GETRANDOM_TARGET),
    )
    .unwrap();
    assert_eq!(flags, vec!["--cfg=target".to_owned()]);
}

#[test]
fn relative_cargo_home_is_resolved_from_child_current_dir() {
    let root = tempfile::tempdir().unwrap();
    let capsule = root.path().join("workspace").join("capsule");
    let relative_home = Path::new("relative-cargo-home");
    fs::create_dir_all(capsule.join(".cargo")).unwrap();
    let resolved_home = resolve_cargo_home(&capsule, relative_home.to_path_buf());
    fs::create_dir_all(&resolved_home).unwrap();
    fs::write(
        resolved_home.join("config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
    )
    .unwrap();

    assert_eq!(
        resolve_cargo_home(&capsule, relative_home.to_path_buf()),
        capsule.join(relative_home)
    );
    let (target, _) =
        cargo_config_target_and_rustflags_with_home(&capsule, Some(relative_home)).unwrap();
    assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
}

#[test]
fn relative_cargo_home_env_is_resolved_from_relative_project_dir() {
    const MODE_ENV: &str = "ASTRID_RELATIVE_CARGO_HOME_TEST";
    const TEST_NAME: &str = "relative_cargo_home_env_is_resolved_from_relative_project_dir";

    if std::env::var_os(MODE_ENV).is_some() {
        let (target, _) = cargo_config_target_and_rustflags(Path::new("project")).unwrap();
        assert_eq!(target.as_deref(), Some(GETRANDOM_TARGET));
        return;
    }

    let root = tempfile::tempdir().unwrap();
    let relative_home = Path::new("relative-cargo-home");
    fs::create_dir_all(root.path().join("project").join(relative_home)).unwrap();
    fs::write(
        root.path()
            .join("project")
            .join(relative_home)
            .join("config.toml"),
        "[build]\ntarget = \"wasm32-unknown-unknown\"\n",
    )
    .unwrap();

    // Environment state is process-global, so execute the normal env-backed
    // loader in a child harness whose working directory is the project parent.
    let status = Command::new(std::env::current_exe().unwrap())
        .current_dir(root.path())
        .env("CARGO_HOME", relative_home)
        .env(MODE_ENV, "1")
        .args(["--exact", TEST_NAME, "--nocapture"])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(!root.path().join("project/project").exists());
}

#[test]
fn multi_target_config_does_not_guess_a_single_target() {
    let project = tempfile::tempdir().unwrap();
    let cargo_dir = project.path().join(".cargo");
    fs::create_dir_all(&cargo_dir).unwrap();
    fs::write(
        cargo_dir.join("config.toml"),
        "[build]\ntarget = [\"wasm32-unknown-unknown\", \"wasm32-wasip2\"]\n",
    )
    .unwrap();

    let (target, flags) =
        cargo_config_target_and_rustflags_with_home(project.path(), None).unwrap();
    assert_eq!(target, None);
    assert!(flags.is_empty());
}

#[test]
fn missing_config_yields_no_target_or_flags() {
    let dir = tempfile::tempdir().unwrap();
    let (target, flags) = cargo_config_target_and_rustflags_with_home(dir.path(), None).unwrap();
    assert_eq!(target, None);
    assert!(flags.is_empty());
}

#[test]
fn environment_target_overrides_capsule_config_target() {
    let target = resolve_build_target(
        Some(GETRANDOM_TARGET.to_owned()),
        Some("wasm32-wasip2".to_owned()),
    )
    .unwrap();
    assert_eq!(target, "wasm32-wasip2");
}

#[test]
fn missing_target_is_rejected_instead_of_building_host_cdylib() {
    let error = resolve_build_target(None, None).unwrap_err();
    assert!(error.to_string().contains("No Cargo build target selected"));

    let error = resolve_build_target(Some(String::new()), None).unwrap_err();
    assert!(error.to_string().contains("No Cargo build target selected"));

    let error = resolve_build_target(None, Some(" ".to_owned())).unwrap_err();
    assert!(error.to_string().contains("No Cargo build target selected"));
}

fn metadata_for(capsule_dir: &Path, target_directory: &Path) -> cargo_metadata::Metadata {
    serde_json::from_value(json!({
        "packages": [],
        "workspace_members": [],
        "resolve": null,
        "workspace_root": capsule_dir,
        "target_directory": target_directory,
        "version": 15,
    }))
    .unwrap()
}

fn create_artifact(target_root: &Path, target: &str, wasm_name: &str) -> anyhow::Result<PathBuf> {
    let artifact = target_root
        .join(target)
        .join("release")
        .join(format!("{wasm_name}.wasm"));
    fs::create_dir_all(artifact.parent().unwrap())?;
    fs::write(&artifact, b"\0asm")?;
    Ok(artifact)
}

#[test]
fn locates_exact_artifact_from_external_target_root() {
    let capsule = tempfile::tempdir().unwrap();
    let external_root = tempfile::tempdir().unwrap();
    let expected = create_artifact(external_root.path(), GETRANDOM_TARGET, "capsule_cli").unwrap();

    create_artifact(
        &capsule.path().join("target"),
        GETRANDOM_TARGET,
        "capsule_cli",
    )
    .unwrap();
    create_artifact(
        &capsule.path().join("workspace-target"),
        GETRANDOM_TARGET,
        "capsule_cli",
    )
    .unwrap();

    let meta = metadata_for(capsule.path(), external_root.path());
    let actual = locate_wasm_binary(&meta, GETRANDOM_TARGET, "capsule_cli").unwrap();

    assert_eq!(actual, expected);
}

#[test]
fn selects_exact_cross_target_artifact() {
    let capsule = tempfile::tempdir().unwrap();
    let target_root = tempfile::tempdir().unwrap();
    create_artifact(target_root.path(), GETRANDOM_TARGET, "capsule").unwrap();
    let expected = create_artifact(target_root.path(), "wasm32-wasip2", "capsule").unwrap();

    let meta = metadata_for(capsule.path(), target_root.path());
    let actual = locate_wasm_binary(&meta, "wasm32-wasip2", "capsule").unwrap();

    assert_eq!(actual, expected);
}

#[test]
fn missing_artifact_is_rejected_without_fallback() {
    let capsule = tempfile::tempdir().unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let meta = metadata_for(capsule.path(), target_root.path());

    let error = locate_wasm_binary(&meta, GETRANDOM_TARGET, "missing_capsule").unwrap_err();

    assert!(error.to_string().contains("Could not locate compiled WASM"));
}

#[test]
fn directory_artifact_is_rejected() {
    let capsule = tempfile::tempdir().unwrap();
    let target_root = tempfile::tempdir().unwrap();
    fs::create_dir_all(
        target_root
            .path()
            .join(GETRANDOM_TARGET)
            .join("release")
            .join("capsule.wasm"),
    )
    .unwrap();
    let meta = metadata_for(capsule.path(), target_root.path());

    let error = locate_wasm_binary(&meta, GETRANDOM_TARGET, "capsule").unwrap_err();

    assert!(error.to_string().contains("not a regular file"));
}

#[cfg(unix)]
#[test]
fn symlinked_artifact_is_rejected() {
    let capsule = tempfile::tempdir().unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let real_artifact = create_artifact(target_root.path(), GETRANDOM_TARGET, "capsule").unwrap();
    let release = target_root.path().join(GETRANDOM_TARGET).join("release");
    let symlink = release.join("symlink.wasm");
    std::os::unix::fs::symlink(real_artifact, &symlink).unwrap();
    let meta = metadata_for(capsule.path(), target_root.path());

    let error = locate_wasm_binary(&meta, GETRANDOM_TARGET, "symlink").unwrap_err();

    assert!(error.to_string().contains("is a symlink"));
}

#[cfg(unix)]
#[test]
fn artifact_escaping_target_root_is_rejected() {
    let capsule = tempfile::tempdir().unwrap();
    let target_root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    create_artifact(outside.path(), GETRANDOM_TARGET, "escaped").unwrap();
    fs::create_dir_all(target_root.path().join(GETRANDOM_TARGET)).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join(GETRANDOM_TARGET).join("release"),
        target_root.path().join(GETRANDOM_TARGET).join("release"),
    )
    .unwrap();
    let meta = metadata_for(capsule.path(), target_root.path());

    let error = locate_wasm_binary(&meta, GETRANDOM_TARGET, "escaped").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("escapes configured target directory")
    );
}

#[test]
fn rejects_escaping_artifact_name() {
    let error = validate_wasm_output_name("../stale.wasm").unwrap_err();
    assert!(error.to_string().contains("Unsafe WASM artifact name"));
}

#[test]
fn uses_explicit_cdylib_output_name() {
    let output_name = resolve_wasm_output_name_from_targets(["custom_capsule".to_owned()]).unwrap();
    assert_eq!(output_name, "custom_capsule");
}

#[test]
fn rejects_ambiguous_cdylib_outputs() {
    let error = resolve_wasm_output_name_from_targets(["first".to_owned(), "second".to_owned()])
        .unwrap_err();

    assert!(error.to_string().contains("ambiguous WASM artifact"));
}

#[test]
fn rejects_missing_cdylib_output() {
    let error = resolve_wasm_output_name_from_targets(std::iter::empty()).unwrap_err();

    assert!(error.to_string().contains("no cdylib target"));
}

#[cfg(unix)]
#[test]
fn rejects_target_path_escaping_target_root() {
    let capsule = tempfile::tempdir().unwrap();
    let parent = tempfile::tempdir().unwrap();
    let target_root = parent.path().join("target");
    fs::create_dir_all(&target_root).unwrap();
    create_artifact(parent.path(), "", "escaped").unwrap();

    let meta = metadata_for(capsule.path(), &target_root);
    let error = locate_wasm_binary(&meta, "../", "escaped").unwrap_err();

    assert!(
        error
            .to_string()
            .contains("escapes configured target directory")
    );
}

#[test]
fn existing_manifest_is_bound_to_renamed_cdylib_in_archive() {
    let source = tempfile::tempdir().unwrap();
    let wasm_path = source.path().join("renamed_capsule.wasm");
    fs::write(&wasm_path, b"\0asm\x01\0\0\0").unwrap();
    fs::write(
        source.path().join("Capsule.toml"),
        "[package]\nname = \"original-package\"\nversion = \"1.0.0\"\n\n[[component]]\nid = \"main\"\nfile = \"original_package.wasm\"\ntype = \"executable\"\n\n[capabilities]\nnet_connect = false\n",
    )
    .unwrap();

    let manifest = build_manifest_content(
        source.path(),
        &wasm_path,
        "original-package",
        "1.0.0",
        "renamed_capsule",
    )
    .unwrap();
    let parsed = manifest.parse::<toml_edit::DocumentMut>().unwrap();
    let file = parsed
        .get("component")
        .and_then(toml_edit::Item::as_array_of_tables)
        .and_then(|components| components.get(0))
        .and_then(|component| component.get("file"))
        .and_then(toml_edit::Item::as_str);
    assert_eq!(file, Some("renamed_capsule.wasm"));
    assert!(manifest.contains("net_connect = false"));

    let archive_path = source.path().join("renamed.capsule");
    pack_capsule_archive(
        &archive_path,
        &manifest,
        Some(&wasm_path),
        source.path(),
        &[],
        None,
    )
    .unwrap();
    let decoder = flate2::read::GzDecoder::new(File::open(&archive_path).unwrap());
    let mut archive = tar::Archive::new(decoder);
    let entries = archive
        .entries()
        .unwrap()
        .map(|entry| entry.unwrap().path().unwrap().into_owned())
        .collect::<Vec<_>>();
    assert!(entries.contains(&PathBuf::from("renamed_capsule.wasm")));
    assert!(entries.contains(&PathBuf::from(file.unwrap())));
}

#[test]
fn existing_manifest_with_multiple_components_fails_closed() {
    let source = tempfile::tempdir().unwrap();
    let wasm_path = source.path().join("capsule.wasm");
    fs::write(&wasm_path, b"\0asm\x01\0\0\0").unwrap();
    fs::write(
        source.path().join("Capsule.toml"),
        "[package]\nname = \"capsule\"\nversion = \"1.0.0\"\n\n[[component]]\nfile = \"one.wasm\"\n\n[[component]]\nfile = \"two.wasm\"\n",
    )
    .unwrap();

    let error = build_manifest_content(source.path(), &wasm_path, "capsule", "1.0.0", "capsule")
        .unwrap_err();
    assert!(error.to_string().contains("exactly one cdylib"));
}
