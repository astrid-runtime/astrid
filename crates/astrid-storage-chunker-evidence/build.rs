use std::env;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=RUSTC");

    let rustc = env::var("RUSTC").unwrap_or_else(|_| "rustc".to_owned());
    let output = Command::new(&rustc)
        .arg("--version")
        .output()
        .expect("run the Rust compiler to record evidence provenance");
    assert!(
        output.status.success(),
        "Rust compiler version query failed"
    );
    let version = String::from_utf8(output.stdout)
        .expect("Rust compiler version is UTF-8")
        .trim()
        .to_owned();

    emit("ASTRID_EVIDENCE_RUSTC", &version);
    emit(
        "ASTRID_EVIDENCE_HOST",
        &env::var("HOST").expect("Cargo provides HOST to build scripts"),
    );
    emit(
        "ASTRID_EVIDENCE_TARGET",
        &env::var("TARGET").expect("Cargo provides TARGET to build scripts"),
    );
    emit(
        "ASTRID_EVIDENCE_PROFILE",
        &env::var("PROFILE").expect("Cargo provides PROFILE to build scripts"),
    );
}

fn emit(name: &str, value: &str) {
    assert!(
        !value.contains('\r') && !value.contains('\n'),
        "build provenance values must be single-line"
    );
    println!("cargo:rustc-env={name}={value}");
}
