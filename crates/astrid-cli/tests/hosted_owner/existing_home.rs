//! Ordinary boot must not make later explicit ownership provisioning impossible.

use super::{Runtime, configure, enrolled_lifecycle, signing_keys, text};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn explicit_enrollment_after_ordinary_boot_preserves_execution_identity() {
    let mut runtime = Runtime::new();
    runtime.start();
    assert_eq!(
        runtime.json(&["owner", "inspect"])["enrollment"],
        "unenrolled"
    );
    assert!(
        !runtime
            .command(&["agent", "create", "before-owner", "-y"])
            .status
            .success()
    );
    let key_path = astrid_core::dirs::AstridHome::from_path(&runtime.home)
        .keys_dir()
        .join("default.key");
    let original_key = std::fs::read(&key_path).unwrap();
    runtime.stop();
    let (owner, deployment, owner_path, deployment_path) = signing_keys(&runtime);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    configure(
        &runtime,
        &serde_json::json!({
            "deployment_key": deployment.verifying_key().to_bytes(),
            "generation": 1,
            "expires_at": now + 3600,
        }),
    );
    runtime.start();
    assert_eq!(std::fs::read(&key_path).unwrap(), original_key);
    let genesis = runtime.json(&[
        "owner",
        "prepare",
        "--owner-public-key",
        &hex::encode(owner.verifying_key().to_bytes()),
    ]);
    let genesis_path = runtime.write("existing-genesis.json", &genesis);
    let challenge = runtime.json(&[
        "owner",
        "challenge",
        "--genesis",
        text(&genesis_path),
        "--expires-at",
        &(now + 1800).to_string(),
    ]);
    let challenge_path = runtime.write("existing-challenge.json", &challenge);
    let owner_signed = runtime.json(&[
        "owner",
        "sign-owner",
        "--challenge",
        text(&challenge_path),
        "--signing-key",
        text(&owner_path),
    ]);
    let owner_signed_path = runtime.write("existing-owner-signed.json", &owner_signed);
    let signed = runtime.json(&[
        "owner",
        "authorize",
        "--envelope",
        text(&owner_signed_path),
        "--signing-key",
        text(&deployment_path),
    ]);
    let signed_path = runtime.write("existing-signed.json", &signed);
    assert_eq!(
        runtime.json(&["owner", "provision", "--envelope", text(&signed_path)])["status"],
        "enrolled"
    );
    enrolled_lifecycle(&runtime);
    runtime.stop();
    runtime.start();
    assert_eq!(
        runtime.json(&["owner", "inspect"])["enrollment"],
        "enrolled"
    );
    assert_eq!(std::fs::read(&key_path).unwrap(), original_key);
    enrolled_lifecycle(&runtime);
    runtime.stop();
}
