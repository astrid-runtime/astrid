//! Cancellation must invalidate signed evidence across a real daemon restart.

use super::{Runtime, configure, signing_keys, text};
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn cancelled_signed_challenge_cannot_enroll_after_restart() {
    let mut runtime = Runtime::new();
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
    let genesis = runtime.json(&[
        "owner",
        "prepare",
        "--owner-public-key",
        &hex::encode(owner.verifying_key().to_bytes()),
    ]);
    let genesis_path = runtime.write("genesis.json", &genesis);
    let challenge = runtime.json(&[
        "owner",
        "challenge",
        "--genesis",
        text(&genesis_path),
        "--expires-at",
        &(now + 1800).to_string(),
    ]);
    let challenge_path = runtime.write("challenge.json", &challenge);
    let owner_signed = runtime.json(&[
        "owner",
        "sign-owner",
        "--challenge",
        text(&challenge_path),
        "--signing-key",
        text(&owner_path),
    ]);
    let owner_signed_path = runtime.write("owner-signed.json", &owner_signed);
    let signed = runtime.json(&[
        "owner",
        "authorize",
        "--envelope",
        text(&owner_signed_path),
        "--signing-key",
        text(&deployment_path),
    ]);
    let signed_path = runtime.write("signed.json", &signed);
    assert_eq!(runtime.json(&["owner", "cancel"])["status"], "cancelled");
    runtime.stop();
    runtime.start();
    let before = runtime.json(&["owner", "inspect"]);
    assert_eq!(before["enrollment"], "unenrolled");
    assert!(before["completion"].is_null());
    assert!(
        !runtime
            .command(&["owner", "provision", "--envelope", text(&signed_path)])
            .status
            .success()
    );
    assert_eq!(runtime.json(&["owner", "inspect"]), before);
    assert!(
        !runtime
            .command(&["agent", "create", "cancelled-owner", "-y"])
            .status
            .success()
    );
    runtime.stop();
}
