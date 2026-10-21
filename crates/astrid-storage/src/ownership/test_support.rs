//! Bootstrap fixtures through the real signed ceremony without extra identities.

use astrid_core::{FirstOwnerClaim, FleetIdentity, PrincipalUid, UserIdentity};
use ed25519_dalek::{Signer, SigningKey};

use super::OwnershipStore;

pub(super) fn public_key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

pub(super) async fn enroll(
    store: &OwnershipStore,
    principal: PrincipalUid,
    user: &UserIdentity,
    fleet: &FleetIdentity,
    seed: u8,
) {
    let signing_key = SigningKey::from_bytes(&[seed; 32]);
    assert_eq!(
        user.genesis.initial_public_key,
        signing_key.verifying_key().to_bytes()
    );
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).unwrap();
    let unsigned = FirstOwnerClaim::from_parts(
        [41; 32],
        [42; 32],
        [43; 32],
        [44; 32],
        user.uid,
        fleet.uid,
        principal,
        user.genesis.initial_public_key,
        nonce,
        1,
        [0; 64],
    )
    .unwrap();
    let claim = FirstOwnerClaim::from_parts(
        *unsigned.machine_context(),
        *unsigned.boot_context(),
        *unsigned.kernel_identity(),
        *unsigned.system_generation(),
        user.uid,
        fleet.uid,
        principal,
        user.genesis.initial_public_key,
        nonce,
        1,
        signing_key.sign(&unsigned.canonical_message()).to_bytes(),
    )
    .unwrap();
    store.begin_first_owner(claim).await.unwrap();
    store
        .commit_first_owner(claim, user.clone(), fleet.clone())
        .await
        .unwrap();
}
