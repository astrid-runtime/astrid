//! Signed enrollment for capsule tests, never a production trust adapter.

use astrid_core::{FirstOwnerClaim, FleetIdentity, UserIdentity};
use astrid_crypto::KeyPair;

pub(crate) async fn enroll_fixture_owner(
    ownership: &astrid_storage::OwnershipStore,
    owner: &UserIdentity,
    fleet: &FleetIdentity,
    principal_uid: astrid_core::PrincipalUid,
    signing_key: &KeyPair,
) {
    let machine_context = [21; 32];
    let boot_context = [22; 32];
    let kernel_identity = [23; 32];
    let system_generation = [24; 32];
    let mut nonce: [u8; 32] = std::array::from_fn(|_| 0_u8);
    getrandom::fill(&mut nonce).expect("fixture nonce");
    let unsigned = FirstOwnerClaim::from_parts(
        machine_context,
        boot_context,
        kernel_identity,
        system_generation,
        owner.uid,
        fleet.uid,
        principal_uid,
        *signing_key.public_key_bytes(),
        nonce,
        1,
        [0; 64],
    )
    .expect("unsigned fixture claim");
    let claim = FirstOwnerClaim::from_parts(
        machine_context,
        boot_context,
        kernel_identity,
        system_generation,
        owner.uid,
        fleet.uid,
        principal_uid,
        *signing_key.public_key_bytes(),
        nonce,
        1,
        *signing_key.sign(&unsigned.canonical_message()).as_bytes(),
    )
    .expect("signed fixture claim");
    assert_eq!(*claim.nonce(), nonce);
    ownership
        .begin_first_owner(claim)
        .await
        .expect("begin fixture enrollment");
    ownership
        .commit_first_owner(claim, owner.clone(), fleet.clone())
        .await
        .expect("commit fixture enrollment");
}
