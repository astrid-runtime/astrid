use astrid_core::{FirstOwnerClaim, FleetIdentity, PrincipalIdentity, UserGenesis, UserIdentity};
use astrid_crypto::KeyPair;
use astrid_storage::{OwnershipStore, PrincipalDirectory};

use crate::first_owner::{self, AuthenticatedBootContext, BootContextProvenance};

pub(crate) async fn enroll_test_first_owner(
    store: &OwnershipStore,
    principal_directory: &PrincipalDirectory,
    root_user: &astrid_core::AstridUserId,
    root_principal_identity: &PrincipalIdentity,
    signing_key: &KeyPair,
) {
    // Test fixtures that exercise mutating storage APIs must represent an
    // admitted runtime. Use the same signed claim/context transition as the
    // real first-owner path; never mint a test-only authority flag.
    assert_eq!(
        *signing_key.public_key_bytes(),
        root_principal_identity.genesis.initial_public_key,
        "test first-owner: signing key must match the admitted principal key"
    );
    let user = UserIdentity::from_genesis(UserGenesis::from_parts(
        root_user.id,
        root_user.created_at,
        *signing_key.public_key_bytes(),
    ))
    .expect("test first-owner: user identity");
    let fleet = FleetIdentity::from_genesis(astrid_core::FleetGenesis::from_parts(
        root_user.id,
        root_user.created_at,
        user.uid,
    ))
    .expect("test first-owner: fleet identity");
    let principal_uid = principal_directory
        .uid_for(&astrid_core::PrincipalId::default())
        .expect("test first-owner: default principal");
    let machine_context = [11; 32];
    let boot_context = [12; 32];
    let kernel_identity = [13; 32];
    let system_generation = [14; 32];
    let mut nonce: [u8; 32] = std::array::from_fn(|_| 0_u8);
    getrandom::fill(&mut nonce).expect("test first-owner: nonce");
    let unsigned = FirstOwnerClaim::from_parts(
        machine_context,
        boot_context,
        kernel_identity,
        system_generation,
        user.uid,
        fleet.uid,
        principal_uid,
        *signing_key.public_key_bytes(),
        nonce,
        1,
        [0; 64],
    )
    .expect("test first-owner: unsigned claim");
    let claim = FirstOwnerClaim::from_parts(
        machine_context,
        boot_context,
        kernel_identity,
        system_generation,
        user.uid,
        fleet.uid,
        principal_uid,
        *signing_key.public_key_bytes(),
        nonce,
        1,
        *signing_key.sign(&unsigned.canonical_message()).as_bytes(),
    )
    .expect("test first-owner: signed claim");
    assert_eq!(*claim.nonce(), nonce);
    let context = AuthenticatedBootContext::from_provenance(
        BootContextProvenance::AuthenticatedHandoff,
        machine_context,
        boot_context,
        kernel_identity,
        system_generation,
    )
    .expect("test first-owner: authenticated context");
    first_owner::begin_first_owner(store, Some(&context), &claim)
        .await
        .expect("test first-owner: begin");
    first_owner::commit_first_owner(store, Some(&context), &claim, user, fleet)
        .await
        .expect("test first-owner: commit");
}
