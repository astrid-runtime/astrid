//! Accept only a distinct, in-floor, correctly bound dual-closure pair.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::codec::decode_table;
use crate::error::ClosureError;
use crate::types::{
    BoundIdentities, ClosureArtifact, ClosureKind, DualClosureKeys, DualClosureTable,
    signed_message,
};

pub fn verify_table(bytes: &[u8]) -> Result<BoundIdentities, ClosureError> {
    let table = decode_table(bytes)?;
    check_distinct_keys(table.keys)?;
    check_slot_kinds(&table)?;
    check_floors(&table)?;
    check_identities(&table)?;
    check_signatures(&table)?;
    Ok(BoundIdentities {
        kernel_bootstrap: table.kernel.identity,
        system_generation: table.sysgen.identity,
        floor: table.kernel.floor,
    })
}

fn check_distinct_keys(keys: DualClosureKeys) -> Result<(), ClosureError> {
    if keys.kernel_bootstrap == keys.system_generation {
        return Err(ClosureError::SameKey);
    }
    Ok(())
}

fn check_slot_kinds(table: &DualClosureTable) -> Result<(), ClosureError> {
    if table.kernel.kind != ClosureKind::KernelBootstrap
        || table.sysgen.kind != ClosureKind::SystemGeneration
    {
        return Err(ClosureError::Swapped);
    }
    Ok(())
}

fn check_floors(table: &DualClosureTable) -> Result<(), ClosureError> {
    if table.kernel.floor < table.min_floor || table.sysgen.floor < table.min_floor {
        return Err(ClosureError::Stale);
    }
    Ok(())
}

fn check_identities(table: &DualClosureTable) -> Result<(), ClosureError> {
    if table.kernel.identity == table.sysgen.identity {
        return Err(ClosureError::Collision);
    }
    if table.sysgen.identity != crate::types::MeasuredIdentity::empty_sysgen() {
        return Err(ClosureError::NotEmpty);
    }
    Ok(())
}

fn check_signatures(table: &DualClosureTable) -> Result<(), ClosureError> {
    bind_artifact(
        &table.kernel,
        &table.keys.kernel_bootstrap,
        &table.keys.system_generation,
    )?;
    bind_artifact(
        &table.sysgen,
        &table.keys.system_generation,
        &table.keys.kernel_bootstrap,
    )
}

fn bind_artifact(
    artifact: &ClosureArtifact,
    expected_key: &[u8; 32],
    other_key: &[u8; 32],
) -> Result<(), ClosureError> {
    if artifact.signer != *expected_key {
        return Err(ClosureError::CrossBound);
    }
    let msg = signed_message(artifact.kind, artifact.floor, artifact.identity);
    if verifies(expected_key, &msg, &artifact.signature) {
        return Ok(());
    }
    if verifies(other_key, &msg, &artifact.signature) {
        return Err(ClosureError::CrossBound);
    }
    Err(ClosureError::SignatureInvalid)
}

fn verifies(key: &[u8; 32], msg: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    vk.verify_strict(msg, &sig).is_ok()
}
