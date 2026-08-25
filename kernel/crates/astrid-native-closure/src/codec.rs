//! Fixed-layout encode/decode. No allocation.

use crate::error::ClosureError;
use crate::types::{
    ARTIFACT_LEN, ClosureArtifact, ClosureKind, DualClosureKeys, DualClosureTable, GenerationFloor,
    HEADER_LEN, MAGIC, MeasuredIdentity, TABLE_LEN, VERSION,
};

pub fn encode_table(table: &DualClosureTable) -> [u8; TABLE_LEN] {
    let mut out = [0u8; TABLE_LEN];
    out[..8].copy_from_slice(MAGIC);
    out[8] = VERSION;
    out[9..17].copy_from_slice(&table.min_floor.to_le_bytes());
    out[17..49].copy_from_slice(&table.keys.kernel_bootstrap);
    out[49..81].copy_from_slice(&table.keys.system_generation);
    encode_artifact(
        &table.kernel,
        &mut out[HEADER_LEN..HEADER_LEN + ARTIFACT_LEN],
    );
    encode_artifact(
        &table.sysgen,
        &mut out[HEADER_LEN + ARTIFACT_LEN..TABLE_LEN],
    );
    out
}

pub fn decode_table(bytes: &[u8]) -> Result<DualClosureTable, ClosureError> {
    if bytes.is_empty() {
        return Err(ClosureError::Missing);
    }
    if bytes.len() != TABLE_LEN {
        return Err(ClosureError::Truncated);
    }
    if bytes[..8] != MAGIC[..] {
        return Err(ClosureError::Malformed);
    }
    if bytes[8] != VERSION {
        return Err(ClosureError::Malformed);
    }
    let mut min_floor_bytes = [0u8; 8];
    min_floor_bytes.copy_from_slice(&bytes[9..17]);
    let min_floor = GenerationFloor::from_le_bytes(min_floor_bytes);
    let mut kernel_bootstrap = [0u8; 32];
    kernel_bootstrap.copy_from_slice(&bytes[17..49]);
    let mut system_generation = [0u8; 32];
    system_generation.copy_from_slice(&bytes[49..81]);
    let kernel = decode_artifact(&bytes[HEADER_LEN..HEADER_LEN + ARTIFACT_LEN])?;
    let sysgen = decode_artifact(&bytes[HEADER_LEN + ARTIFACT_LEN..TABLE_LEN])?;
    Ok(DualClosureTable {
        min_floor,
        keys: DualClosureKeys {
            kernel_bootstrap,
            system_generation,
        },
        kernel,
        sysgen,
    })
}

fn encode_artifact(artifact: &ClosureArtifact, out: &mut [u8]) {
    out[0] = artifact.kind.to_u8();
    out[1..9].copy_from_slice(&artifact.floor.to_le_bytes());
    out[9..41].copy_from_slice(&artifact.identity.as_bytes());
    out[41..73].copy_from_slice(&artifact.signer);
    out[73..137].copy_from_slice(&artifact.signature);
}

fn decode_artifact(bytes: &[u8]) -> Result<ClosureArtifact, ClosureError> {
    if bytes.len() != ARTIFACT_LEN {
        return Err(ClosureError::Truncated);
    }
    let kind = ClosureKind::from_u8(bytes[0]).ok_or(ClosureError::Malformed)?;
    let mut floor_bytes = [0u8; 8];
    floor_bytes.copy_from_slice(&bytes[1..9]);
    let floor = GenerationFloor::from_le_bytes(floor_bytes);
    let mut identity = [0u8; 32];
    identity.copy_from_slice(&bytes[9..41]);
    let mut signer = [0u8; 32];
    signer.copy_from_slice(&bytes[41..73]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&bytes[73..137]);
    Ok(ClosureArtifact {
        kind,
        floor,
        identity: MeasuredIdentity::from_bytes(identity),
        signer,
        signature,
    })
}
