//! Fixed-frame encoding and domain-separated integrity checksum.

use crate::error::JournalError;
use crate::types::{CandidateClaim, CandidateInput, DIGEST_LEN, Frame, RecordState, Slot};

pub const FRAME_LEN: usize = 256;
pub const MAGIC: &[u8; 8] = b"ASTRABJ1";
pub const VERSION: u8 = 1;
pub const RESERVED_START: usize = 12;
pub const RESERVED_END: usize = 16;
pub const RECORD_SEQ_START: usize = 16;
pub const RECORD_SEQ_END: usize = 24;
pub const BOOT_SEQUENCE_START: usize = 24;
pub const BOOT_SEQUENCE_END: usize = 32;
pub const FACTS_START: usize = 32;
pub const DESCRIPTOR_START: usize = FACTS_START;
pub const KERNEL_START: usize = DESCRIPTOR_START + DIGEST_LEN;
pub const PLAN_START: usize = KERNEL_START + DIGEST_LEN;
pub const OBJECT_ROOT_START: usize = PLAN_START + DIGEST_LEN;
pub const CLOSURE_ROOT_START: usize = OBJECT_ROOT_START + DIGEST_LEN;
pub const FACTS_END: usize = CLOSURE_ROOT_START + DIGEST_LEN;
pub const GENERATION_START: usize = FACTS_END;
pub const GENERATION_END: usize = GENERATION_START + 8;
pub const ROLLBACK_START: usize = GENERATION_END;
pub const ROLLBACK_END: usize = ROLLBACK_START + 8;
pub const KERNEL_FLOOR_START: usize = ROLLBACK_END;
pub const KERNEL_FLOOR_END: usize = KERNEL_FLOOR_START + 8;
pub const SYSGEN_FLOOR_START: usize = KERNEL_FLOOR_END;
pub const SYSGEN_FLOOR_END: usize = SYSGEN_FLOOR_START + 8;
pub const CHECKSUM_START: usize = SYSGEN_FLOOR_END;
pub const CHECKSUM_END: usize = CHECKSUM_START + 32;

pub fn encode_frame(frame: &Frame) -> [u8; FRAME_LEN] {
    let mut out = [0u8; FRAME_LEN];
    out[..MAGIC.len()].copy_from_slice(MAGIC);
    out[8] = VERSION;
    out[9] = frame.state.to_byte();
    out[10] = frame.slot.to_byte();
    out[11] = frame.attempt;
    write_u64(frame.record_seq, &mut out[RECORD_SEQ_START..RECORD_SEQ_END]);
    write_u64(
        frame.boot_sequence,
        &mut out[BOOT_SEQUENCE_START..BOOT_SEQUENCE_END],
    );
    copy_digest(
        frame.claim.descriptor_identity(),
        &mut out[DESCRIPTOR_START..KERNEL_START],
    );
    copy_digest(
        frame.claim.kernel_identity(),
        &mut out[KERNEL_START..PLAN_START],
    );
    copy_digest(
        frame.claim.plan_digest(),
        &mut out[PLAN_START..OBJECT_ROOT_START],
    );
    copy_digest(
        frame.claim.object_root(),
        &mut out[OBJECT_ROOT_START..CLOSURE_ROOT_START],
    );
    copy_digest(
        frame.claim.closure_root(),
        &mut out[CLOSURE_ROOT_START..FACTS_END],
    );
    write_u64(
        frame.claim.generation(),
        &mut out[GENERATION_START..GENERATION_END],
    );
    write_u64(
        frame.claim.rollback_floor(),
        &mut out[ROLLBACK_START..ROLLBACK_END],
    );
    write_u64(
        frame.claim.kernel_floor(),
        &mut out[KERNEL_FLOOR_START..KERNEL_FLOOR_END],
    );
    write_u64(
        frame.claim.sysgen_floor(),
        &mut out[SYSGEN_FLOOR_START..SYSGEN_FLOOR_END],
    );
    let checksum = checksum(&out[..CHECKSUM_START]);
    out[CHECKSUM_START..CHECKSUM_END].copy_from_slice(&checksum);
    out
}

pub fn decode_frame(bytes: &[u8; FRAME_LEN]) -> Result<Frame, JournalError> {
    if bytes[..MAGIC.len()] != MAGIC[..] || bytes[8] != VERSION {
        return Err(JournalError::InteriorCorrupt);
    }
    if bytes[RESERVED_START..RESERVED_END]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(JournalError::InteriorCorrupt);
    }
    if checksum(&bytes[..CHECKSUM_START]) != bytes[CHECKSUM_START..CHECKSUM_END] {
        return Err(JournalError::InteriorCorrupt);
    }
    let state = RecordState::from_byte(bytes[9]).ok_or(JournalError::InteriorCorrupt)?;
    let slot = Slot::from_byte(bytes[10]).ok_or(JournalError::InteriorCorrupt)?;
    let attempt = bytes[11];
    if attempt == 0 || attempt > crate::policy::MAX_ATTEMPTS {
        return Err(JournalError::InteriorCorrupt);
    }
    let claim = decode_claim(bytes)?;
    Ok(Frame {
        state,
        slot,
        attempt,
        record_seq: read_u64(&bytes[RECORD_SEQ_START..RECORD_SEQ_END]),
        boot_sequence: read_u64(&bytes[BOOT_SEQUENCE_START..BOOT_SEQUENCE_END]),
        claim,
    })
}

fn decode_claim(bytes: &[u8; FRAME_LEN]) -> Result<CandidateClaim, JournalError> {
    let mut descriptor = [0u8; DIGEST_LEN];
    let mut kernel = [0u8; DIGEST_LEN];
    let mut plan = [0u8; DIGEST_LEN];
    let mut object_root = [0u8; DIGEST_LEN];
    let mut closure_root = [0u8; DIGEST_LEN];
    descriptor.copy_from_slice(&bytes[DESCRIPTOR_START..KERNEL_START]);
    kernel.copy_from_slice(&bytes[KERNEL_START..PLAN_START]);
    plan.copy_from_slice(&bytes[PLAN_START..OBJECT_ROOT_START]);
    object_root.copy_from_slice(&bytes[OBJECT_ROOT_START..CLOSURE_ROOT_START]);
    closure_root.copy_from_slice(&bytes[CLOSURE_ROOT_START..FACTS_END]);
    if [descriptor, kernel, plan, object_root, closure_root]
        .iter()
        .any(|digest| digest.iter().all(|byte| *byte == 0))
    {
        return Err(JournalError::InteriorCorrupt);
    }
    Ok(CandidateClaim::from_persisted(CandidateInput {
        descriptor_identity: descriptor,
        kernel_identity: kernel,
        plan_digest: plan,
        object_root,
        closure_root,
        generation: read_u64(&bytes[GENERATION_START..GENERATION_END]),
        rollback_floor: read_u64(&bytes[ROLLBACK_START..ROLLBACK_END]),
        kernel_floor: read_u64(&bytes[KERNEL_FLOOR_START..KERNEL_FLOOR_END]),
        sysgen_floor: read_u64(&bytes[SYSGEN_FLOOR_START..SYSGEN_FLOOR_END]),
    }))
}

/// BLAKE3 detects torn or modified bytes only; it is not authentication.
fn checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("astrid.boot-selection.journal.v1");
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn copy_digest(digest: [u8; DIGEST_LEN], out: &mut [u8]) {
    out.copy_from_slice(&digest);
}

fn read_u64(bytes: &[u8]) -> u64 {
    let mut value = [0u8; 8];
    value.copy_from_slice(bytes);
    u64::from_le_bytes(value)
}

fn write_u64(value: u64, out: &mut [u8]) {
    out.copy_from_slice(&value.to_le_bytes());
}
