//! Streaming verification against a digest pinned before logical recovery.
use super::{ArenaLocation, BTreeMap, DurableError, ObjectId, RecoveredDirect, io_error};
use std::io::{BufReader, Read};

pub(super) fn validate(
    stream: RecoveredDirect,
    index: &BTreeMap<ObjectId, ArenaLocation>,
) -> Result<(), DurableError> {
    let mut input = BufReader::new(stream.file);
    let mut digest = blake3::Hasher::new();
    let mut remaining = stream.bytes;
    for _ in 0..stream.groups {
        let object = ObjectId::new(take::<32>(&mut input, &mut digest, &mut remaining)?);
        let count = u64::from_le_bytes(take::<8>(&mut input, &mut digest, &mut remaining)?);
        if count == 0 || count > remaining / 48 {
            return Err(invalid());
        }
        let expected = index
            .get(&object)
            .ok_or(DurableError::InvalidRepresentationState(
                "direct representation names a missing logical object",
            ))?;
        let mut matched = false;
        for _ in 0..count {
            let offset = u64::from_le_bytes(take::<8>(&mut input, &mut digest, &mut remaining)?);
            let payload_len =
                u64::from_le_bytes(take::<8>(&mut input, &mut digest, &mut remaining)?);
            let checksum = take::<32>(&mut input, &mut digest, &mut remaining)?;
            matched |= *expected
                == ArenaLocation {
                    offset,
                    payload_len,
                    checksum,
                };
        }
        if !matched {
            return Err(DurableError::InvalidRepresentationState(
                "generation-zero placement disagrees with the arena index",
            ));
        }
    }
    let mut trailing = [0; 1];
    if remaining != 0
        || input
            .read(&mut trailing)
            .map_err(|e| io_error("check recovery replica stream end", e))?
            != 0
        || digest.finalize() != stream.digest
    {
        return Err(invalid());
    }
    Ok(())
}

fn take<const N: usize>(
    input: &mut impl Read,
    digest: &mut blake3::Hasher,
    remaining: &mut u64,
) -> Result<[u8; N], DurableError> {
    *remaining = remaining
        .checked_sub(u64::try_from(N).map_err(|_| DurableError::EncodingOverflow)?)
        .ok_or_else(invalid)?;
    let mut bytes = [0; N];
    input
        .read_exact(&mut bytes)
        .map_err(|e| io_error("read recovery replica stream", e))?;
    digest.update(&bytes);
    Ok(bytes)
}

fn invalid() -> DurableError {
    DurableError::InvalidRepresentationState("recovery replica stream is corrupt")
}
