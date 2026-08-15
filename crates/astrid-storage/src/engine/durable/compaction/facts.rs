//! Canonical fact-snapshot field encoders.

use std::collections::BTreeMap;

use crate::storage_model::RootState;

use super::{CompactionRetainedRoot, DurableError, PrincipalCodec};

pub(super) fn encode_current_roots<P: Ord, C: PrincipalCodec<P>>(
    bytes: &mut Vec<u8>,
    roots: &BTreeMap<P, RootState>,
    codec: &C,
) -> Result<(), DurableError> {
    let mut encoded = roots
        .iter()
        .map(|(principal, root)| (codec.encode(principal), *root))
        .collect::<Vec<_>>();
    encoded.sort_by(|left, right| left.0.cmp(&right.0));
    if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(DurableError::InvalidCompactionEvidence(
            "principal codec collides in fact snapshot",
        ));
    }
    let count = u64::try_from(encoded.len()).map_err(|_| DurableError::EncodingOverflow)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for (principal, root) in encoded {
        let len = u64::try_from(principal.len()).map_err(|_| DurableError::EncodingOverflow)?;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&principal);
        bytes.extend_from_slice(&root.generation.get().to_le_bytes());
        bytes.extend_from_slice(root.commit.as_bytes());
    }
    Ok(())
}

pub(super) fn encode_retained_roots(
    bytes: &mut Vec<u8>,
    roots: &[CompactionRetainedRoot],
) -> Result<(), DurableError> {
    let count = u64::try_from(roots.len()).map_err(|_| DurableError::EncodingOverflow)?;
    bytes.extend_from_slice(&count.to_le_bytes());
    for root in roots {
        bytes.push(root.kind().code());
        bytes.extend_from_slice(root.object().as_bytes());
    }
    Ok(())
}
