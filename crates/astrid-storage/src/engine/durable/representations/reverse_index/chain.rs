//! Immutable checksummed links, rooted in authenticated paged head locations.

use super::super::super::format::{frame_checksum, read_frame_at};
use super::super::super::{FRAME_HEADER_LEN, RecoveryLimits};
use super::{
    ArenaLocation, DurableError, ObjectId, Ordering, RepresentationRecordId, ReverseIndex,
};

// This private process-local framing is never persisted as store authority.
// Its exact payload ceiling bounds scratch reads before allocating buffers.
pub(super) const MAGIC: [u8; 8] = *b"ASTRREV1";
pub(super) const PAYLOAD_BYTES: usize = 152;
const SCRATCH: &str = "anonymous reverse locator arena";

pub(super) struct Link {
    pub(super) id: RepresentationRecordId,
    pub(super) first: RepresentationRecordId,
    pub(super) previous: Option<ArenaLocation>,
}

impl Link {
    pub(super) fn encode(&self, object: ObjectId) -> [u8; PAYLOAD_BYTES] {
        let mut bytes = [0; PAYLOAD_BYTES];
        bytes[..32].copy_from_slice(object.as_bytes());
        bytes[32..64].copy_from_slice(self.id.as_bytes());
        bytes[64..96].copy_from_slice(self.first.as_bytes());
        if let Some(previous) = self.previous {
            bytes[96] = 1;
            bytes[104..112].copy_from_slice(&previous.offset.to_le_bytes());
            bytes[112..120].copy_from_slice(&previous.payload_len.to_le_bytes());
            bytes[120..].copy_from_slice(&previous.checksum);
        }
        bytes
    }

    fn decode(
        object: ObjectId,
        location: ArenaLocation,
        bytes: &[u8],
    ) -> Result<Self, DurableError> {
        if bytes.len() != PAYLOAD_BYTES
            || &bytes[..32] != object.as_bytes()
            || bytes[97..104].iter().any(|byte| *byte != 0)
        {
            return Err(corrupt("reverse link has invalid shape or object identity"));
        }
        let id = RepresentationRecordId::new(
            bytes[32..64]
                .try_into()
                .map_err(|_| corrupt("reverse record identity"))?,
        );
        let first = RepresentationRecordId::new(
            bytes[64..96]
                .try_into()
                .map_err(|_| corrupt("reverse earliest identity"))?,
        );
        let previous = match bytes[96] {
            0 if bytes[104..].iter().all(|byte| *byte == 0) && first == id => None,
            1 => {
                let previous = ArenaLocation {
                    offset: u64::from_le_bytes(
                        bytes[104..112]
                            .try_into()
                            .map_err(|_| corrupt("reverse backlink offset"))?,
                    ),
                    payload_len: u64::from_le_bytes(
                        bytes[112..120]
                            .try_into()
                            .map_err(|_| corrupt("reverse backlink length"))?,
                    ),
                    checksum: bytes[120..]
                        .try_into()
                        .map_err(|_| corrupt("reverse backlink checksum"))?,
                };
                let end = previous
                    .offset
                    .checked_add(FRAME_HEADER_LEN)
                    .and_then(|offset| offset.checked_add(previous.payload_len))
                    .ok_or(DurableError::EncodingOverflow)?;
                if previous.payload_len != PAYLOAD_BYTES as u64 || end > location.offset {
                    return Err(corrupt("reverse backlink is forward or overlapping"));
                }
                Some(previous)
            },
            _ => {
                return Err(corrupt(
                    "reverse link has invalid presence or terminal state",
                ));
            },
        };
        Ok(Self {
            id,
            first,
            previous,
        })
    }
}

impl ReverseIndex {
    pub(super) fn link(
        &self,
        object: ObjectId,
        location: ArenaLocation,
    ) -> Result<Link, DurableError> {
        let result = (|| {
            if location.payload_len != PAYLOAD_BYTES as u64 {
                return Err(corrupt("reverse locator has invalid payload length"));
            }
            let limits = RecoveryLimits::new(PAYLOAD_BYTES as u64)
                .expect("fixed nonzero reverse frame size");
            let bytes = read_frame_at(&self.file, SCRATCH, MAGIC, location.offset, limits)?;
            if bytes.len() != PAYLOAD_BYTES
                || frame_checksum(MAGIC, location.payload_len, &bytes) != location.checksum
            {
                return Err(corrupt(
                    "reverse link no longer matches authenticated head or backlink",
                ));
            }
            Link::decode(object, location, &bytes)
        })();
        result.inspect_err(|_| self.failed.store(true, Ordering::Release))
    }
}

pub(super) fn corrupt(detail: &'static str) -> DurableError {
    DurableError::Corrupt {
        file: SCRATCH,
        offset: 0,
        detail,
    }
}
