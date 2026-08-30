//! Independent strict decoder for the frozen canonical frame wire format.
//! Mirrors the kernel codec byte-for-byte; any drift fails loudly here.

/// Wire-level decode errors for one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Malformed,
    DenialDisclosure,
}

/// Minimal view the fold needs: sequence plus denial-projection checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameView {
    pub boot: [u8; 16],
    pub seq: u64,
    pub class: u16,
    pub has_object: bool,
    pub prev_root: Option<[u8; 32]>,
}

const CLASS_DISCRIMINANTS: &[u16] = &[
    1, 2, 3, 4, 5, 6, 7, 8, 9, 16, 17, 18, 32, 33, 34, 35, 48, 49, 50, 64, 65, 66, 80,
];

const DENIAL_CLASS: u16 = 80;
const LANDED_RIGHTS_MASK: u16 = 0b1111;
const MAX_PAYLOAD: usize = 64;

/// Strict canonical decode with the same fail-closed rules as the kernel.
pub fn decode_frame(bytes: &[u8]) -> Result<FrameView, WireError> {
    let mut reader = Reader::new(bytes).ok_or(WireError::Malformed)?;
    let total = reader.u32().ok_or(WireError::Malformed)? as usize;
    if bytes.len() - 4 != total {
        return Err(WireError::Malformed);
    }
    let codec_version = reader.u16().ok_or(WireError::Malformed)?;
    if codec_version != super::CODEC_VERSION {
        return Err(WireError::Malformed);
    }
    let boot: [u8; 16] = reader
        .bytes(16)
        .ok_or(WireError::Malformed)?
        .try_into()
        .map_err(|_| WireError::Malformed)?;
    if boot.iter().all(|byte| *byte == 0) {
        return Err(WireError::Malformed);
    }
    let seq = reader.u64().ok_or(WireError::Malformed)?;
    if seq == 0 {
        return Err(WireError::Malformed);
    }
    let class = reader.u16().ok_or(WireError::Malformed)?;
    if !CLASS_DISCRIMINANTS.contains(&class) {
        return Err(WireError::Malformed);
    }
    let subject_slot = reader.u8().ok_or(WireError::Malformed)? as usize;
    if subject_slot >= 2 {
        return Err(WireError::Malformed);
    }
    let subject_generation = reader.u64().ok_or(WireError::Malformed)?;
    if subject_generation == 0 {
        return Err(WireError::Malformed);
    }
    let has_object = match reader.u8().ok_or(WireError::Malformed)? {
        0 => false,
        1 => {
            if reader.u8().ok_or(WireError::Malformed)? as usize >= 2 {
                return Err(WireError::Malformed);
            }
            if reader.u64().ok_or(WireError::Malformed)? == 0 {
                return Err(WireError::Malformed);
            }
            true
        },
        2 => {
            if reader.u8().ok_or(WireError::Malformed)? as usize >= 4 {
                return Err(WireError::Malformed);
            }
            if reader.u64().ok_or(WireError::Malformed)? == 0 {
                return Err(WireError::Malformed);
            }
            true
        },
        3 => {
            if reader.u64().ok_or(WireError::Malformed)? == 0 {
                return Err(WireError::Malformed);
            }
            if reader.u8().ok_or(WireError::Malformed)? as usize >= 8 {
                return Err(WireError::Malformed);
            }
            if reader.u64().ok_or(WireError::Malformed)? == 0 {
                return Err(WireError::Malformed);
            }
            let kind = reader.u8().ok_or(WireError::Malformed)?;
            if kind != 2 {
                return Err(WireError::Malformed);
            }
            if reader.u64().ok_or(WireError::Malformed)? == 0 {
                return Err(WireError::Malformed);
            }
            true
        },
        _ => return Err(WireError::Malformed),
    };
    let rights = reader.u16().ok_or(WireError::Malformed)?;
    if rights & !LANDED_RIGHTS_MASK != 0 {
        return Err(WireError::Malformed);
    }
    let payload_len = reader.u16().ok_or(WireError::Malformed)? as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(WireError::Malformed);
    }
    let payload_start = reader.pos();
    reader.skip(payload_len).ok_or(WireError::Malformed)?;
    let prev_root = match reader.u8().ok_or(WireError::Malformed)? {
        0 => None,
        1 => Some(
            reader
                .bytes(32)
                .ok_or(WireError::Malformed)?
                .try_into()
                .map_err(|_| WireError::Malformed)?,
        ),
        _ => return Err(WireError::Malformed),
    };
    if reader.remaining() != 0 {
        return Err(WireError::Malformed);
    }
    if class == DENIAL_CLASS {
        if has_object {
            return Err(WireError::DenialDisclosure);
        }
        let payload = &bytes[payload_start..payload_start + payload_len];
        let denial_ok =
            payload.len() == 10 && matches!(u16::from_le_bytes([payload[0], payload[1]]), 1..=6);
        if !denial_ok {
            return Err(WireError::Malformed);
        }
    }
    Ok(FrameView {
        boot,
        seq,
        class,
        has_object,
        prev_root,
    })
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }
        Some(Self { bytes, pos: 0 })
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn skip(&mut self, len: usize) -> Option<()> {
        if self.remaining() < len {
            return None;
        }
        self.pos += len;
        Some(())
    }

    pub fn bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.remaining() < len {
            return None;
        }
        let start = self.pos;
        self.pos += len;
        Some(&self.bytes[start..self.pos])
    }

    pub fn u8(&mut self) -> Option<u8> {
        Some(self.bytes(1)?[0])
    }

    pub fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.bytes(2)?.try_into().ok()?))
    }

    pub fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.bytes(4)?.try_into().ok()?))
    }

    pub fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.bytes(8)?.try_into().ok()?))
    }
}
