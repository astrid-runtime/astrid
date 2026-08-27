//! Exact journal-media model shared by host tests and the standalone guest.

pub const FRAME_LEN: usize = 296;
pub const FRAME_COUNT: usize = 16;
pub const PAYLOAD_LEN: usize = FRAME_LEN * FRAME_COUNT;
pub const SECTOR_LEN: usize = 512;
pub const RECORD_SECTORS: usize = FRAME_COUNT + 1;
pub const RECORD_LEN: usize = RECORD_SECTORS * SECTOR_LEN;
pub const MEDIA_LEN: usize = 2 * RECORD_LEN;
pub const MAGIC: &[u8; 8] = b"ASTRABJ2";
pub const COMMIT_MAGIC: &[u8; 8] = b"PIOJAUT2";
pub const INVALID_MAGIC: &[u8; 8] = b"PIOJINV2";
pub const KEY_ID: &[u8; 16] = b"PIO1691-KEY-0001";
pub const STATE_PENDING: u8 = 1;
pub const STATE_INVALIDATED: u8 = 0;
pub const STATE_COMMITTED: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    A = 0,
    B = 1,
}

impl Slot {
    pub const ALL: [Self; 2] = [Self::A, Self::B];
    pub fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
    pub fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CommitMetadata {
    pub state: u8,
    pub epoch: u64,
}

/// Explicit host-side observation only. QEMU boot evidence is produced by
/// `pio-media-host`; this helper never presents itself as guest ATA proof.
pub fn canonical_payload() -> [u8; PAYLOAD_LEN] {
    let mut payload = [0u8; PAYLOAD_LEN];
    for (frame_index, frame) in payload.chunks_exact_mut(FRAME_LEN).enumerate() {
        frame[..MAGIC.len()].copy_from_slice(MAGIC);
        frame[8] = 2;
        frame[9..]
            .iter_mut()
            .enumerate()
            .for_each(|(offset, byte)| {
                *byte = (u32::from_ne_bytes([frame_index as u8, offset as u8, 0x91, 0x37])
                    .wrapping_mul(0x9e37_79b1)
                    >> 23) as u8;
            });
    }
    payload
}

fn slot_base(slot: Slot) -> usize {
    slot.index() * RECORD_LEN
}

fn put_u64(value: u64, out: &mut [u8]) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn get_u64(bytes: &[u8]) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(bytes);
    u64::from_le_bytes(raw)
}

pub mod auth {
    use super::KEY_ID;

    pub const KEY_LEN: usize = 32;
    pub const TAG_LEN: usize = 32;
    pub type Tag = [u8; TAG_LEN];
    const DOMAIN: &[u8] = b"astrid.issue-1691.pio.journal.v1";

    #[derive(Clone)]
    pub struct Authenticator {
        key: [u8; KEY_LEN],
    }

    impl Authenticator {
        pub fn new(key: [u8; KEY_LEN]) -> Option<Self> {
            if key == [0; KEY_LEN] {
                None
            } else {
                Some(Self { key })
            }
        }

        /// HMAC-SHA-256 over the exact commit header (through its tag field)
        /// plus every byte of the sixteen 512-byte padded frame sectors.
        pub fn tag(&self, media_header: &[u8], padded_payload: &[u8]) -> Tag {
            let mut inner = Sha256::new();
            let mut ipad = [0x36u8; 64];
            for (pad_byte, key_byte) in ipad.iter_mut().zip(self.key.iter()) {
                *pad_byte ^= *key_byte;
            }
            inner.update(&ipad);
            inner.update(DOMAIN);
            inner.update(KEY_ID);
            inner.update(media_header);
            inner.update(padded_payload);
            let inner_digest = inner.finalize();

            let mut outer = Sha256::new();
            let mut opad = [0x5cu8; 64];
            for (pad_byte, key_byte) in opad.iter_mut().zip(self.key.iter()) {
                *pad_byte ^= *key_byte;
            }
            outer.update(&opad);
            outer.update(&inner_digest);
            outer.finalize()
        }
    }

    struct Sha256 {
        state: [u32; 8],
        buffer: [u8; 64],
        buffered: usize,
        length: u128,
    }

    impl Sha256 {
        fn new() -> Self {
            Self {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
                buffer: [0; 64],
                buffered: 0,
                length: 0,
            }
        }

        fn update(&mut self, mut data: &[u8]) {
            self.length += data.len() as u128;
            if self.buffered > 0 {
                let take = core::cmp::min(64 - self.buffered, data.len());
                self.buffer[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
                self.buffered += take;
                data = &data[take..];
                if self.buffered == 64 {
                    let block = self.buffer;
                    self.compress(&block);
                    self.buffered = 0;
                }
            }
            while data.len() >= 64 {
                let mut block = [0u8; 64];
                block.copy_from_slice(&data[..64]);
                self.compress(&block);
                data = &data[64..];
            }
            if !data.is_empty() {
                self.buffer[..data.len()].copy_from_slice(data);
                self.buffered = data.len();
            }
        }

        fn finalize(mut self) -> Tag {
            let bits = (self.length * 8) as u64;
            self.update_no_length(&[0x80]);
            while self.buffered != 56 {
                self.update_no_length(&[0]);
            }
            self.update_no_length(&bits.to_be_bytes());
            let mut tag = [0; 32];
            for (index, word) in self.state.iter().enumerate() {
                tag[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
            }
            tag
        }

        fn update_no_length(&mut self, data: &[u8]) {
            for byte in data {
                self.buffer[self.buffered] = *byte;
                self.buffered += 1;
                if self.buffered == 64 {
                    let block = self.buffer;
                    self.compress(&block);
                    self.buffered = 0;
                }
            }
        }

        fn compress(&mut self, block: &[u8; 64]) {
            const K: [u32; 64] = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
                0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
                0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
                0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
                0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
                0xc67178f2,
            ];
            let mut w = [0u32; 64];
            for index in 0..16 {
                w[index] = u32::from_be_bytes([
                    block[index * 4],
                    block[index * 4 + 1],
                    block[index * 4 + 2],
                    block[index * 4 + 3],
                ]);
            }
            for index in 16..64 {
                let s0 = w[index - 15].rotate_right(7)
                    ^ w[index - 15].rotate_right(18)
                    ^ (w[index - 15] >> 3);
                let s1 = w[index - 2].rotate_right(17)
                    ^ w[index - 2].rotate_right(19)
                    ^ (w[index - 2] >> 10);
                w[index] = w[index - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[index - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
            for (round, word) in w.into_iter().enumerate() {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let choose = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(choose)
                    .wrapping_add(K[round])
                    .wrapping_add(word);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let majority = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(majority);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }
    }

    pub fn tags_equal(left: &Tag, right: &Tag) -> bool {
        let mut difference = 0u8;
        for (a, b) in left.iter().zip(right.iter()) {
            difference |= a ^ b;
        }
        difference == 0
    }
}

use auth::{Authenticator, tags_equal};

#[allow(clippy::large_enum_variant)]
pub enum Recovery {
    Candidate {
        epoch: u64,
        slot: Slot,
        payload: [u8; PAYLOAD_LEN],
    },
    Torn {
        reason: &'static str,
    },
    ConflictingSameEpoch {
        epoch: u64,
    },
    Uncommitted {
        epoch: u64,
    },
    StaleEpoch {
        found: u64,
        floor: u64,
    },
}

// Commit sector is separate from all sixteen padded frames.
const COPY_OFFSET: usize = 12;
const STATE_OFFSET: usize = 15;
const EPOCH_OFFSET: usize = 16;
const LEN_OFFSET: usize = 24;
pub const TAG_OFFSET: usize = 48;
const KEY_ID_OFFSET: usize = 32;

fn read_payload(media: &[u8], slot: Slot) -> [u8; PAYLOAD_LEN] {
    let base = slot_base(slot);
    let mut payload = [0; PAYLOAD_LEN];
    for index in 0..FRAME_COUNT {
        let start = base + index * SECTOR_LEN;
        payload[index * FRAME_LEN..(index + 1) * FRAME_LEN]
            .copy_from_slice(&media[start..start + FRAME_LEN]);
    }
    payload
}

pub fn build_slot_record(
    payload: &[u8; PAYLOAD_LEN],
    metadata: CommitMetadata,
    slot: Slot,
    authenticator: &Authenticator,
) -> [u8; RECORD_LEN] {
    let mut record = [0; RECORD_LEN];
    for (index, chunk) in payload.chunks_exact(FRAME_LEN).enumerate() {
        record[index * SECTOR_LEN..index * SECTOR_LEN + chunk.len()].copy_from_slice(chunk);
    }
    let start = FRAME_COUNT * SECTOR_LEN;
    record[start..start + COMMIT_MAGIC.len()].copy_from_slice(COMMIT_MAGIC);
    record[start + 8..start + 10].copy_from_slice(&2u16.to_le_bytes());
    record[start + 10..start + 12].copy_from_slice(&1u16.to_le_bytes());
    record[start + COPY_OFFSET] = slot.index() as u8;
    record[start + STATE_OFFSET] = metadata.state;
    record[start + KEY_ID_OFFSET..start + KEY_ID_OFFSET + KEY_ID.len()].copy_from_slice(KEY_ID);
    put_u64(
        metadata.epoch,
        &mut record[start + EPOCH_OFFSET..start + EPOCH_OFFSET + 8],
    );
    put_u64(
        PAYLOAD_LEN as u64,
        &mut record[start + LEN_OFFSET..start + LEN_OFFSET + 8],
    );
    // The authenticator sees the complete on-media representation, including
    // each sector's trailing padding and the copy identity.
    let tag = authenticator.tag(
        &record[start..start + TAG_OFFSET],
        &record[..FRAME_COUNT * SECTOR_LEN],
    );
    record[start + TAG_OFFSET..start + TAG_OFFSET + tag.len()].copy_from_slice(&tag);
    record
}

pub fn parse_media(
    media: &[u8],
    fresh_floor: u64,
    authenticator: &Authenticator,
) -> Result<Recovery, &'static str> {
    if media.len() < MEDIA_LEN || !media.len().is_multiple_of(SECTOR_LEN) {
        return Err("wrong-media-size");
    }
    let mut candidates = [(false, 0u64); 2];
    for slot in Slot::ALL {
        let base = slot_base(slot);
        let commit_start = base + FRAME_COUNT * SECTOR_LEN;
        let commit: &[u8; SECTOR_LEN] = media[commit_start..commit_start + SECTOR_LEN]
            .try_into()
            .map_err(|_| "sector-read")?;
        if commit.iter().all(|byte| *byte == 0) {
            continue;
        }
        if commit[..INVALID_MAGIC.len()] == INVALID_MAGIC[..] {
            if commit[8..10] != 2u16.to_le_bytes()
                || commit[10..12] != 1u16.to_le_bytes()
                || commit[COPY_OFFSET] != slot.index() as u8
                || commit[STATE_OFFSET] != STATE_INVALIDATED
                || commit[13..EPOCH_OFFSET].iter().any(|byte| *byte != 0)
            {
                return Ok(Recovery::Torn {
                    reason: "invalid-marker",
                });
            }
            continue;
        }
        if commit[..COMMIT_MAGIC.len()] != COMMIT_MAGIC[..] || commit[8..10] != 2u16.to_le_bytes() {
            return Ok(Recovery::Torn {
                reason: "commit-header",
            });
        }
        if commit[10..12] != 1u16.to_le_bytes() || commit[COPY_OFFSET] != slot.index() as u8 {
            return Ok(Recovery::Torn {
                reason: "layout-or-copy",
            });
        }
        if commit[KEY_ID_OFFSET..KEY_ID_OFFSET + KEY_ID.len()] != KEY_ID[..] {
            return Ok(Recovery::Torn { reason: "key-id" });
        }
        if commit[COPY_OFFSET + 1..STATE_OFFSET]
            .iter()
            .any(|byte| *byte != 0)
            || commit[TAG_OFFSET + auth::TAG_LEN..]
                .iter()
                .any(|byte| *byte != 0)
        {
            return Ok(Recovery::Torn {
                reason: "commit-padding",
            });
        }
        let state = commit[STATE_OFFSET];
        let epoch = get_u64(&commit[EPOCH_OFFSET..EPOCH_OFFSET + 8]);
        if get_u64(&commit[LEN_OFFSET..LEN_OFFSET + 8]) != PAYLOAD_LEN as u64 {
            return Ok(Recovery::Torn {
                reason: "payload-length",
            });
        }
        // Authenticator binds the commit header through TAG_OFFSET plus the
        // sixteen padded frame sectors, matching `build_slot_record`.
        let expected = authenticator.tag(
            &commit[..TAG_OFFSET],
            &media[base..base + FRAME_COUNT * SECTOR_LEN],
        );
        let stored: [u8; 32] = commit[TAG_OFFSET..TAG_OFFSET + 32].try_into().unwrap();
        if !tags_equal(&stored, &expected) {
            return Ok(Recovery::Torn {
                reason: "authentication",
            });
        }
        if state == STATE_PENDING {
            return Ok(Recovery::Uncommitted { epoch });
        }
        if state != STATE_COMMITTED {
            return Ok(Recovery::Torn { reason: "state" });
        }
        candidates[slot.index()] = (true, epoch);
    }

    let best_slot = match (candidates[0], candidates[1]) {
        ((false, _), (false, _)) => {
            return Ok(Recovery::Torn {
                reason: "missing-commit",
            });
        },
        ((true, epoch), (true, other_epoch)) if epoch == other_epoch => {
            return Ok(Recovery::ConflictingSameEpoch { epoch });
        },
        ((true, _), (false, _)) => Slot::A,
        ((false, _), (true, _)) => Slot::B,
        ((true, epoch_a), (true, epoch_b)) if epoch_a > epoch_b => Slot::A,
        ((true, _), (true, _)) => Slot::B,
    };
    let (_, epoch) = candidates[best_slot.index()];
    let other = candidates[best_slot.other().index()];
    if other.0 && other.1 > epoch {
        return Err("slot-order-impossible");
    }
    if epoch < fresh_floor {
        return Ok(Recovery::StaleEpoch {
            found: epoch,
            floor: fresh_floor,
        });
    }
    Ok(Recovery::Candidate {
        epoch,
        slot: best_slot,
        payload: read_payload(media, best_slot),
    })
}
