//! Journal storage model, scan, and append-only transition validation.

use crate::codec::{FRAME_LEN, decode_frame, encode_frame};
use crate::error::JournalError;
use crate::types::{Frame, RecordState, transition_is_valid};

pub const FRAME_COUNT: usize = 16;
pub const JOURNAL_LEN: usize = FRAME_LEN * FRAME_COUNT;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Journal {
    bytes: [u8; JOURNAL_LEN],
}

impl Journal {
    pub const fn empty() -> Self {
        Self {
            bytes: [0; JOURNAL_LEN],
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() != JOURNAL_LEN {
            return Err(JournalError::WrongLength);
        }
        let mut out = [0u8; JOURNAL_LEN];
        out.copy_from_slice(bytes);
        Ok(Self { bytes: out })
    }

    pub const fn as_bytes(self) -> [u8; JOURNAL_LEN] {
        self.bytes
    }

    pub(crate) fn parse(self) -> Result<ParsedJournal, JournalError> {
        let mut parsed = ParsedJournal::empty();
        let mut index = 0;
        while index < FRAME_COUNT {
            let start = index * FRAME_LEN;
            let end = start + FRAME_LEN;
            let mut raw = [0u8; FRAME_LEN];
            raw.copy_from_slice(&self.bytes[start..end]);
            if raw.iter().all(|byte| *byte == 0) {
                if self.bytes[end..].iter().any(|byte| *byte != 0) {
                    return Err(JournalError::InteriorCorrupt);
                }
                return Ok(parsed);
            }
            let frame = match decode_frame(&raw) {
                Ok(frame) => frame,
                Err(_) => {
                    if self.bytes[end..].iter().any(|byte| *byte != 0) {
                        return Err(JournalError::InteriorCorrupt);
                    }
                    return Ok(parsed);
                },
            };
            validate_frame(&parsed, frame)?;
            parsed.frames[index] = Some(frame);
            parsed.latest_by_slot[frame.slot.index()] = Some(frame);
            if frame.state == RecordState::Confirmed {
                parsed.latest_confirmed_by_slot[frame.slot.index()] = Some(frame);
            }
            parsed.count += 1;
            parsed.last = Some(frame);
            index += 1;
        }
        Ok(parsed)
    }

    pub(crate) fn append(self, frame: Frame) -> Result<Self, JournalError> {
        let parsed = self.parse()?;
        if parsed.count == FRAME_COUNT {
            return Err(JournalError::Full);
        }
        if !frame.claim.well_formed() {
            return Err(JournalError::Ineligible);
        }
        validate_frame(&parsed, frame)?;
        let mut bytes = self.bytes;
        let start = parsed.count * FRAME_LEN;
        bytes[start..start + FRAME_LEN].copy_from_slice(&encode_frame(&frame));
        Ok(Self { bytes })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParsedJournal {
    pub frames: [Option<Frame>; FRAME_COUNT],
    pub latest_by_slot: [Option<Frame>; 2],
    pub latest_confirmed_by_slot: [Option<Frame>; 2],
    pub count: usize,
    pub last: Option<Frame>,
}

impl ParsedJournal {
    pub const fn empty() -> Self {
        Self {
            frames: [None; FRAME_COUNT],
            latest_by_slot: [None; 2],
            latest_confirmed_by_slot: [None; 2],
            count: 0,
            last: None,
        }
    }

    pub fn latest_pending(self) -> Option<Frame> {
        let mut result = None;
        for frame in self.latest_by_slot.into_iter().flatten() {
            if frame.state == RecordState::Pending
                && result.is_none_or(|current: Frame| frame.record_seq > current.record_seq)
            {
                result = Some(frame);
            }
        }
        result
    }

    pub fn latest_confirmed(self) -> Option<Frame> {
        let mut result = None;
        for frame in self.latest_confirmed_by_slot.into_iter().flatten() {
            if frame.state == RecordState::Confirmed
                && result.is_none_or(|current: Frame| frame.record_seq > current.record_seq)
            {
                result = Some(frame);
            }
        }
        result
    }
}

fn validate_frame(parsed: &ParsedJournal, frame: Frame) -> Result<(), JournalError> {
    if parsed.count == 0 {
        if frame.record_seq != 0 || frame.state != RecordState::Pending || frame.attempt != 1 {
            return Err(JournalError::InvalidTransition);
        }
    } else {
        transition_is_valid(parsed.last, frame)?;
    }
    Ok(())
}
