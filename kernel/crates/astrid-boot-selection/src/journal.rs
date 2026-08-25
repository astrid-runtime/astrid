//! Journal storage model, scan, and append-only transition validation.

use crate::codec::{FRAME_LEN, decode_frame, encode_frame};
use crate::error::JournalError;
use crate::policy::MAX_ATTEMPTS;
use crate::types::{CandidateClaim, Frame, RecordState, transition_is_valid};

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
            if frame.state == RecordState::Bad
                || (frame.state == RecordState::Pending && frame.attempt == MAX_ATTEMPTS)
            {
                parsed.record_failed(frame.claim);
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
    pub failed_claims: [Option<CandidateClaim>; FRAME_COUNT],
    pub failed_count: usize,
    pub count: usize,
    pub last: Option<Frame>,
}

impl ParsedJournal {
    pub const fn empty() -> Self {
        Self {
            frames: [None; FRAME_COUNT],
            latest_by_slot: [None; 2],
            failed_claims: [None; FRAME_COUNT],
            failed_count: 0,
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
        for frame in self.frames.into_iter().flatten() {
            if frame.state == RecordState::Confirmed
                && !self.is_failed(frame.claim)
                && result.is_none_or(|current: Frame| frame.record_seq > current.record_seq)
            {
                result = Some(frame);
            }
        }
        result
    }

    pub fn is_failed(self, claim: CandidateClaim) -> bool {
        self.failed_claims[..self.failed_count]
            .iter()
            .flatten()
            .any(|failed| *failed == claim)
    }

    fn record_failed(&mut self, claim: CandidateClaim) {
        if self.is_failed(claim) || self.failed_count == FRAME_COUNT {
            return;
        }
        self.failed_claims[self.failed_count] = Some(claim);
        self.failed_count += 1;
    }
}

fn validate_frame(parsed: &ParsedJournal, frame: Frame) -> Result<(), JournalError> {
    if parsed.count == 0 {
        if frame.record_seq != 0 || frame.state != RecordState::Pending || frame.attempt != 1 {
            return Err(JournalError::InvalidTransition);
        }
    } else {
        if parsed.is_failed(frame.claim) {
            return Err(JournalError::AttemptsExhausted);
        }
        transition_is_valid(parsed.last, frame)?;
    }
    Ok(())
}
