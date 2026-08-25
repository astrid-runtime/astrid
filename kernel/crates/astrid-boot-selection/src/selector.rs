//! Candidate selection and exact-token lifecycle operations.

use crate::error::{JournalError, SelectionError};
use crate::journal::Journal;
use crate::policy::{MAX_ATTEMPTS, SelectionPolicy};
use crate::types::{CandidateClaim, CandidateFacts, Frame, PendingToken, RecordState, Slot};

/// Fresh verifier-owned facts used to rebind persisted journal claims. The
/// journal never creates these values; an adapter constructs this set only
/// after descriptor/closure verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCandidates {
    facts: [Option<CandidateFacts>; 2],
}

impl VerifiedCandidates {
    pub const fn empty() -> Self {
        Self {
            facts: [None, None],
        }
    }

    #[allow(dead_code)]
    pub(crate) const fn from_verified(
        first: Option<CandidateFacts>,
        second: Option<CandidateFacts>,
    ) -> Self {
        Self {
            facts: [first, second],
        }
    }

    fn matching(self, claim: CandidateClaim) -> Option<CandidateFacts> {
        let mut index = 0;
        while index < self.facts.len() {
            if let Some(facts) = self.facts[index]
                && claim.matches(facts)
            {
                return Some(facts);
            }
            index += 1;
        }
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selector {
    policy: SelectionPolicy,
}

impl Selector {
    pub const fn new(policy: SelectionPolicy) -> Self {
        Self { policy }
    }

    /// Recover the newest eligible pending trial or confirmed candidate.
    ///
    /// A malformed/torn final frame with an all-zero tail is ignored by the
    /// journal scanner. Any interior corruption becomes `Recovery`; this
    /// method never silently chooses a later record over a damaged interior.
    pub fn recover(&self, journal: Journal, verified: VerifiedCandidates) -> BootDecision {
        let Ok(parsed) = journal.parse() else {
            return BootDecision::Recovery;
        };
        let pending = parsed.latest_pending().and_then(|frame| {
            let facts = verified.matching(frame.claim)?;
            (frame.attempt < MAX_ATTEMPTS && self.policy.accepts(&facts)).then_some((frame, facts))
        });
        let confirmed = parsed.latest_confirmed().and_then(|frame| {
            let facts = verified.matching(frame.claim)?;
            self.policy.accepts(&facts).then_some((frame, facts))
        });
        match (pending, confirmed) {
            (Some((pending, _)), Some((confirmed, facts)))
                if confirmed.record_seq > pending.record_seq =>
            {
                BootDecision::Confirmed(ConfirmedBoot {
                    slot: confirmed.slot,
                    facts,
                })
            },
            (Some((pending, facts)), _) => BootDecision::Pending(PendingTrial {
                journal,
                token: pending.token(),
                facts,
            }),
            (None, Some((confirmed, facts))) => BootDecision::Confirmed(ConfirmedBoot {
                slot: confirmed.slot,
                facts,
            }),
            (None, None) => BootDecision::Recovery,
        }
    }

    /// Append a new pending trial. The returned journal bytes are the record
    /// that the caller must durably persist before executing the candidate.
    pub fn start_pending(
        &self,
        journal: Journal,
        slot: Slot,
        facts: CandidateFacts,
        boot_sequence: u64,
    ) -> Result<PendingTrial, SelectionError> {
        if !self.policy.accepts(&facts) {
            return Err(SelectionError::Journal(JournalError::Ineligible));
        }
        let parsed = journal.parse().map_err(|_| SelectionError::Recovery)?;
        if parsed.is_failed(facts.claim()) {
            return Err(SelectionError::Journal(JournalError::AttemptsExhausted));
        }
        if parsed
            .latest_confirmed()
            .is_some_and(|confirmed| confirmed.claim == facts.claim())
        {
            return Err(SelectionError::Journal(JournalError::PendingExists));
        }
        let attempt = match parsed.latest_pending() {
            Some(pending) if pending.attempt >= MAX_ATTEMPTS => {
                return Err(SelectionError::Journal(JournalError::AttemptsExhausted));
            },
            Some(pending) if pending.slot == slot && pending.claim == facts.claim() => {
                pending.attempt + 1
            },
            Some(_) => return Err(SelectionError::Journal(JournalError::PendingExists)),
            None => 1,
        };
        let record_seq = next_record_seq(parsed.last)?;
        if parsed
            .last
            .is_some_and(|last| boot_sequence <= last.boot_sequence)
        {
            return Err(SelectionError::Journal(
                JournalError::BootSequenceNotMonotonic,
            ));
        }
        let frame = Frame {
            state: RecordState::Pending,
            slot,
            attempt,
            record_seq,
            boot_sequence,
            claim: facts.claim(),
        };
        let journal = journal.append(frame).map_err(SelectionError::Journal)?;
        Ok(PendingTrial {
            journal,
            token: frame.token(),
            facts,
        })
    }

    /// Confirm exactly the latest pending record. The token is opaque and is
    /// returned only by `start_pending` or recovery of that record.
    pub fn confirm(
        &self,
        journal: Journal,
        token: PendingToken,
    ) -> Result<Journal, SelectionError> {
        self.finish_pending(journal, token, RecordState::Confirmed)
    }

    /// Mark exactly the latest pending record bad, allowing fallback to an
    /// older eligible confirmed candidate.
    pub fn mark_bad(
        &self,
        journal: Journal,
        token: PendingToken,
    ) -> Result<Journal, SelectionError> {
        self.finish_pending(journal, token, RecordState::Bad)
    }

    fn finish_pending(
        &self,
        journal: Journal,
        token: PendingToken,
        state: RecordState,
    ) -> Result<Journal, SelectionError> {
        let parsed = journal.parse().map_err(|_| SelectionError::Recovery)?;
        let pending = parsed
            .latest_pending()
            .ok_or(SelectionError::Journal(JournalError::TokenMismatch))?;
        if pending.token() != token {
            return Err(SelectionError::Journal(JournalError::TokenMismatch));
        }
        let record_seq = next_record_seq(parsed.last)?;
        let frame = Frame {
            state,
            slot: pending.slot,
            attempt: pending.attempt,
            record_seq,
            boot_sequence: pending.boot_sequence,
            claim: pending.claim,
        };
        journal.append(frame).map_err(SelectionError::Journal)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum BootDecision {
    Pending(PendingTrial),
    Confirmed(ConfirmedBoot),
    Recovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingTrial {
    journal: Journal,
    token: PendingToken,
    facts: CandidateFacts,
}

impl PendingTrial {
    pub const fn journal(self) -> Journal {
        self.journal
    }

    pub const fn token(self) -> PendingToken {
        self.token
    }

    pub const fn slot(self) -> Slot {
        self.token.slot
    }

    pub const fn attempt(self) -> u8 {
        self.token.attempt
    }

    pub const fn candidate(self) -> CandidateFacts {
        self.facts
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfirmedBoot {
    slot: Slot,
    facts: CandidateFacts,
}

impl ConfirmedBoot {
    pub const fn slot(self) -> Slot {
        self.slot
    }

    pub const fn candidate(self) -> CandidateFacts {
        self.facts
    }
}

fn next_record_seq(previous: Option<Frame>) -> Result<u64, SelectionError> {
    match previous {
        Some(frame) => frame
            .record_seq
            .checked_add(1)
            .ok_or(SelectionError::Journal(JournalError::SequenceOverflow)),
        None => Ok(0),
    }
}

#[cfg(test)]
pub(crate) fn next_record_seq_for_test(previous: Option<Frame>) -> Result<u64, SelectionError> {
    next_record_seq(previous)
}
