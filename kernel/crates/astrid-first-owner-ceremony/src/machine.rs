//! Explicit private ceremony lifecycle and authority gate.

use crate::attestation::{
    DestructiveResetProof, OwnerRotationProof, PresenceAction, PresenceProof, RecoveryApproval,
    TwoPartyAttestation,
};
use crate::error::CeremonyError;
use crate::transcript::{Transcript, TranscriptInput};
use crate::types::{
    AnchorKey, DataKeyId, DeviceKey, MAX_RECOVERY_MEMBERS, MachineGeneration, PresenceKey,
    RecoveryPolicy,
};

/// Every persisted phase, including both required authority commit points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CeremonyPhase {
    Fresh,
    AnchorPending,
    GraphPending,
    GraphEnrolled,
    Enrolled,
}

/// Model authority is absent until the graph and anchor are both enrolled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authority {
    None,
    Owner(DeviceKey),
}

impl Authority {
    pub const fn owner(self) -> Option<DeviceKey> {
        match self {
            Self::None => None,
            Self::Owner(owner) => Some(owner),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyMachine {
    generation: MachineGeneration,
    data_key_id: DataKeyId,
    phase: CeremonyPhase,
    active_transcript: Option<Transcript>,
    pending_policy: Option<RecoveryPolicy>,
    owner: Option<DeviceKey>,
    anchor: Option<AnchorKey>,
    presence: Option<PresenceKey>,
    recovery_policy: Option<RecoveryPolicy>,
}

impl CeremonyMachine {
    pub fn new(generation: MachineGeneration, data_key_id: DataKeyId) -> Self {
        Self {
            generation,
            data_key_id,
            phase: CeremonyPhase::Fresh,
            active_transcript: None,
            pending_policy: None,
            owner: None,
            anchor: None,
            presence: None,
            recovery_policy: None,
        }
    }

    pub const fn generation(&self) -> MachineGeneration {
        self.generation
    }

    pub const fn data_key_id(&self) -> DataKeyId {
        self.data_key_id
    }

    pub const fn phase(&self) -> CeremonyPhase {
        self.phase
    }

    pub fn authority(&self) -> Authority {
        match self.owner {
            Some(owner) if self.phase == CeremonyPhase::Enrolled => Authority::Owner(owner),
            _ => Authority::None,
        }
    }

    pub const fn active_transcript(&self) -> Option<Transcript> {
        self.active_transcript
    }

    pub const fn anchor_key(&self) -> Option<AnchorKey> {
        self.anchor
    }

    pub const fn presence_key(&self) -> Option<PresenceKey> {
        self.presence
    }

    pub const fn recovery_policy(&self) -> Option<RecoveryPolicy> {
        self.recovery_policy
    }

    pub fn begin_anchor_pending(
        &mut self,
        input: TranscriptInput,
        policy: Option<RecoveryPolicy>,
        attestation: TwoPartyAttestation,
    ) -> Result<(), CeremonyError> {
        if self.phase != CeremonyPhase::Fresh {
            return Err(CeremonyError::NotFresh);
        }
        let transcript = Transcript::try_new(input)?;
        if transcript.generation() != self.generation {
            return Err(CeremonyError::TranscriptGeneration);
        }
        if transcript.data_key_id() != self.data_key_id {
            return Err(CeremonyError::TranscriptDataKey);
        }
        let policy_commitment = policy.map_or_else(
            crate::transcript::absent_recovery_commitment,
            RecoveryPolicy::commitment,
        );
        if policy_commitment != transcript.recovery_commitment()
            || transcript.has_recovery_policy() != policy.is_some()
        {
            return Err(CeremonyError::TranscriptPolicy);
        }
        attestation.verify(&transcript)?;
        self.phase = CeremonyPhase::AnchorPending;
        self.active_transcript = Some(transcript);
        self.pending_policy = policy;
        Ok(())
    }

    pub fn begin_graph_pending(&mut self) -> Result<(), CeremonyError> {
        if self.phase != CeremonyPhase::AnchorPending {
            return Err(CeremonyError::NotAnchorPending);
        }
        self.phase = CeremonyPhase::GraphPending;
        Ok(())
    }

    pub fn commit_graph(&mut self, attestation: TwoPartyAttestation) -> Result<(), CeremonyError> {
        let transcript = self
            .active_transcript
            .ok_or(CeremonyError::NotGraphPending)?;
        if self.phase != CeremonyPhase::GraphPending {
            return Err(CeremonyError::NotGraphPending);
        }
        attestation.verify(&transcript)?;
        self.phase = CeremonyPhase::GraphEnrolled;
        Ok(())
    }

    pub fn commit_anchor(&mut self, attestation: TwoPartyAttestation) -> Result<(), CeremonyError> {
        let transcript = self
            .active_transcript
            .ok_or(CeremonyError::NotGraphEnrolled)?;
        if self.phase != CeremonyPhase::GraphEnrolled {
            return Err(CeremonyError::NotGraphEnrolled);
        }
        attestation.verify(&transcript)?;
        self.phase = CeremonyPhase::Enrolled;
        self.owner = Some(transcript.owner_device_key());
        self.anchor = Some(transcript.anchor_key());
        self.presence = Some(transcript.presence_key());
        self.recovery_policy = self.pending_policy;
        Ok(())
    }

    pub fn rotate(
        &mut self,
        input: TranscriptInput,
        policy: Option<RecoveryPolicy>,
        attestation: TwoPartyAttestation,
        presence: PresenceProof,
        owner: OwnerRotationProof,
    ) -> Result<(), CeremonyError> {
        let current = self.enrolled_transcript()?;
        let next = self.valid_successor(
            input,
            policy,
            current,
            CeremonyError::TranscriptDataKey,
            CeremonyError::OwnerUnchanged,
        )?;
        attestation.verify(&next)?;
        presence.verify(
            current.presence_key().as_bytes(),
            PresenceAction::Rotate,
            &next,
        )?;
        owner.verify(current.owner_device_key().as_bytes(), &current, &next)?;

        self.generation = next.generation();
        self.phase = CeremonyPhase::Enrolled;
        self.active_transcript = Some(next);
        self.pending_policy = None;
        self.owner = Some(next.owner_device_key());
        self.anchor = Some(next.anchor_key());
        self.presence = Some(next.presence_key());
        self.recovery_policy = policy;
        Ok(())
    }

    pub fn recover_lost_owner(
        &mut self,
        input: TranscriptInput,
        attestation: TwoPartyAttestation,
        presence: PresenceProof,
        approvals: &[RecoveryApproval],
    ) -> Result<(), CeremonyError> {
        let current = self.enrolled_transcript()?;
        let Some(policy) = self.recovery_policy else {
            return Err(CeremonyError::PolicyRequired);
        };
        let next = self.valid_successor(
            input,
            Some(policy),
            current,
            CeremonyError::TranscriptDataKey,
            CeremonyError::OwnerUnchanged,
        )?;
        attestation.verify(&next)?;
        presence.verify(
            current.presence_key().as_bytes(),
            PresenceAction::Recover,
            &next,
        )?;
        if approvals.len() < usize::from(policy.threshold()) {
            return Err(CeremonyError::RecoveryApprovalsInvalid);
        }
        let mut used = [false; MAX_RECOVERY_MEMBERS];
        for approval in approvals {
            let mut member_index = 0;
            let mut enrolled = false;
            while member_index < MAX_RECOVERY_MEMBERS {
                if policy.member(member_index) == Some(approval.member()) {
                    enrolled = true;
                    break;
                }
                member_index += 1;
            }
            if !enrolled || used[member_index] {
                return Err(CeremonyError::RecoveryApprovalsInvalid);
            }
            used[member_index] = true;
            approval.verify(&current, &next)?;
        }

        self.generation = next.generation();
        self.phase = CeremonyPhase::Enrolled;
        self.active_transcript = Some(next);
        self.owner = Some(next.owner_device_key());
        Ok(())
    }

    pub fn destructive_reset(
        &mut self,
        reset: DestructiveResetProof,
    ) -> Result<DestroyedDataKey, CeremonyError> {
        let current = self.enrolled_transcript()?;
        if self.recovery_policy.is_some() {
            return Err(CeremonyError::PolicyRequired);
        }
        let next_data_key = reset.next_data_key_id();
        if next_data_key == self.data_key_id {
            return Err(CeremonyError::TranscriptDataKey);
        }
        reset.verify(current.presence_key().as_bytes(), &current)?;
        let next_generation = self.generation.next()?;
        let destroyed = DestroyedDataKey::destroy(self.data_key_id);

        self.generation = next_generation;
        self.data_key_id = next_data_key;
        self.phase = CeremonyPhase::Fresh;
        self.active_transcript = None;
        self.pending_policy = None;
        self.owner = None;
        self.anchor = None;
        self.presence = None;
        self.recovery_policy = None;
        Ok(destroyed)
    }

    fn enrolled_transcript(&self) -> Result<Transcript, CeremonyError> {
        if self.phase != CeremonyPhase::Enrolled {
            return Err(CeremonyError::NotEnrolled);
        }
        self.active_transcript.ok_or(CeremonyError::NotEnrolled)
    }

    fn valid_successor(
        &self,
        input: TranscriptInput,
        policy: Option<RecoveryPolicy>,
        current: Transcript,
        data_key_error: CeremonyError,
        owner_error: CeremonyError,
    ) -> Result<Transcript, CeremonyError> {
        let next = Transcript::try_new(input)?;
        if next.generation() != self.generation.next()? {
            return Err(CeremonyError::TranscriptGeneration);
        }
        if next.anchor_key() != current.anchor_key() {
            return Err(CeremonyError::TranscriptAnchor);
        }
        if next.presence_key() != current.presence_key() {
            return Err(CeremonyError::TranscriptPresence);
        }
        if next.data_key_id() != self.data_key_id {
            return Err(data_key_error);
        }
        if next.owner_device_key() == current.owner_device_key() {
            return Err(owner_error);
        }
        let policy_commitment = policy.map_or_else(
            crate::transcript::absent_recovery_commitment,
            RecoveryPolicy::commitment,
        );
        if policy_commitment != next.recovery_commitment()
            || next.has_recovery_policy() != policy.is_some()
        {
            return Err(CeremonyError::TranscriptPolicy);
        }
        Ok(next)
    }
}

/// Receipt for an old model data key after its last live-state reference ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DestroyedDataKey(DataKeyId);

impl DestroyedDataKey {
    pub(crate) fn destroy(id: DataKeyId) -> Self {
        Self(id)
    }

    pub const fn id(self) -> DataKeyId {
        self.0
    }
}
