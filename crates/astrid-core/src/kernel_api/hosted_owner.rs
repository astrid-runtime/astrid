//! Direct native controls. These are not event-bus kernel requests.

use crate::identity::hosted_owner::{HostedOwnerChallenge, HostedOwnerEnvelope, HostedOwnerPolicy};
use crate::{FleetIdentity, FleetUid, PrincipalUid, UserIdentity, UserUid};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Historical one-shot outcome; reading it never refreshes device authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedOwnerCompletion {
    /// Enrolled `AFOv1` canonical digest.
    pub request_digest: [u8; 32],
    /// Original human authority.
    pub user: UserUid,
    /// Original fleet.
    pub fleet: FleetUid,
    /// Original target principal.
    pub principal: PrincipalUid,
    /// Original delegation incarnation, never recreated by replay.
    pub binding_generation: Uuid,
}

/// Direct socket request bound to an independently authenticated connection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostedOwnerRequest {
    /// Read the already-running daemon; never implicitly initialize anything.
    Inspect {},
    /// Obtain unsigned facts for external owner and deployment authorization.
    Challenge {
        /// Prospective owner genesis.
        user: UserIdentity,
        /// Prospective fleet genesis.
        fleet: FleetIdentity,
        /// Desired finite authorization expiry, bounded by installed policy.
        expires_at: u64,
    },
    /// Persist verified Pending, then atomically complete or return historical result.
    Provision {
        /// Independently signed public evidence; never a secret/path.
        envelope: Box<HostedOwnerEnvelope>,
    },
    /// Invalidate the target device's pending challenge and signed statement.
    Cancel {},
}

/// Public result vocabulary. Transport errors never echo request data.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostedOwnerResponse {
    /// Actual durable facts from the current daemon.
    Inspected {
        /// Durable phase, without inventing an offline Unenrolled result.
        enrollment: HostedEnrollmentPhase,
        /// Host-administered deployment policy if explicitly installed.
        policy: Option<HostedOwnerPolicy>,
        /// Stable installation if explicitly configured.
        installation: Option<Uuid>,
        /// Existing one-shot historical result, if committed.
        completion: Option<HostedOwnerCompletion>,
    },
    /// Public signing packet.
    Challenge {
        /// Frozen `AFOv1` statement with hosted context commitments.
        challenge: Box<HostedOwnerChallenge>,
    },
    /// One-shot commit result, not a new grant on replay.
    Enrolled {
        /// Durable completion result.
        completion: HostedOwnerCompletion,
    },
    /// Pending evidence cancelled and authority counters advanced.
    Cancelled,
}

/// Public durable enrollment phase.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedEnrollmentPhase {
    /// No owner.
    Unenrolled,
    /// Verified evidence, no ownership grant yet.
    Pending,
    /// First owner committed.
    Enrolled,
    /// Previous standalone claim cancelled.
    Cancelled,
}
