//! Typed identities, event classes, and capacity derivation for the private
//! audit chain.

use core::num::NonZeroU64;

use blake3::Hasher;

use super::root;
use crate::ipc::DomainToken;

/// Restated landed #1705 protocol ceilings used for static capacity
/// derivation only. If the landed pools change, this derivation must be
/// recalculated before the audit relay remains sound (#1759 freeze).
pub(crate) const AUDIT_DOMAIN_SLOTS: usize = 2;
pub(crate) const AUDIT_CAP_SLOTS_PER_DOMAIN: usize = 8;
pub(crate) const AUDIT_ENDPOINT_POOL: usize = 4;
pub(crate) const AUDIT_CAP_OBJECT_POOL: usize = 16;
pub(crate) const AUDIT_QUEUES_PER_ENDPOINT: usize = 2;
/// Landed message payload ceiling. Audit payloads never exceed it.
pub(crate) const AUDIT_MAX_PAYLOAD: usize = 64;

const _: () = assert!(
    AUDIT_DOMAIN_SLOTS * AUDIT_CAP_SLOTS_PER_DOMAIN == AUDIT_CAP_OBJECT_POOL,
    "landed domain and capability pools disagree with the audit capacity derivation",
);

/// Maximum mandatory terminal/invalidation records one admitted atomic
/// mutation batch can produce at the frozen ceilings: mass invalidation of
/// every capability-instance slot of both domain slots, every endpoint, both
/// queues on every endpoint, and the dying domain identity itself. This is
/// the statically derived relay reserve, never a single global death slot.
pub(crate) const MAX_TERMINAL_RECORDS_PER_BATCH: usize = AUDIT_DOMAIN_SLOTS
    * AUDIT_CAP_SLOTS_PER_DOMAIN
    + AUDIT_ENDPOINT_POOL
    + AUDIT_ENDPOINT_POOL * AUDIT_QUEUES_PER_ENDPOINT
    + 1;

/// Boot-scoped audit session identity. A kernel restart mints a new identity;
/// this slice claims no cross-boot durable continuity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BootSessionId([u8; 16]);

impl BootSessionId {
    /// Rejects the all-zero identity so two boots can never share one chain.
    pub const fn new(bytes: [u8; 16]) -> Option<Self> {
        let mut index = 0;
        let mut any_nonzero = false;
        while index < bytes.len() {
            if bytes[index] != 0 {
                any_nonzero = true;
            }
            index += 1;
        }
        if any_nonzero { Some(Self(bytes)) } else { None }
    }

    pub const fn bytes(self) -> [u8; 16] {
        self.0
    }
}

const AUTHORITY_ROOT_DOMAIN: &[u8] = b"astrid.native-kernel.audit-authority-root.v1";
const AUTHORITY_ID_DOMAIN: &[u8] = b"astrid.native-kernel.audit-authority-id.v1";
const AUTHORITY_KEY_DOMAIN: &[u8] = b"astrid.native-kernel.audit-authority-key.v1";

/// Opaque kernel-owned authentication context. It is derived inside the
/// kernel from the live boot identity and cannot be constructed from
/// caller-selected bytes. Its authority id is part of every checkpoint tag.
///
/// The verification key stays kernel-side for the whole boot/session. It
/// reaches the verifier only through an independently trusted kernel-origin
/// channel that this unwired slice models by injection; the untrusted
/// handoff carries none of it. Production anchor delivery and key
/// lifecycle remain named #1759 residuals, and no fixed production secret
/// is introduced.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct CheckpointAuthContext {
    authority_id: u64,
    verification_key: [u8; 32],
}

impl CheckpointAuthContext {
    fn mint(boot: BootSessionId) -> Self {
        let mut id_hasher = Hasher::new();
        id_hasher.update(AUTHORITY_ROOT_DOMAIN);
        id_hasher.update(&boot.bytes());
        id_hasher.update(AUTHORITY_ID_DOMAIN);
        let id_digest: [u8; 32] = id_hasher.finalize().into();
        let mut authority_id = u64::from_le_bytes(id_digest[..8].try_into().unwrap());
        if authority_id == 0 {
            authority_id = 1;
        }

        let mut key_hasher = Hasher::new();
        key_hasher.update(AUTHORITY_ROOT_DOMAIN);
        key_hasher.update(&boot.bytes());
        key_hasher.update(AUTHORITY_KEY_DOMAIN);
        key_hasher.update(&authority_id.to_le_bytes());
        let verification_key: [u8; 32] = key_hasher.finalize().into();
        debug_assert!(verification_key != [0; 32]);
        Self {
            authority_id,
            verification_key,
        }
    }

    pub(crate) const fn authority_id(self) -> u64 {
        self.authority_id
    }

    pub(crate) const fn verification_key(self) -> [u8; 32] {
        self.verification_key
    }
}

impl core::fmt::Debug for CheckpointAuthContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CheckpointAuthContext(REDACTED)")
    }
}

/// Kernel-minted authority for one live boot/session. Its verifier handoff
/// is untrusted binding evidence: it names the authority and carries a
/// keyed minting tag, never verification material, so it cannot
/// authenticate itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuditAuthority {
    boot: BootSessionId,
    context: CheckpointAuthContext,
}

/// Fixed wire size of the untrusted verifier handoff binding: magic,
/// authority id, boot/session identity, and the keyed tag. No key material.
const VERIFIER_HANDOFF_BYTES: usize = 8 + 8 + 16 + root::ROOT_LEN;

impl AuditAuthority {
    pub fn mint(boot: BootSessionId) -> Self {
        Self {
            boot,
            context: CheckpointAuthContext::mint(boot),
        }
    }

    pub const fn boot(self) -> BootSessionId {
        self.boot
    }

    pub(crate) const fn context(self) -> CheckpointAuthContext {
        self.context
    }

    /// Untrusted binding evidence accepted by `native-audit-verifier`. It
    /// carries no verification material: the tag is checkable only against
    /// the independently trusted kernel-origin anchor, so a caller-minted
    /// handoff cannot authenticate itself. The private first-slice layout
    /// carries no production lifecycle provisioning claim.
    pub fn verifier_handoff(self) -> [u8; VERIFIER_HANDOFF_BYTES] {
        let mut handoff = [0; VERIFIER_HANDOFF_BYTES];
        handoff[..8].copy_from_slice(b"ASAUDCTX");
        handoff[8..16].copy_from_slice(&self.context.authority_id().to_le_bytes());
        handoff[16..32].copy_from_slice(&self.boot.bytes());
        let tag = root::verifier_handoff_tag(
            self.boot,
            self.context.authority_id(),
            &self.context.verification_key(),
        );
        handoff[32..].copy_from_slice(&tag);
        handoff
    }
}

/// Landed caller identity (#1705 `DomainToken`): domain slot plus generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuditSubject {
    slot: u8,
    generation: NonZeroU64,
}

impl AuditSubject {
    pub fn from_domain(token: DomainToken) -> Self {
        Self {
            slot: token.slot().index() as u8,
            generation: token.generation(),
        }
    }

    pub(crate) fn from_parts(slot: u8, generation: NonZeroU64) -> Option<Self> {
        if slot as usize >= AUDIT_DOMAIN_SLOTS {
            return None;
        }
        Some(Self { slot, generation })
    }

    pub const fn slot(self) -> u8 {
        self.slot
    }

    pub const fn generation(self) -> NonZeroU64 {
        self.generation
    }
}

/// Landed object kind (#1705 domain or endpoint object).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditObjectKind {
    Domain,
    Endpoint,
}

impl AuditObjectKind {
    pub(crate) const fn from_discriminant(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Domain),
            2 => Some(Self::Endpoint),
            _ => None,
        }
    }

    pub(crate) const fn discriminant(self) -> u8 {
        match self {
            Self::Domain => 1,
            Self::Endpoint => 2,
        }
    }
}

/// Typed object identity for one frame. Values restate the landed #1705 and
/// #1758 identity fields through ceiling-enforced constructors; this is
/// attribution encoding, not a parallel identity authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditObject {
    Domain {
        slot: u8,
        generation: NonZeroU64,
    },
    Endpoint {
        pool_index: u8,
        generation: NonZeroU64,
    },
    CapabilityInstance(AuditCapabilityInstance),
}

impl AuditObject {
    pub fn domain(slot: usize, generation: u64) -> Option<Self> {
        if slot >= AUDIT_DOMAIN_SLOTS {
            return None;
        }
        Some(Self::Domain {
            slot: slot as u8,
            generation: NonZeroU64::new(generation)?,
        })
    }

    pub fn endpoint(pool_index: usize, generation: u64) -> Option<Self> {
        if pool_index >= AUDIT_ENDPOINT_POOL {
            return None;
        }
        Some(Self::Endpoint {
            pool_index: pool_index as u8,
            generation: NonZeroU64::new(generation)?,
        })
    }

    pub fn capability_instance(
        projection_token: u64,
        capability_slot: usize,
        capability_generation: u64,
        object_kind: AuditObjectKind,
        object_token: u64,
    ) -> Option<Self> {
        Some(Self::CapabilityInstance(AuditCapabilityInstance::try_new(
            projection_token,
            capability_slot,
            capability_generation,
            object_kind,
            object_token,
        )?))
    }
}

/// Full landed #1758 capability-instance identity restated for attribution:
/// kernel-issued projection token, capability-table slot, capability/object
/// generations, and the held object identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuditCapabilityInstance {
    projection_token: NonZeroU64,
    capability_slot: u8,
    capability_generation: NonZeroU64,
    object_kind: AuditObjectKind,
    object_token: NonZeroU64,
}

impl AuditCapabilityInstance {
    pub fn try_new(
        projection_token: u64,
        capability_slot: usize,
        capability_generation: u64,
        object_kind: AuditObjectKind,
        object_token: u64,
    ) -> Option<Self> {
        // Landed #1758 capability-instance projections name Endpoint objects
        // only; a Domain identity is attribution, not the held object.
        if capability_slot >= AUDIT_CAP_SLOTS_PER_DOMAIN || object_kind != AuditObjectKind::Endpoint
        {
            return None;
        }
        Some(Self {
            projection_token: NonZeroU64::new(projection_token)?,
            capability_slot: capability_slot as u8,
            capability_generation: NonZeroU64::new(capability_generation)?,
            object_kind,
            object_token: NonZeroU64::new(object_token)?,
        })
    }

    pub const fn projection_token(self) -> NonZeroU64 {
        self.projection_token
    }

    pub const fn capability_slot(self) -> u8 {
        self.capability_slot
    }

    pub const fn capability_generation(self) -> NonZeroU64 {
        self.capability_generation
    }

    pub const fn object_kind(self) -> AuditObjectKind {
        self.object_kind
    }

    pub const fn object_token(self) -> NonZeroU64 {
        self.object_token
    }
}

/// Landed #1705 rights bits (`SEND=1 RECV=2 GRANT=4 IDENTIFY=8`). Unknown
/// bits fail closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AuditRights(u16);

impl AuditRights {
    const LANDED_RIGHTS_MASK: u16 = 0b1111;

    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::LANDED_RIGHTS_MASK == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }
}

/// Typed denial reason. Denials never disclose a foreign object identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DenialReason {
    StaleIdentity = 1,
    MissingCapability = 2,
    RightsInsufficient = 3,
    ForeignObject = 4,
    CapacityExhausted = 5,
    MalformedRequest = 6,
}

impl DenialReason {
    pub(crate) const fn from_discriminant(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::StaleIdentity),
            2 => Some(Self::MissingCapability),
            3 => Some(Self::RightsInsufficient),
            4 => Some(Self::ForeignObject),
            5 => Some(Self::CapacityExhausted),
            6 => Some(Self::MalformedRequest),
            _ => None,
        }
    }

    pub(crate) const fn discriminant(self) -> u16 {
        match self {
            Self::StaleIdentity => 1,
            Self::MissingCapability => 2,
            Self::RightsInsufficient => 3,
            Self::ForeignObject => 4,
            Self::CapacityExhausted => 5,
            Self::MalformedRequest => 6,
        }
    }
}

/// Caller-visible denial context: one typed reason plus a bounded caller
/// stamp. The canonical payload is `reason: u16` little-endian, then 8 stamp
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DenialContext {
    reason: DenialReason,
    stamp: [u8; 8],
}

impl DenialContext {
    pub(crate) const PAYLOAD_LEN: usize = 10;

    pub const fn new(reason: DenialReason, stamp: [u8; 8]) -> Self {
        Self { reason, stamp }
    }

    pub(crate) fn payload_bytes(self) -> [u8; Self::PAYLOAD_LEN] {
        let reason = self.reason.discriminant().to_le_bytes();
        let mut out = [0u8; Self::PAYLOAD_LEN];
        out[0] = reason[0];
        out[1] = reason[1];
        out[2..].copy_from_slice(&self.stamp);
        out
    }

    pub(crate) fn from_payload(payload: &[u8]) -> Option<Self> {
        if payload.len() != Self::PAYLOAD_LEN {
            return None;
        }
        let reason = u16::from_le_bytes([payload[0], payload[1]]);
        let mut stamp = [0u8; 8];
        stamp.copy_from_slice(&payload[2..]);
        Some(Self {
            reason: DenialReason::from_discriminant(reason)?,
            stamp,
        })
    }

    pub const fn reason(self) -> DenialReason {
        self.reason
    }

    pub const fn stamp(self) -> [u8; 8] {
        self.stamp
    }
}

/// Security-event class. Discriminant groups follow the #1759 freeze: domain
/// lifecycle, capability, IPC, generation, root, and bounded denial.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditClass {
    DomainCreate = 1,
    DomainAdmit = 2,
    DomainStart = 3,
    DomainEnter = 4,
    DomainExit = 5,
    DomainFault = 6,
    DomainKill = 7,
    DomainReclaim = 8,
    DomainCancel = 9,
    CapabilityDerive = 16,
    CapabilityGrant = 17,
    CapabilityRevoke = 18,
    IpcSend = 32,
    IpcRecv = 33,
    IpcQueueDrop = 34,
    IpcEndpointTeardown = 35,
    GenerationAdvance = 48,
    GenerationReject = 49,
    GenerationOverflow = 50,
    RootCheckpoint = 64,
    RootOverflow = 65,
    RootIncomplete = 66,
    BoundedDenial = 80,
}

impl AuditClass {
    pub(crate) const fn from_discriminant(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::DomainCreate),
            2 => Some(Self::DomainAdmit),
            3 => Some(Self::DomainStart),
            4 => Some(Self::DomainEnter),
            5 => Some(Self::DomainExit),
            6 => Some(Self::DomainFault),
            7 => Some(Self::DomainKill),
            8 => Some(Self::DomainReclaim),
            9 => Some(Self::DomainCancel),
            16 => Some(Self::CapabilityDerive),
            17 => Some(Self::CapabilityGrant),
            18 => Some(Self::CapabilityRevoke),
            32 => Some(Self::IpcSend),
            33 => Some(Self::IpcRecv),
            34 => Some(Self::IpcQueueDrop),
            35 => Some(Self::IpcEndpointTeardown),
            48 => Some(Self::GenerationAdvance),
            49 => Some(Self::GenerationReject),
            50 => Some(Self::GenerationOverflow),
            64 => Some(Self::RootCheckpoint),
            65 => Some(Self::RootOverflow),
            66 => Some(Self::RootIncomplete),
            80 => Some(Self::BoundedDenial),
            _ => None,
        }
    }

    pub(crate) const fn discriminant(self) -> u16 {
        self as u16
    }

    /// Classes whose relay records participate in the statically reserved
    /// terminal/invalidation headroom. Ordinary records cannot consume the
    /// headroom needed by one admitted atomic teardown batch.
    pub(crate) const fn is_terminal_or_invalidation(self) -> bool {
        matches!(
            self,
            Self::DomainKill
                | Self::DomainReclaim
                | Self::DomainCancel
                | Self::CapabilityRevoke
                | Self::IpcQueueDrop
                | Self::IpcEndpointTeardown
                | Self::GenerationOverflow
                | Self::RootOverflow
                | Self::RootIncomplete
        )
    }
}

/// One typed audit event before canonical encoding. Construction is
/// fallible where a ceiling applies, so a frame can never encode a value the
/// landed pools cannot produce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    class: AuditClass,
    subject: AuditSubject,
    object: Option<AuditObject>,
    rights: AuditRights,
    payload: [u8; AUDIT_MAX_PAYLOAD],
    payload_len: usize,
}

impl AuditEvent {
    pub fn new(class: AuditClass, subject: AuditSubject) -> Self {
        Self {
            class,
            subject,
            object: None,
            rights: AuditRights::from_bits(0).expect("zero is a valid rights mask"),
            payload: [0; AUDIT_MAX_PAYLOAD],
            payload_len: 0,
        }
    }

    pub fn with_object(mut self, object: AuditObject) -> Option<Self> {
        if self.class == AuditClass::BoundedDenial {
            return None;
        }
        self.object = Some(object);
        Some(self)
    }

    pub fn with_rights(mut self, rights: AuditRights) -> Self {
        self.rights = rights;
        self
    }

    pub fn with_payload(mut self, payload: &[u8]) -> Option<Self> {
        if payload.len() > AUDIT_MAX_PAYLOAD {
            return None;
        }
        self.payload = [0; AUDIT_MAX_PAYLOAD];
        self.payload[..payload.len()].copy_from_slice(payload);
        self.payload_len = payload.len();
        Some(self)
    }

    /// A bounded denial under caller-visible/stamped context. The object
    /// stays absent: an unauthorized attempt must not disclose foreign
    /// object identity through the verifier projection.
    pub fn denial(subject: AuditSubject, context: DenialContext) -> Self {
        let payload = context.payload_bytes();
        Self {
            class: AuditClass::BoundedDenial,
            subject,
            object: None,
            rights: AuditRights::from_bits(0).expect("zero is a valid rights mask"),
            payload: [0; AUDIT_MAX_PAYLOAD],
            payload_len: 0,
        }
        .with_payload(&payload)
        .expect("denial payload fits the landed ceiling")
    }

    pub const fn class(self) -> AuditClass {
        self.class
    }

    pub const fn subject(self) -> AuditSubject {
        self.subject
    }

    pub const fn object(self) -> Option<AuditObject> {
        self.object
    }

    pub const fn rights(self) -> AuditRights {
        self.rights
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }
}

/// Kernel-authenticated restart checkpoint bound to boot/session identity,
/// exact `audit_seq`, root, codec version, and relay generation. A
/// verifier-local cache alone is never a trusted checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditCheckpoint {
    boot: BootSessionId,
    seq: u64,
    root: [u8; root::ROOT_LEN],
    codec_version: u16,
    relay_generation: u64,
    authority_id: u64,
    tag: [u8; root::ROOT_LEN],
}

impl AuditCheckpoint {
    pub(crate) fn seal(
        boot: BootSessionId,
        seq: u64,
        root: [u8; root::ROOT_LEN],
        relay_generation: u64,
        context: CheckpointAuthContext,
    ) -> Result<Self, AuditError> {
        if relay_generation == 0 || context.authority_id() == 0 {
            return Err(AuditError::MalformedFrame);
        }
        let codec_version = super::CODEC_VERSION;
        let tag = root::checkpoint_tag(boot, seq, root, relay_generation, &context);
        Ok(Self {
            boot,
            seq,
            root,
            codec_version,
            relay_generation,
            authority_id: context.authority_id(),
            tag,
        })
    }

    pub(crate) fn verify_tag(&self, context: CheckpointAuthContext) -> bool {
        if self.authority_id != context.authority_id() {
            return false;
        }
        root::checkpoint_tag(
            self.boot,
            self.seq,
            self.root,
            self.relay_generation,
            &context,
        ) == self.tag
    }

    pub const fn boot(self) -> BootSessionId {
        self.boot
    }

    pub const fn seq(self) -> u64 {
        self.seq
    }

    pub const fn root(self) -> [u8; root::ROOT_LEN] {
        self.root
    }

    pub const fn codec_version(self) -> u16 {
        self.codec_version
    }

    pub const fn relay_generation(self) -> u64 {
        self.relay_generation
    }

    pub const fn authority_id(self) -> u64 {
        self.authority_id
    }

    pub const fn tag(self) -> [u8; root::ROOT_LEN] {
        self.tag
    }
}

/// Fail-closed audit errors. None of these are recoverable by wraparound or
/// silent omission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditError {
    SequenceOverflow,
    RelayGenerationOverflow,
    PayloadTooLarge,
    EncodeOverflow,
    MalformedFrame,
    UnauthorizedDisclosure,
    RootMismatch,
    CheckpointMismatch,
    RelayWindowOverflow,
    RelayInvalidCursor,
    RelayStaleCursor,
    RelayNotInFlight,
    HandoffIncomplete,
    BatchCapacityExhausted,
}

impl core::fmt::Display for AuditError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::SequenceOverflow => "audit sequence overflow",
            Self::RelayGenerationOverflow => "relay generation overflow",
            Self::PayloadTooLarge => "payload exceeds the landed ceiling",
            Self::EncodeOverflow => "canonical frame exceeds the fixed bound",
            Self::MalformedFrame => "malformed canonical frame",
            Self::UnauthorizedDisclosure => "denial frame discloses a foreign identity",
            Self::RootMismatch => "rolling root mismatch",
            Self::CheckpointMismatch => "checkpoint authentication mismatch",
            Self::RelayWindowOverflow => "relay window overflow",
            Self::RelayInvalidCursor => "relay cursor invalid",
            Self::RelayStaleCursor => "relay cursor stale",
            Self::RelayNotInFlight => "relay record is not in flight",
            Self::HandoffIncomplete => "audit handoff is incomplete and requires resync",
            Self::BatchCapacityExhausted => "batch exceeds the static terminal reserve",
        };
        f.write_str(text)
    }
}
