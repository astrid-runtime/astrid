//! Private request/reply registry for typed runtime elicitation.
//!
//! It delivers typed input, a secret, or cancellation to the
//! originating host waiter through a oneshot. It never persists secrets, never
//! talks to `SecretStore`, and never publishes on the elicit bus. The host
//! keeps `invocation_authority_active` and stores at the existing mutation
//! edge after the waiter returns.
//!
//! Capacity is caller-supplied; daemon composition uses the existing configured
//! pending-request limit rather than a separate in-crate ceiling.
//!
//! Identity matching is correlation only, not authentication. The native
//! responder supplies verified caller identity; the slot owns its destination.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::oneshot;
use uuid::Uuid;
use zeroize::Zeroizing;

use astrid_core::principal::PrincipalId;

use crate::capsule::CapsuleId;

#[cfg(test)]
mod tests;

/// Correlation id for one in-flight secret elicit. Single-use.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecretElicitId(Uuid);

impl SecretElicitId {
    /// Decode a correlation id. Possession of an id grants no authority.
    #[must_use]
    pub const fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    fn generate() -> Self {
        Self(Uuid::new_v4())
    }

    /// Underlying UUID, for later admin complete wiring.
    #[must_use]
    pub const fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for SecretElicitId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Public env/secret key name captured as slot metadata. Not a secret value.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct SecretElicitKey(String);

impl SecretElicitKey {
    /// Reject empty names. Charset policy stays with the host/manifest.
    ///
    /// # Errors
    ///
    /// Returns [`SecretElicitError::EmptyKey`] when `key` is empty so a
    /// blank name cannot be used as slot identity.
    pub fn new(key: impl Into<String>) -> Result<Self, SecretElicitError> {
        let key = key.into();
        if key.is_empty() {
            return Err(SecretElicitError::EmptyKey);
        }
        Ok(Self(key))
    }

    /// Borrow the key name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Immutable public identity bound into a slot at register time.
///
/// Matching this tuple is not authentication. Completers must pass an
/// already-verified identity; the registry only rejects a mismatched
/// tuple so it cannot consume the live slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretElicitIdentity {
    principal: PrincipalId,
    capsule: CapsuleId,
    key: SecretElicitKey,
}

impl SecretElicitIdentity {
    /// Capture the public tuple. No secret snapshot is stored.
    #[must_use]
    pub fn new(principal: PrincipalId, capsule: CapsuleId, key: SecretElicitKey) -> Self {
        Self {
            principal,
            capsule,
            key,
        }
    }

    /// Principal that must complete or cancel this slot.
    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Capsule that must complete or cancel this slot.
    #[must_use]
    pub fn capsule(&self) -> &CapsuleId {
        &self.capsule
    }

    /// Public key name that must complete or cancel this slot.
    #[must_use]
    pub fn key(&self) -> &SecretElicitKey {
        &self.key
    }
}

/// Expected answer shape captured when the host opens a slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ElicitAnswerKind {
    /// Ordinary single string; empty is valid and distinct from cancel.
    Text,
    /// Non-empty secret; empty is invalid and does not consume the slot.
    Secret,
    /// Single string that must be an exact option member.
    Select(Vec<String>),
    /// String list; empty list is valid and distinct from cancel.
    Array,
}

/// Secret bytes delivered to the originating waiter. Never logged or serialized.
pub struct SecretValue(Zeroizing<String>);

impl SecretValue {
    /// Reject empty secrets. The host still decides whether to store.
    ///
    /// # Errors
    ///
    /// Returns [`SecretElicitError::EmptySecret`] when `value` is empty.
    pub fn try_new(value: impl Into<String>) -> Result<Self, SecretElicitError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() {
            return Err(SecretElicitError::EmptySecret);
        }
        Ok(Self(value))
    }

    /// Borrow for the host mutation edge. Callers must not log this.
    #[must_use]
    pub fn expose_as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue([REDACTED])")
    }
}

/// Outcome delivered to the originating host waiter.
pub enum SecretElicitReply {
    /// Secret for the host to store after retirement/authority checks.
    Provided(SecretValue),
    /// Ordinary single-string answer, including empty text.
    Value(String),
    /// Ordinary list answer, including an empty list.
    Values(Vec<String>),
    /// Explicit cancel (UI Escape, unload). Not [`SecretElicitError::EmptySecret`].
    Cancelled,
}

impl fmt::Debug for SecretElicitReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provided(_) => f.write_str("Provided([REDACTED])"),
            Self::Value(_) => f.write_str("Value(..)"),
            Self::Values(_) => f.write_str("Values(..)"),
            Self::Cancelled => f.write_str("Cancelled"),
        }
    }
}

/// Fail-closed registry errors. Identity mismatch does not consume a slot.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum SecretElicitError {
    /// Caller-supplied capacity is fully occupied.
    #[error("secret elicit registry is at capacity")]
    AtCapacity,
    /// No live slot for this id (unknown, already completed, dropped, or
    /// the waiter is gone so delivery failed).
    #[error("secret elicit request is unknown")]
    UnknownRequest,
    /// Completer identity did not match the captured tuple; slot remains.
    /// This is a correlation check, not authentication.
    #[error("secret elicit identity does not match the pending request")]
    IdentityMismatch,
    /// Empty secret value. Cancellation is a different path.
    #[error("secret elicit value must not be empty")]
    EmptySecret,
    /// Empty public key name. Not a secret value.
    #[error("secret elicit key must not be empty")]
    EmptyKey,
    /// Answer shape or select membership did not match; slot remains.
    #[error("secret elicit answer does not match the pending request")]
    InvalidAnswer,
}

/// Private in-flight secret elicit slots.
pub struct PendingSecretElicits {
    slots: Mutex<HashMap<SecretElicitId, Slot>>,
    capacity: usize,
    principals: Option<HashSet<PrincipalId>>,
}

struct Slot {
    identity: SecretElicitIdentity,
    expected: ElicitAnswerKind,
    tx: oneshot::Sender<SecretElicitReply>,
}

/// RAII waiter. Drop, timeout of [`Self::recv`], abort, and unload
/// release the slot.
#[must_use = "dropping the wait cancels the pending secret elicit"]
pub struct SecretElicitWait {
    id: SecretElicitId,
    identity: SecretElicitIdentity,
    registry: Arc<PendingSecretElicits>,
    rx: Option<oneshot::Receiver<SecretElicitReply>>,
}

impl PendingSecretElicits {
    /// Bound in-flight slots by `capacity`. No default const ceiling.
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            capacity: capacity.get(),
            principals: None,
        }
    }

    /// Restrict native routing to an immutable operator-selected principal set.
    #[must_use]
    pub fn for_principals(capacity: NonZeroUsize, principals: HashSet<PrincipalId>) -> Self {
        Self {
            principals: Some(principals),
            ..Self::new(capacity)
        }
    }

    /// Whether this principal uses the private path. Other principals retain
    /// their existing transport; a disconnected native responder is not fallback.
    #[must_use]
    pub fn routes_principal(&self, principal: &PrincipalId) -> bool {
        self.principals
            .as_ref()
            .is_none_or(|principals| principals.contains(principal))
    }

    /// Open a secret slot and return the host-side waiter.
    ///
    /// # Errors
    ///
    /// Returns [`SecretElicitError::AtCapacity`] when `capacity` slots are live.
    pub fn register(
        self: &Arc<Self>,
        identity: SecretElicitIdentity,
    ) -> Result<SecretElicitWait, SecretElicitError> {
        self.register_kind(identity, ElicitAnswerKind::Secret)
    }

    /// Open a slot for a captured answer kind and return the host-side waiter.
    ///
    /// # Errors
    ///
    /// Returns [`SecretElicitError::AtCapacity`] when `capacity` slots are live.
    pub fn register_kind(
        self: &Arc<Self>,
        identity: SecretElicitIdentity,
        expected: ElicitAnswerKind,
    ) -> Result<SecretElicitWait, SecretElicitError> {
        if !self.routes_principal(identity.principal()) {
            return Err(SecretElicitError::IdentityMismatch);
        }
        let (tx, rx) = oneshot::channel();
        let id = SecretElicitId::generate();
        let wait_identity = identity.clone();
        {
            let mut slots = self.slots.lock();
            if slots.len() >= self.capacity {
                return Err(SecretElicitError::AtCapacity);
            }
            slots.insert(
                id,
                Slot {
                    identity,
                    expected,
                    tx,
                },
            );
        }
        Ok(SecretElicitWait {
            id,
            identity: wait_identity,
            registry: Arc::clone(self),
            rx: Some(rx),
        })
    }

    /// Deliver a secret to the originating waiter. Does not store it.
    ///
    /// `identity` is caller-supplied correlation, not authentication. Later
    /// admin wiring must pass a verified principal/capsule/key.
    ///
    /// # Errors
    ///
    /// * [`SecretElicitError::UnknownRequest`] if the id is gone or the
    ///   waiter dropped before delivery.
    /// * [`SecretElicitError::IdentityMismatch`] if the tuple does not match;
    ///   the slot is left in place.
    /// * [`SecretElicitError::EmptySecret`] if `secret` is empty; the slot is
    ///   left in place.
    /// * [`SecretElicitError::InvalidAnswer`] if the slot is not a secret.
    pub fn complete(
        &self,
        id: SecretElicitId,
        identity: &SecretElicitIdentity,
        secret: String,
    ) -> Result<(), SecretElicitError> {
        let secret = Zeroizing::new(secret);
        let slot = {
            let mut slots = self.slots.lock();
            let Some(slot) = slots.remove(&id) else {
                return Err(SecretElicitError::UnknownRequest);
            };
            if &slot.identity != identity {
                slots.insert(id, slot);
                return Err(SecretElicitError::IdentityMismatch);
            }
            if !matches!(slot.expected, ElicitAnswerKind::Secret) {
                slots.insert(id, slot);
                return Err(SecretElicitError::InvalidAnswer);
            }
            if secret.is_empty() {
                slots.insert(id, slot);
                return Err(SecretElicitError::EmptySecret);
            }
            slot
        };
        send_or_unknown(slot, SecretElicitReply::Provided(SecretValue(secret)))
    }

    /// Complete the waiter with cancellation, not invalid input.
    ///
    /// Same identity-correlation rule as [`Self::complete`].
    ///
    /// # Errors
    ///
    /// Same unknown/mismatch rules as [`Self::complete`]. Mismatch does not
    /// consume the slot. Failed delivery (waiter gone) is
    /// [`SecretElicitError::UnknownRequest`].
    pub fn cancel(
        &self,
        id: SecretElicitId,
        identity: &SecretElicitIdentity,
    ) -> Result<(), SecretElicitError> {
        let slot = self.take_matching(id, identity)?;
        send_or_unknown(slot, SecretElicitReply::Cancelled)
    }

    /// Runtime shutdown: cancel every waiter and release every slot.
    /// Individual capsule retirement must instead drop its own waiter, so it
    /// cannot cancel unrelated principals' or capsules' requests.
    pub fn cancel_all(&self) {
        let slots: HashMap<SecretElicitId, Slot> = {
            let mut guard = self.slots.lock();
            std::mem::take(&mut *guard)
        };
        for slot in slots.into_values() {
            let _ = slot.tx.send(SecretElicitReply::Cancelled);
        }
    }

    /// Deliver a reply using only a previously authorized principal and the
    /// request id. Capsule and key are resolved from the original host slot,
    /// never from client-supplied destination fields.
    ///
    /// The caller must authenticate and authorize its responder device first.
    /// This method enforces request ownership, not human presence.
    ///
    /// # Errors
    /// Rejects unknown/finished requests, a different principal, an empty
    /// secret, or an answer that does not match the captured kind. Rejection
    /// leaves a live rightful request available.
    pub fn reply_for_principal(
        &self,
        id: SecretElicitId,
        principal: &PrincipalId,
        value: Option<String>,
        values: Option<Vec<String>>,
    ) -> Result<(), SecretElicitError> {
        let value = value.map(Zeroizing::new);
        let (slot, reply) = {
            let mut slots = self.slots.lock();
            let slot = slots.get(&id).ok_or(SecretElicitError::UnknownRequest)?;
            if slot.identity.principal() != principal {
                return Err(SecretElicitError::IdentityMismatch);
            }
            let reply = classify_answer(&slot.expected, value, values)?;
            let slot = slots.remove(&id).ok_or(SecretElicitError::UnknownRequest)?;
            (slot, reply)
        };
        send_or_unknown(slot, reply)
    }

    fn take_matching(
        &self,
        id: SecretElicitId,
        identity: &SecretElicitIdentity,
    ) -> Result<Slot, SecretElicitError> {
        let mut slots = self.slots.lock();
        let Some(slot) = slots.remove(&id) else {
            return Err(SecretElicitError::UnknownRequest);
        };
        if &slot.identity != identity {
            slots.insert(id, slot);
            return Err(SecretElicitError::IdentityMismatch);
        }
        Ok(slot)
    }

    fn abandon(&self, id: SecretElicitId) {
        drop(self.slots.lock().remove(&id));
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.slots.lock().len()
    }
}

fn classify_answer(
    expected: &ElicitAnswerKind,
    value: Option<Zeroizing<String>>,
    values: Option<Vec<String>>,
) -> Result<SecretElicitReply, SecretElicitError> {
    match (value, values, expected) {
        (Some(_), Some(_), _) => Err(SecretElicitError::InvalidAnswer),
        (None, None, _) => Ok(SecretElicitReply::Cancelled),
        (Some(value), None, ElicitAnswerKind::Secret) if value.is_empty() => {
            Err(SecretElicitError::EmptySecret)
        },
        (Some(value), None, ElicitAnswerKind::Secret) => {
            Ok(SecretElicitReply::Provided(SecretValue(value)))
        },
        (Some(value), None, ElicitAnswerKind::Text) => {
            Ok(SecretElicitReply::Value(value.to_string()))
        },
        (Some(value), None, ElicitAnswerKind::Select(options))
            if options.iter().any(|option| option == value.as_str()) =>
        {
            Ok(SecretElicitReply::Value(value.to_string()))
        },
        (None, Some(values), ElicitAnswerKind::Array) => Ok(SecretElicitReply::Values(values)),
        (Some(_), None, _) | (None, Some(_), _) => Err(SecretElicitError::InvalidAnswer),
    }
}

fn send_or_unknown(slot: Slot, reply: SecretElicitReply) -> Result<(), SecretElicitError> {
    slot.tx
        .send(reply)
        .map_err(|_| SecretElicitError::UnknownRequest)
}

impl SecretElicitWait {
    /// Slot id presented to a later completer.
    #[must_use]
    pub fn id(&self) -> SecretElicitId {
        self.id
    }

    /// Captured public identity for this waiter.
    #[must_use]
    pub fn identity(&self) -> &SecretElicitIdentity {
        &self.identity
    }

    /// Block until complete, cancel, or this waiter is dropped.
    ///
    /// Consumes the RAII guard so timeout or abort of the returned future
    /// drops the slot automatically.
    pub async fn recv(mut self) -> SecretElicitReply {
        let Some(rx) = self.rx.take() else {
            return SecretElicitReply::Cancelled;
        };
        rx.await.unwrap_or(SecretElicitReply::Cancelled)
    }
}

impl Drop for SecretElicitWait {
    fn drop(&mut self) {
        self.registry.abandon(self.id);
    }
}

impl fmt::Debug for SecretElicitWait {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretElicitWait")
            .field("id", &self.id)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}
