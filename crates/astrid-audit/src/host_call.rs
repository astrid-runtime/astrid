//! Host-call records written by the kernel's host-audit lane.
//!
//! Capsule host calls (fs, net, process) reach the audit chain through an
//! ordered, per-chain lane in the kernel. The lane records consecutive calls
//! of one principal as a single entry and accounts for calls it could not
//! record individually. The types here are the signed payload of those
//! entries; they live in this crate so a verifier can check them without the
//! kernel.
//!
//! # Call digest
//!
//! Every host call has a digest over the fields a single-call entry records.
//! `lp(b)` is `b` prefixed by its length as a big-endian `u64`:
//!
//! ```text
//! call_digest = BLAKE3(
//!     lp("astrid.audit.host-call.v1")
//!  || lp(class)                   // see `host_call_class`
//!  || class fields                // see below
//!  || u8(outcome)                 // 0 = ok, 1 = failed, 2 = denied
//!  || lp(detail)                  // error or denial reason; empty for ok
//!  || i64_be(unix_seconds) || u32_be(subsec_nanos)   // event time
//! )
//!
//! file_read, file_delete:  lp(path)
//! file_write:              lp(path) || content_hash (32 bytes)
//! net_connect:             lp(host) || u16_be(port)
//! net_bind:                lp(addr)
//! net_accept:              lp(local_addr) || lp(peer_addr)
//! process_spawn:           lp(command)
//! ```
//!
//! Strings are the values a single-call entry would store, i.e. after the
//! kernel bounds guest-controlled strings.
//!
//! # Fold
//!
//! A run of `n` calls commits to all of them, in call order:
//!
//! ```text
//! fold_0 = 32 zero bytes
//! fold_i = BLAKE3(lp("astrid.audit.host-call-fold.v1") || fold_{i-1} || call_digest_i)
//! ```
//!
//! [`HostCallSummary::fold`] is `fold_n` and [`HostCallSummary::count`] is
//! `n`. Given the individual calls, [`HostCallSummary::matches_calls`]
//! recomputes both.

use astrid_core::Timestamp;
use astrid_crypto::ContentHash;
use serde::{Deserialize, Serialize};

use crate::entry::AuditAction;

/// Domain separator of a single call's digest.
pub const HOST_CALL_DIGEST_DOMAIN: &str = "astrid.audit.host-call.v1";
/// Domain separator of one fold step.
pub const HOST_CALL_FOLD_DOMAIN: &str = "astrid.audit.host-call-fold.v1";

/// Host-call classes, in the spelling used by digests, tallies and the
/// `audit.host_fail_closed` configuration.
pub const HOST_CALL_CLASSES: [&str; 7] = [
    "file_read",
    "file_write",
    "file_delete",
    "net_connect",
    "net_bind",
    "net_accept",
    "process_spawn",
];

/// How a host call ended, as the host-audit lane classifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostCallOutcome {
    /// The security gate passed and the effect succeeded.
    Ok,
    /// The security gate passed but the effect failed.
    Failed,
    /// The security gate refused the call before any effect ran.
    Denied,
}

impl HostCallOutcome {
    /// Byte used for this outcome in [`host_call_digest`].
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Ok => 0,
            Self::Failed => 1,
            Self::Denied => 2,
        }
    }
}

/// Calls of one class and outcome inside a [`HostCallSummary`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCallTally {
    /// Host-call class (one of [`HOST_CALL_CLASSES`]).
    pub class: String,
    /// Outcome shared by the counted calls.
    pub outcome: HostCallOutcome,
    /// Number of calls of this class and outcome.
    pub count: u64,
    /// The first such call, as a single-call entry would record its action.
    pub first: AuditAction,
    /// Error (failed) or denial reason (denied) of the first such call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_detail: Option<String>,
}

/// Consecutive host calls of one principal, recorded in one entry.
///
/// The summary is part of the signed action, so the count, the time range and
/// the fold are covered by the entry signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostCallSummary {
    /// Number of calls.
    pub count: u64,
    /// Event time of the first call.
    pub first_at: Timestamp,
    /// Event time of the last call.
    pub last_at: Timestamp,
    /// Fold over every call's digest in call order (see the module docs).
    pub fold: ContentHash,
    /// Calls per class and outcome, in order of first appearance.
    pub tally: Vec<HostCallTally>,
}

/// One host call as the digest sees it.
#[derive(Debug, Clone, Copy)]
pub struct HostCallRef<'a> {
    /// The action a single-call entry records.
    pub action: &'a AuditAction,
    /// How the call ended.
    pub outcome: HostCallOutcome,
    /// Error (failed) or denial reason (denied); empty for ok.
    pub detail: &'a str,
    /// Event time.
    pub at: &'a Timestamp,
}

impl HostCallSummary {
    /// Recompute count, time range and fold from the individual calls and
    /// compare them with this summary.
    #[must_use]
    pub fn matches_calls(&self, calls: &[HostCallRef<'_>]) -> bool {
        let mut fold = HostCallFold::new();
        for call in calls {
            let Some(digest) = host_call_digest(call) else {
                return false;
            };
            fold.push(&digest);
        }
        let (Some(first), Some(last)) = (calls.first(), calls.last()) else {
            return false;
        };
        fold.count() == self.count
            && fold.value() == self.fold
            && *first.at == self.first_at
            && *last.at == self.last_at
    }
}

/// Running fold over call digests (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCallFold {
    value: ContentHash,
    count: u64,
}

impl Default for HostCallFold {
    fn default() -> Self {
        Self::new()
    }
}

impl HostCallFold {
    /// The empty fold (`fold_0`).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            value: ContentHash::zero(),
            count: 0,
        }
    }

    /// Fold one more call digest in.
    pub fn push(&mut self, digest: &ContentHash) {
        let mut hasher = blake3::Hasher::new();
        write_lp(&mut hasher, HOST_CALL_FOLD_DOMAIN.as_bytes());
        hasher.update(self.value.as_bytes());
        hasher.update(digest.as_bytes());
        self.value = ContentHash::from(*hasher.finalize().as_bytes());
        self.count = self.count.saturating_add(1);
    }

    /// Current fold value.
    #[must_use]
    pub const fn value(&self) -> ContentHash {
        self.value
    }

    /// Number of digests folded in.
    #[must_use]
    pub const fn count(&self) -> u64 {
        self.count
    }
}

/// Host-call class of an action, or `None` for an action that is not a
/// capsule host call.
#[must_use]
pub fn host_call_class(action: &AuditAction) -> Option<&'static str> {
    match action {
        AuditAction::FileRead { .. } => Some("file_read"),
        AuditAction::FileWrite { .. } => Some("file_write"),
        AuditAction::FileDelete { .. } => Some("file_delete"),
        AuditAction::NetConnect { .. } => Some("net_connect"),
        AuditAction::NetBind { .. } => Some("net_bind"),
        AuditAction::NetAccept { .. } => Some("net_accept"),
        AuditAction::ProcessSpawn { .. } => Some("process_spawn"),
        _ => None,
    }
}

/// Digest of one host call (see the module docs), or `None` when the action
/// is not a capsule host call.
#[must_use]
pub fn host_call_digest(call: &HostCallRef<'_>) -> Option<ContentHash> {
    let class = host_call_class(call.action)?;
    let mut hasher = blake3::Hasher::new();
    write_lp(&mut hasher, HOST_CALL_DIGEST_DOMAIN.as_bytes());
    write_lp(&mut hasher, class.as_bytes());
    match call.action {
        AuditAction::FileRead { path } | AuditAction::FileDelete { path } => {
            write_lp(&mut hasher, path.as_bytes());
        },
        AuditAction::FileWrite { path, content_hash } => {
            write_lp(&mut hasher, path.as_bytes());
            hasher.update(content_hash.as_bytes());
        },
        AuditAction::NetConnect { host, port } => {
            write_lp(&mut hasher, host.as_bytes());
            hasher.update(&port.to_be_bytes());
        },
        AuditAction::NetBind { addr } => write_lp(&mut hasher, addr.as_bytes()),
        AuditAction::NetAccept {
            local_addr,
            peer_addr,
        } => {
            write_lp(&mut hasher, local_addr.as_bytes());
            write_lp(&mut hasher, peer_addr.as_bytes());
        },
        AuditAction::ProcessSpawn { command } => write_lp(&mut hasher, command.as_bytes()),
        _ => return None,
    }
    hasher.update(&[call.outcome.code()]);
    write_lp(&mut hasher, call.detail.as_bytes());
    hasher.update(&call.at.0.timestamp().to_be_bytes());
    hasher.update(&call.at.0.timestamp_subsec_nanos().to_be_bytes());
    Some(ContentHash::from(*hasher.finalize().as_bytes()))
}

fn write_lp(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(&len.to_be_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
#[path = "host_call_tests.rs"]
mod tests;
