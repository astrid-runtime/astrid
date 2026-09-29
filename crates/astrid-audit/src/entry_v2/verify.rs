//! Chain verification against the key registry.

use super::body::{EntryV2Seal, derive_chain_id, timestamp_nanos};
use super::registry::{KeyRegistry, KeyRole};
use crate::entry::AuditEntry;
use crate::log::{ChainIssue, ChainVerificationResult};

/// Where a run of entries handed to [`ChainVerifier::verify`] starts.
#[derive(Clone, Copy, Debug)]
pub enum ChainStart<'a> {
    /// The first entry opens its storage chain: its previous hash is zero.
    Genesis,
    /// The first entry directly follows this entry of the same chain.
    After(&'a AuditEntry),
    /// The first entry's predecessor is not available (a retained suffix
    /// after pruning, or an exported segment); its link is not checked.
    Detached,
}

/// Verifies audit entries of one storage chain, in storage order.
///
/// Format-v2 entries are checked against the key registry: the signer must
/// hold [`KeyRole::Audit`] in the registry state the entry names, the chain
/// id must match its derivation from the registry id, session and principal,
/// and sequence numbers must run 1, 2, 3, … within a chain with each entry
/// linking to the hash of its predecessor. The key embedded in an entry is
/// only a selector; it is never trusted on its own.
///
/// Format-v1 entries are checked for their signature and hash link as
/// before. With a registry, their embedded key must also be registered as
/// [`KeyRole::AuditV1`] (the key that signed the node's v1 history), so a v1
/// chain rewritten under some other key no longer passes;
/// [`require_registered_v1_keys`](Self::require_registered_v1_keys) turns
/// that off. A v1 entry after a v2 entry is always an issue: v2 closes the
/// chain to v1.
#[derive(Clone, Copy, Debug)]
pub struct ChainVerifier<'a> {
    registry: Option<&'a KeyRegistry>,
    registered_v1_keys: bool,
}

impl<'a> ChainVerifier<'a> {
    /// A verifier over `registry`. Without a registry every v2 entry is
    /// reported as signed by an unregistered key and v1 entries are verified
    /// against their embedded key; with one, v1 entries must also be signed
    /// by a registered [`KeyRole::AuditV1`] key.
    #[must_use]
    pub const fn new(registry: Option<&'a KeyRegistry>) -> Self {
        Self {
            registry,
            registered_v1_keys: registry.is_some(),
        }
    }

    /// Whether each v1 entry's embedded key must be registered as
    /// [`KeyRole::AuditV1`]. On by default when a registry is given; turning
    /// it off verifies v1 entries against their embedded key alone, as format
    /// v1 did.
    #[must_use]
    pub const fn require_registered_v1_keys(mut self, required: bool) -> Self {
        self.registered_v1_keys = required;
        self
    }

    /// Verify a run of consecutive entries of one storage chain.
    #[must_use]
    pub fn verify(&self, entries: &[AuditEntry], start: ChainStart<'_>) -> ChainVerificationResult {
        let mut issues = Vec::new();
        let mut previous = match start {
            ChainStart::After(entry) => Some(entry),
            ChainStart::Genesis | ChainStart::Detached => None,
        };
        for (index, entry) in entries.iter().enumerate() {
            if index == 0 && matches!(start, ChainStart::Genesis) && !entry.previous_hash.is_zero()
            {
                issues.push(ChainIssue::InvalidGenesis {
                    entry_id: entry.id.clone(),
                });
            }
            issues.extend(self.check_entry(entry, previous));
            previous = Some(entry);
        }
        ChainVerificationResult {
            valid: issues.is_empty(),
            entries_verified: entries.len(),
            issues,
        }
    }

    /// Check one entry and its link to `previous`, the entry stored directly
    /// before it in the same storage chain (`None` for the first entry, whose
    /// anchoring the caller checks).
    #[must_use]
    pub fn check_entry(
        &self,
        entry: &AuditEntry,
        previous: Option<&AuditEntry>,
    ) -> Vec<ChainIssue> {
        let mut issues = Vec::new();
        match &entry.v2 {
            None => self.check_v1(entry, previous, &mut issues),
            Some(seal) => self.check_v2(entry, seal, previous, &mut issues),
        }
        issues
    }

    fn check_v1(
        &self,
        entry: &AuditEntry,
        previous: Option<&AuditEntry>,
        issues: &mut Vec<ChainIssue>,
    ) {
        if entry.verify_signature().is_err() {
            issues.push(ChainIssue::InvalidSignature {
                entry_id: entry.id.clone(),
            });
        }
        if self.registered_v1_keys
            && !self.registry.is_some_and(|registry| {
                registry.was_registered(KeyRole::AuditV1, &entry.runtime_key)
            })
        {
            issues.push(ChainIssue::UnregisteredKey {
                entry_id: entry.id.clone(),
            });
        }
        if previous.is_some_and(|previous| previous.v2.is_some()) {
            issues.push(ChainIssue::FormatDowngrade {
                entry_id: entry.id.clone(),
            });
        }
        check_link(entry, previous, issues);
    }

    fn check_v2(
        &self,
        entry: &AuditEntry,
        seal: &EntryV2Seal,
        previous: Option<&AuditEntry>,
        issues: &mut Vec<ChainIssue>,
    ) {
        let entry_id = || entry.id.clone();
        if timestamp_nanos(&entry.timestamp).is_none() {
            issues.push(ChainIssue::MalformedEntry {
                entry_id: entry_id(),
                reason: "time is not representable as u64 nanoseconds".to_owned(),
            });
        }
        if seal.seq == 0 {
            issues.push(ChainIssue::MalformedEntry {
                entry_id: entry_id(),
                reason: "sequence numbers start at 1".to_owned(),
            });
        }
        if let Err(error) = entry.v2_entry_hash(seal) {
            issues.push(ChainIssue::MalformedEntry {
                entry_id: entry_id(),
                reason: error.to_string(),
            });
        }
        match self.registry {
            None => issues.push(ChainIssue::UnregisteredKey {
                entry_id: entry_id(),
            }),
            Some(registry) => {
                let derived = derive_chain_id(
                    &registry.registry_id(),
                    &entry.session_id,
                    entry.principal.as_ref(),
                    seal.principal_uid.as_ref(),
                );
                if derived != seal.chain_id {
                    issues.push(ChainIssue::ChainIdMismatch {
                        entry_id: entry_id(),
                    });
                }
                if !registry.is_active(KeyRole::Audit, &entry.runtime_key, seal.key_epoch) {
                    issues.push(ChainIssue::UnregisteredKey {
                        entry_id: entry_id(),
                    });
                }
            },
        }
        if entry.verify_signature().is_err() {
            issues.push(ChainIssue::InvalidSignature {
                entry_id: entry_id(),
            });
        }
        check_sequence(entry, seal, previous, issues);
        check_link(entry, previous, issues);
    }
}

/// Sequence and key-epoch continuity of a v2 entry.
fn check_sequence(
    entry: &AuditEntry,
    seal: &EntryV2Seal,
    previous: Option<&AuditEntry>,
    issues: &mut Vec<ChainIssue>,
) {
    // Entries of one storage chain are signed in storage order, each at the
    // registry head of its time, so the key epoch never decreases along the
    // storage chain, also where a new v2 chain opens.
    if let Some(previous_seal) = previous.and_then(|previous| previous.v2.as_ref())
        && seal.key_epoch < previous_seal.key_epoch
    {
        issues.push(ChainIssue::KeyEpochRegression {
            entry_id: entry.id.clone(),
        });
    }
    let expected = match previous {
        // A first stored entry either opens its chain (zero previous hash,
        // sequence 1) or is anchored by an archive receipt, which the caller
        // checks; only the unanchored opening is decidable here.
        None if entry.previous_hash.is_zero() => Some(1),
        None => None,
        Some(previous) => match &previous.v2 {
            Some(previous_seal) if previous_seal.chain_id == seal.chain_id => {
                let Some(next) = previous_seal.seq.checked_add(1) else {
                    issues.push(ChainIssue::MalformedEntry {
                        entry_id: entry.id.clone(),
                        reason: "sequence number overflows after its predecessor".to_owned(),
                    });
                    return;
                };
                Some(next)
            },
            // A v2 chain opens at 1 after a v1 entry or another v2 chain.
            _ => Some(1),
        },
    };
    if let Some(expected) = expected
        && seal.seq != expected
    {
        issues.push(ChainIssue::SequenceGap {
            entry_id: entry.id.clone(),
            expected,
            actual: seal.seq,
        });
    }
}

fn check_link(entry: &AuditEntry, previous: Option<&AuditEntry>, issues: &mut Vec<ChainIssue>) {
    if let Some(previous) = previous
        && !entry.follows(previous)
    {
        issues.push(ChainIssue::BrokenLink {
            entry_id: entry.id.clone(),
            expected_previous: previous.content_hash(),
            actual_previous: entry.previous_hash,
        });
    }
}
