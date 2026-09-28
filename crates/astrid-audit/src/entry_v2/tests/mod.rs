//! Tests for audit entry format v2.

use astrid_capabilities::AuditEntryId;
use astrid_core::identity::PrincipalUid;
use astrid_core::{PrincipalId, SessionId, Timestamp};
use astrid_crypto::{ContentHash, KeyPair};
use chrono::TimeZone;

use super::{AuditActor, EntryV2Draft, KeyRegistry, KeyRole, derive_chain_id};
use crate::entry::{AuditAction, AuditEntry, AuditOutcome, AuthorizationProof};

mod cbor;
mod chain;
mod coverage;
mod kat;
mod registry;

/// A key pair from a fixed 32-byte seed.
fn key(seed: u8) -> KeyPair {
    KeyPair::from_secret_key(&[seed; 32]).unwrap()
}

fn at(seconds: i64, nanos: u32) -> Timestamp {
    Timestamp::from_datetime(chrono::Utc.timestamp_opt(seconds, nanos).single().unwrap())
}

/// 2026-09-28T00:00:00Z.
const KAT_GENESIS_SECONDS: i64 = 1_790_553_600;
/// 2026-09-28T12:34:56Z.
const KAT_ENTRY_SECONDS: i64 = 1_790_598_896;

/// The KAT registry: audit key seed 0x01, runtime key seed 0x02 as
/// capability, build and audit-v1 key.
fn kat_registry() -> KeyRegistry {
    let audit = key(1);
    let runtime = key(2);
    let genesis = KeyRegistry::genesis_record(
        at(KAT_GENESIS_SECONDS, 0),
        &[
            (KeyRole::Audit, &audit),
            (KeyRole::Capability, &runtime),
            (KeyRole::Build, &runtime),
            (KeyRole::AuditV1, &runtime),
        ],
    )
    .unwrap();
    KeyRegistry::from_records(vec![genesis]).unwrap()
}

fn kat_session() -> SessionId {
    SessionId::from_uuid(uuid::Uuid::from_bytes([
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    ]))
}

fn kat_entry_id() -> AuditEntryId {
    AuditEntryId(uuid::Uuid::from_bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ]))
}

fn alice() -> PrincipalId {
    PrincipalId::new("alice").unwrap()
}

/// A v2 draft opening a chain for `principal` in `session`.
fn draft(
    registry: &KeyRegistry,
    session: &SessionId,
    principal: Option<PrincipalId>,
    principal_uid: Option<PrincipalUid>,
    action: AuditAction,
) -> EntryV2Draft {
    let chain_id = derive_chain_id(
        &registry.registry_id(),
        session,
        principal.as_ref(),
        principal_uid.as_ref(),
    );
    EntryV2Draft {
        session_id: session.clone(),
        principal,
        principal_uid,
        actor: None,
        action,
        authorization: AuthorizationProof::System {
            reason: "test".to_owned(),
        },
        outcome: AuditOutcome::success(),
        previous_hash: ContentHash::zero(),
        chain_id,
        seq: 1,
        key_epoch: registry.head_seq(),
    }
}

/// The KAT entry, signed by the KAT audit key.
fn kat_entry(registry: &KeyRegistry) -> AuditEntry {
    let mut draft = draft(
        registry,
        &kat_session(),
        Some(alice()),
        Some(PrincipalUid::from_bytes([7; 32])),
        AuditAction::FileWrite {
            path: "/home/alice/notes.txt".to_owned(),
            content_hash: ContentHash::from_bytes([0x0a; 32]),
        },
    );
    draft.actor = Some(AuditActor {
        capsule_id: "aos-fs".to_owned(),
        wasm_sha256: Some([8; 32]),
    });
    draft.authorization = AuthorizationProof::System {
        reason: "manifest-gated host call".to_owned(),
    };
    draft.outcome = AuditOutcome::failure("disk full");
    AuditEntry::assemble_v2(
        draft,
        &key(1),
        kat_entry_id(),
        at(KAT_ENTRY_SECONDS, 123_456_789),
        [9; 32],
    )
    .unwrap()
}

/// A signed chain of `count` v2 entries on one principal chain.
fn signed_chain(registry: &KeyRegistry, signer: &KeyPair, count: u64) -> Vec<AuditEntry> {
    let session = kat_session();
    let mut entries: Vec<AuditEntry> = Vec::new();
    for seq in 1..=count {
        let mut next = draft(
            registry,
            &session,
            Some(alice()),
            None,
            AuditAction::FileRead {
                path: format!("/file/{seq}"),
            },
        );
        next.seq = seq;
        next.previous_hash = entries
            .last()
            .map_or_else(ContentHash::zero, AuditEntry::content_hash);
        entries.push(AuditEntry::create_v2(next, signer).unwrap());
    }
    entries
}
