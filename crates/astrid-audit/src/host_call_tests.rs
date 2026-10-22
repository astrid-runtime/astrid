use super::*;
use crate::entry::{AuditEntry, AuditOutcome, AuthorizationProof};
use astrid_core::{PrincipalId, SessionId};
use astrid_crypto::KeyPair;
use chrono::{TimeZone, Utc};

fn at(secs: i64, nanos: u32) -> Timestamp {
    Timestamp::from_datetime(Utc.timestamp_opt(secs, nanos).single().expect("valid time"))
}

fn read(path: &str) -> AuditAction {
    AuditAction::FileRead {
        actor: None,
        path: path.to_owned(),
    }
}

/// Independent spelling of the documented digest layout for `file_read`.
fn manual_file_read_digest(path: &str, outcome: u8, detail: &str, time: &Timestamp) -> [u8; 32] {
    let mut bytes = Vec::new();
    for field in [
        HOST_CALL_DIGEST_DOMAIN.as_bytes(),
        b"file_read",
        path.as_bytes(),
    ] {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes.push(outcome);
    bytes.extend_from_slice(&(detail.len() as u64).to_be_bytes());
    bytes.extend_from_slice(detail.as_bytes());
    bytes.extend_from_slice(&time.0.timestamp().to_be_bytes());
    bytes.extend_from_slice(&time.0.timestamp_subsec_nanos().to_be_bytes());
    *blake3::hash(&bytes).as_bytes()
}

#[test]
fn call_digest_follows_the_documented_layout() {
    let time = at(1_700_000_000, 123_456_789);
    let action = read("/w/a");
    let digest = host_call_digest(&HostCallRef {
        action: &action,
        outcome: HostCallOutcome::Failed,
        detail: "NotFound",
        at: &time,
    })
    .expect("file_read is a host call");
    assert_eq!(
        *digest.as_bytes(),
        manual_file_read_digest("/w/a", 1, "NotFound", &time)
    );
    // Pinned known answer: a change here changes every stored fold.
    assert_eq!(
        digest.to_hex(),
        "70b7c49cf6c543ca0ad463ae0159ce396c0d3d2bd6057dea0f3094d01ad73e58"
    );
}

#[test]
fn call_digest_binds_every_field() {
    let time = at(10, 0);
    let base_action = AuditAction::NetConnect {
        actor: None,
        host: "example.com".to_owned(),
        port: 443,
    };
    let base = HostCallRef {
        action: &base_action,
        outcome: HostCallOutcome::Ok,
        detail: "",
        at: &time,
    };
    let digest = host_call_digest(&base).expect("host call");

    let other_port = AuditAction::NetConnect {
        actor: None,
        host: "example.com".to_owned(),
        port: 444,
    };
    let later = at(10, 1);
    let variants = [
        HostCallRef {
            action: &other_port,
            ..base
        },
        HostCallRef {
            outcome: HostCallOutcome::Failed,
            ..base
        },
        HostCallRef {
            detail: "refused",
            ..base
        },
        HostCallRef { at: &later, ..base },
    ];
    for variant in &variants {
        assert_ne!(host_call_digest(variant), Some(digest), "{variant:?}");
    }
}

#[test]
fn non_host_call_actions_have_no_digest() {
    let action = AuditAction::ConfigReloaded;
    let time = at(1, 0);
    assert!(host_call_class(&action).is_none());
    assert!(
        host_call_digest(&HostCallRef {
            action: &action,
            outcome: HostCallOutcome::Ok,
            detail: "",
            at: &time,
        })
        .is_none()
    );
}

#[test]
fn attributed_call_digest_binds_capsule_and_wasm_identity() {
    let time = at(10, 0);
    let digest = |capsule: &str, wasm: &[u8]| {
        host_call_digest(&HostCallRef {
            action: &AuditAction::FileRead {
                path: "/w/a".into(),
                actor: Some(crate::CapsuleActor {
                    capsule_id: capsule.into(),
                    wasm_hash: Some(ContentHash::hash(wasm)),
                }),
            },
            outcome: HostCallOutcome::Ok,
            detail: "",
            at: &time,
        })
        .expect("attributed call")
    };
    assert_ne!(digest("one", b"a"), digest("two", b"a"));
    assert_ne!(digest("one", b"a"), digest("one", b"b"));
}

#[test]
fn every_host_call_class_is_listed() {
    let actions = [
        read("/p"),
        AuditAction::FileWrite {
            actor: None,
            path: "/p".to_owned(),
            content_hash: ContentHash::zero(),
        },
        AuditAction::FileDelete {
            actor: None,
            path: "/p".to_owned(),
        },
        AuditAction::NetConnect {
            actor: None,
            host: "h".to_owned(),
            port: 1,
        },
        AuditAction::NetBind {
            actor: None,
            addr: "a".to_owned(),
        },
        AuditAction::NetAccept {
            actor: None,
            local_addr: "l".to_owned(),
            peer_addr: "p".to_owned(),
        },
        AuditAction::ProcessSpawn {
            actor: None,
            command: "c".to_owned(),
        },
    ];
    let classes: Vec<_> = actions
        .iter()
        .map(|action| host_call_class(action).expect("host call"))
        .collect();
    assert_eq!(classes, HOST_CALL_CLASSES);
}

fn calls() -> Vec<(AuditAction, HostCallOutcome, &'static str, Timestamp)> {
    vec![
        (read("/a"), HostCallOutcome::Ok, "", at(100, 1)),
        (read("/b"), HostCallOutcome::Failed, "NotFound", at(100, 2)),
        (
            AuditAction::ProcessSpawn {
                actor: None,
                command: "ls".to_owned(),
            },
            HostCallOutcome::Ok,
            "",
            at(100, 3),
        ),
    ]
}

fn refs<'a>(
    calls: &'a [(AuditAction, HostCallOutcome, &'static str, Timestamp)],
) -> Vec<HostCallRef<'a>> {
    calls
        .iter()
        .map(|(action, outcome, detail, time)| HostCallRef {
            action,
            outcome: *outcome,
            detail,
            at: time,
        })
        .collect()
}

fn summary_of(calls: &[HostCallRef<'_>]) -> HostCallSummary {
    let mut fold = HostCallFold::new();
    for call in calls {
        fold.push(&host_call_digest(call).expect("host call"));
    }
    HostCallSummary {
        count: fold.count(),
        first_at: *calls.first().expect("calls").at,
        last_at: *calls.last().expect("calls").at,
        fold: fold.value(),
        tally: Vec::new(),
    }
}

#[test]
fn fold_is_a_hash_chain_over_call_digests() {
    let owned = calls();
    let calls = refs(&owned);
    let mut expected = [0_u8; 32];
    for call in &calls {
        let digest = host_call_digest(call).expect("host call");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(HOST_CALL_FOLD_DOMAIN.len() as u64).to_be_bytes());
        bytes.extend_from_slice(HOST_CALL_FOLD_DOMAIN.as_bytes());
        bytes.extend_from_slice(&expected);
        bytes.extend_from_slice(digest.as_bytes());
        expected = *blake3::hash(&bytes).as_bytes();
    }
    let summary = summary_of(&calls);
    assert_eq!(*summary.fold.as_bytes(), expected);
    assert_eq!(summary.count, 3);
    assert!(summary.matches_calls(&calls));
}

#[test]
fn summary_rejects_missing_reordered_or_altered_calls() {
    let owned = calls();
    let calls = refs(&owned);
    let summary = summary_of(&calls);

    assert!(!summary.matches_calls(&calls[..2]), "dropped call");
    let reordered = [calls[1], calls[0], calls[2]];
    assert!(!summary.matches_calls(&reordered), "reordered calls");
    let altered_action = read("/other");
    let mut altered = calls.clone();
    altered[1].action = &altered_action;
    assert!(!summary.matches_calls(&altered), "altered call");
    assert!(!summary.matches_calls(&[]), "no calls");
}

#[test]
fn summary_is_covered_by_the_entry_signature() {
    let owned = calls();
    let calls = refs(&owned);
    let key = KeyPair::generate();
    let entry = AuditEntry::create_with_principal(
        SessionId::new(),
        PrincipalId::new("alice").expect("principal"),
        AuditAction::HostCallRun {
            calls: summary_of(&calls),
        },
        AuthorizationProof::System {
            reason: "test".to_owned(),
        },
        AuditOutcome::success(),
        ContentHash::zero(),
        &key,
    );
    assert!(entry.verify_signature().is_ok());

    let json = serde_json::to_string(&entry).expect("serialize");
    let mut decoded: AuditEntry = serde_json::from_str(&json).expect("deserialize");
    assert!(decoded.verify_signature().is_ok(), "round trip keeps bytes");

    let AuditAction::HostCallRun { calls: summary } = &mut decoded.action else {
        panic!("unexpected action {:?}", decoded.action);
    };
    summary.count = 2;
    assert!(
        decoded.verify_signature().is_err(),
        "the count must be signed"
    );
}
