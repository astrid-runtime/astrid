use super::super::{AdminKernelRequest, AdminRequestKind};
use super::*;

fn evidence() -> AuditAnchorEvidence {
    AuditAnchorEvidence {
        network: "unicity:testnet2".to_owned(),
        checkpoint_digest_hex: "ab".repeat(32),
        link_position: 7,
        certifying_round: Some(1234),
        seal_digest_hex: Some("CD".repeat(32)),
    }
}

#[test]
fn anchor_mark_uses_adjacent_method_params_wire_shape() {
    let request = AdminRequestKind::AuditAnchorMark(AuditAnchorMarkRequest {
        evidence: evidence(),
        chains: vec![AuditAnchorMarkChain {
            session: SessionId::SYSTEM,
            principal: Some(PrincipalId::new("alice").unwrap()),
            position: 12,
            head_hash_hex: "11".repeat(32),
        }],
    });
    let value = serde_json::to_value(AdminKernelRequest::from(request)).unwrap();
    assert_eq!(value["method"], "AuditAnchorMark");
    assert_eq!(value["params"]["evidence"]["link_position"], 7);
    assert_eq!(value["params"]["chains"][0]["principal"], "alice");
    assert_eq!(value["params"]["chains"][0]["position"], 12);

    // A system chain and evidence without the optional fields.
    let minimal: AdminKernelRequest = serde_json::from_value(serde_json::json!({
        "method": "AuditAnchorMark",
        "params": {
            "evidence": {
                "network": "n",
                "checkpoint_digest_hex": "00",
                "link_position": 1
            },
            "chains": [{
                "session": SessionId::SYSTEM.0.to_string(),
                "position": 3,
                "head_hash_hex": "22".repeat(32)
            }]
        }
    }))
    .unwrap();
    let AdminRequestKind::AuditAnchorMark(request) = minimal.kind else {
        panic!("expected AuditAnchorMark");
    };
    assert!(request.chains[0].principal.is_none());
    assert!(request.evidence.certifying_round.is_none());
    assert!(request.evidence.validate().is_ok());

    let status = serde_json::to_value(AdminKernelRequest::from(
        AdminRequestKind::AuditAnchorStatus,
    ))
    .unwrap();
    assert_eq!(status["method"], "AuditAnchorStatus");
}

#[test]
fn anchor_evidence_validation_rejects_malformed_fields() {
    assert!(evidence().validate().is_ok());
    for broken in [
        AuditAnchorEvidence {
            network: String::new(),
            ..evidence()
        },
        AuditAnchorEvidence {
            network: "x".repeat(129),
            ..evidence()
        },
        AuditAnchorEvidence {
            checkpoint_digest_hex: "abc".to_owned(),
            ..evidence()
        },
        AuditAnchorEvidence {
            checkpoint_digest_hex: "zz".to_owned(),
            ..evidence()
        },
        AuditAnchorEvidence {
            checkpoint_digest_hex: "ab".repeat(65),
            ..evidence()
        },
        AuditAnchorEvidence {
            seal_digest_hex: Some(String::new()),
            ..evidence()
        },
    ] {
        assert!(broken.validate().is_err(), "{broken:?}");
    }
}

#[test]
fn anchor_status_reports_head_position_and_lag() {
    let status = |omitted_total, anchored_position| AuditAnchorChainStatus {
        session: SessionId::SYSTEM.0.to_string(),
        principal: None,
        count: 10,
        omitted_total,
        anchored_position,
        anchored_head_hash_hex: None,
        anchored_at: None,
        evidence: None,
    };
    assert_eq!(status(5, Some(12)).head_position(), Some(15));
    assert_eq!(status(5, Some(12)).lag(), Some(3));
    assert_eq!(status(5, None).lag(), Some(15));
    assert_eq!(status(AUDIT_OMITTED_TOTAL_UNKNOWN, Some(3)).lag(), None);

    let outcome = AuditAnchorMarkOutcome {
        session: SessionId::SYSTEM.0.to_string(),
        principal: None,
        status: AuditAnchorMarkStatus::Unchanged,
        anchored_position: 4,
        error: None,
    };
    let value = serde_json::to_value(&outcome).unwrap();
    assert_eq!(value["status"], "unchanged");
    assert!(value.get("error").is_none());
}
