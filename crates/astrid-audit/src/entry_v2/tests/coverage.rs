//! Every stored field of an entry is covered by its v2 signature.

use serde_json::Value;

use super::*;
use crate::entry::ApprovalScope;
use crate::entry_v2::fields::{action_section, section_of};
use crate::entry_v2::json::to_cbor;
use astrid_core::{Permission, TokenId};

/// One instance of every action variant, with every optional field set.
#[expect(
    clippy::too_many_lines,
    reason = "one instance per action variant, kept in one list"
)]
fn sample_actions() -> Vec<AuditAction> {
    let hash = ContentHash::from_bytes([3; 32]);
    let token = TokenId(uuid::Uuid::from_bytes([4; 16]));
    vec![
        AuditAction::McpToolCall {
            server: "s".into(),
            tool: "t".into(),
            args_hash: hash,
        },
        AuditAction::CapsuleToolCall {
            capsule_id: "c".into(),
            tool: "t".into(),
            args_hash: hash,
        },
        AuditAction::McpResourceRead {
            server: "s".into(),
            uri: "u".into(),
        },
        AuditAction::McpPromptGet {
            server: "s".into(),
            name: "n".into(),
        },
        AuditAction::McpElicitation {
            request_id: "r".into(),
            schema: "text".into(),
        },
        AuditAction::McpUrlElicitation {
            url: "u".into(),
            interaction_type: "oauth".into(),
        },
        AuditAction::McpSampling {
            model: "m".into(),
            prompt_tokens: 5,
        },
        AuditAction::FileRead { path: "/a".into() },
        AuditAction::FileWrite {
            path: "/a".into(),
            content_hash: hash,
        },
        AuditAction::FileDelete { path: "/a".into() },
        AuditAction::NetConnect {
            host: "h".into(),
            port: 443,
        },
        AuditAction::NetBind {
            addr: "0.0.0.0:1".into(),
        },
        AuditAction::ProcessSpawn {
            command: "ls".into(),
        },
        AuditAction::CapabilityCreated {
            token_id: token.clone(),
            resource: "r".into(),
            permissions: vec![Permission::Read, Permission::Invoke],
            scope: ApprovalScope::Session,
        },
        AuditAction::CapabilityRevoked {
            token_id: token,
            reason: "r".into(),
        },
        AuditAction::ApprovalRequested {
            action_type: "a".into(),
            resource: "r".into(),
        },
        AuditAction::ApprovalGranted {
            action: "a".into(),
            resource: Some("r".into()),
            scope: ApprovalScope::Workspace,
        },
        AuditAction::ApprovalDenied {
            action: "a".into(),
            reason: Some("r".into()),
        },
        AuditAction::SessionStarted {
            user_id: [5; 8],
            platform: "cli".into(),
        },
        AuditAction::SessionEnded {
            reason: "r".into(),
            duration_secs: 7,
        },
        AuditAction::ContextSummarized {
            evicted_count: 2,
            tokens_freed: 9,
        },
        AuditAction::LlmRequest {
            model: "m".into(),
            input_tokens: 1,
            output_tokens: 2,
        },
        AuditAction::ServerStarted {
            name: "n".into(),
            transport: "stdio".into(),
            binary_hash: Some(hash),
        },
        AuditAction::ServerStopped {
            name: "n".into(),
            reason: "r".into(),
        },
        AuditAction::ElicitationSent {
            request_id: "r".into(),
            server: "s".into(),
            elicitation_type: "e".into(),
        },
        AuditAction::ElicitationReceived {
            request_id: "r".into(),
            action: "submit".into(),
        },
        AuditAction::SecurityViolation {
            violation_type: "v".into(),
            details: "d".into(),
        },
        AuditAction::SubAgentSpawned {
            parent_session_id: "p".into(),
            child_session_id: "c".into(),
            description: "d".into(),
        },
        AuditAction::ConfigReloaded,
        AuditAction::AdminRequest {
            method: "Shutdown".into(),
            required_capability: "system:shutdown".into(),
            target_principal: Some(alice()),
            params: Some(serde_json::json!({"quota": 5, "names": ["a", "b"], "ratio": 0.5})),
            device_key_id: Some("k".into()),
        },
        AuditAction::NetAccept {
            local_addr: "l".into(),
            peer_addr: "p".into(),
        },
    ]
}

fn sample_authorizations() -> Vec<AuthorizationProof> {
    vec![
        AuthorizationProof::User {
            user_id: [1; 8],
            message_id: "m".into(),
        },
        AuthorizationProof::Capability {
            token_id: TokenId(uuid::Uuid::from_bytes([2; 16])),
            token_hash: ContentHash::from_bytes([3; 32]),
        },
        AuthorizationProof::UserApproval {
            user_id: [1; 8],
            approval_entry_id: Some(AuditEntryId(uuid::Uuid::from_bytes([6; 16]))),
        },
        AuthorizationProof::NotRequired { reason: "r".into() },
        AuthorizationProof::System { reason: "r".into() },
        AuthorizationProof::Denied { reason: "r".into() },
    ]
}

/// Candidate edits of a JSON leaf that keep it well-typed where possible:
/// change the first digit, the last digit, or the last alphanumeric
/// character of a string (which keeps ids, hex, base64 and timestamps
/// parseable), append to it, bump a number, flip a boolean.
fn leaf_edits(value: &Value) -> Vec<Value> {
    fn replace_at(text: &str, index: usize, c: char) -> Value {
        let mut edited = text.to_owned();
        let replacement = if c == '1' { '2' } else { '1' };
        edited.replace_range(
            index..index.checked_add(c.len_utf8()).unwrap(),
            &replacement.to_string(),
        );
        Value::String(edited)
    }
    match value {
        Value::String(text) => {
            let mut edits = Vec::new();
            let mut digits = text.char_indices().filter(|(_, c)| c.is_ascii_digit());
            if let Some((index, c)) = digits.next() {
                edits.push(replace_at(text, index, c));
            }
            if let Some((index, c)) = text.char_indices().rev().find(|(_, c)| c.is_ascii_digit()) {
                edits.push(replace_at(text, index, c));
            }
            if let Some((index, c)) = text
                .char_indices()
                .rev()
                .find(|(_, c)| c.is_ascii_alphanumeric())
            {
                edits.push(replace_at(text, index, c));
            }
            edits.push(Value::String(format!("{text}x")));
            edits.dedup();
            edits
        },
        Value::Number(number) => {
            vec![Value::from(
                number.as_u64().unwrap_or(0).checked_add(1).unwrap(),
            )]
        },
        Value::Bool(flag) => vec![Value::Bool(!flag)],
        _ => Vec::new(),
    }
}

/// Every mutation of `value` that changes one leaf, or removes one optional
/// member, as `(path, mutated)`.
fn mutations(value: &Value, path: &str, out: &mut Vec<(String, Value)>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}/{key}");
                let mut removed = value.clone();
                removed.as_object_mut().unwrap().remove(key);
                out.push((format!("{child_path} (removed)"), removed));
                let mut child_mutations = Vec::new();
                mutations(child, &child_path, &mut child_mutations);
                for (mutated_path, mutated_child) in child_mutations {
                    let mut whole = value.clone();
                    whole[key] = mutated_child;
                    out.push((mutated_path, whole));
                }
            }
        },
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let mut child_mutations = Vec::new();
                mutations(child, &format!("{path}/{index}"), &mut child_mutations);
                for (mutated_path, mutated_child) in child_mutations {
                    let mut whole = value.clone();
                    whole[index] = mutated_child;
                    out.push((mutated_path, whole));
                }
            }
        },
        leaf => {
            for edit in leaf_edits(leaf) {
                out.push((path.to_owned(), edit));
            }
        },
    }
}

#[test]
fn every_stored_entry_field_is_signed() {
    let registry = kat_registry();
    let entry = kat_entry(&registry);
    let stored = serde_json::to_value(&entry).unwrap();
    let mut all = Vec::new();
    mutations(&stored, "", &mut all);
    let mut checked = std::collections::BTreeSet::new();
    for (path, mutated) in all {
        if path.starts_with("/signature") {
            continue;
        }
        // Mutations that no longer deserialize cannot be stored at all.
        let Ok(mutated) = serde_json::from_value::<AuditEntry>(mutated) else {
            continue;
        };
        if serde_json::to_value(&mutated).unwrap() == stored {
            continue;
        }
        assert!(
            mutated.verify_signature().is_err(),
            "changing {path} must invalidate the signature"
        );
        checked.insert(path);
    }
    for required in [
        "/id",
        "/timestamp",
        "/session_id",
        "/principal",
        "/principal (removed)",
        "/action/path",
        "/action/content_hash",
        "/authorization/reason",
        "/outcome/error",
        "/previous_hash",
        "/runtime_key",
        "/v2 (removed)",
        "/v2/chain_id",
        "/v2/seq",
        "/v2/key_epoch",
        "/v2/principal_uid",
        "/v2/principal_uid (removed)",
        "/v2/actor (removed)",
        "/v2/actor/capsule_id",
        "/v2/actor/wasm_sha256",
        "/v2/actor/wasm_sha256 (removed)",
        "/v2/salt_key",
    ] {
        assert!(checked.contains(required), "{required} was not exercised");
    }
}

#[test]
fn enum_valued_fields_are_signed() {
    let authorization = AuthorizationProof::System { reason: "r".into() };
    let outcome = AuditOutcome::success();
    let created = |permission, scope| AuditAction::CapabilityCreated {
        token_id: TokenId(uuid::Uuid::from_bytes([4; 16])),
        resource: "r".into(),
        permissions: vec![permission],
        scope,
    };
    let base = body_with(
        created(Permission::Read, ApprovalScope::Once),
        authorization.clone(),
        outcome.clone(),
    );
    for other in [
        created(Permission::Write, ApprovalScope::Once),
        created(Permission::Read, ApprovalScope::Always),
    ] {
        assert_ne!(
            body_with(other, authorization.clone(), outcome.clone()),
            base
        );
    }
    // The same text as success details and as a failure error differ.
    let success = body_with(
        AuditAction::ConfigReloaded,
        authorization.clone(),
        AuditOutcome::success_with("x"),
    );
    let failure = body_with(
        AuditAction::ConfigReloaded,
        authorization,
        AuditOutcome::failure("x"),
    );
    assert_ne!(success, failure);
}

fn body_with(
    action: AuditAction,
    authorization: AuthorizationProof,
    outcome: AuditOutcome,
) -> Vec<u8> {
    let registry = kat_registry();
    let mut entry = kat_entry(&registry);
    entry.action = action;
    entry.authorization = authorization;
    entry.outcome = outcome;
    entry.v2_body().unwrap().unwrap()
}

/// Apply every single-field edit to `original` and require each edit that
/// still deserializes to change the body `body_of` builds from it.
fn check_edits<T>(original: &T, what: &str, body_of: impl Fn(T) -> Vec<u8>) -> usize
where
    T: Clone + serde::Serialize + serde::de::DeserializeOwned,
{
    let original_json = serde_json::to_value(original).unwrap();
    let base = body_of(original.clone());
    let mut all = Vec::new();
    mutations(&original_json, "", &mut all);
    let mut checked: usize = 0;
    for (path, mutated) in all {
        let Ok(mutated) = serde_json::from_value::<T>(mutated) else {
            continue;
        };
        if serde_json::to_value(&mutated).unwrap() == original_json {
            continue;
        }
        assert_ne!(body_of(mutated), base, "{what}: field {path} is not signed");
        checked = checked.saturating_add(1);
    }
    checked
}

#[test]
fn every_action_authorization_and_outcome_field_changes_the_body() {
    let authorization = AuthorizationProof::System { reason: "r".into() };
    let outcome = AuditOutcome::success();
    let mut checked: usize = 0;
    for action in sample_actions() {
        let edits = check_edits(&action, &action.description(), |action| {
            body_with(action, authorization.clone(), outcome.clone())
        });
        checked = checked.saturating_add(edits);
    }
    for proof in sample_authorizations() {
        let edits = check_edits(&proof, "authorization", |proof| {
            body_with(AuditAction::ConfigReloaded, proof, outcome.clone())
        });
        checked = checked.saturating_add(edits);
    }
    for result in [
        AuditOutcome::success_with("details"),
        AuditOutcome::failure("error"),
    ] {
        let edits = check_edits(&result, "outcome", |result| {
            body_with(AuditAction::ConfigReloaded, authorization.clone(), result)
        });
        checked = checked.saturating_add(edits);
    }
    assert!(checked > 80, "only {checked} field edits were checked");
}

#[test]
fn every_action_variant_has_a_distinct_kind() {
    let actions = sample_actions();
    let mut kinds: Vec<String> = actions
        .iter()
        .map(|action| action_section(action).unwrap().kind)
        .collect();
    assert_eq!(
        kinds.len(),
        31,
        "sample_actions must list every AuditAction variant"
    );
    kinds.sort_unstable();
    kinds.dedup();
    assert_eq!(kinds.len(), 31);
    assert!(kinds.contains(&"file_write".to_owned()));
}

/// A variant added later, with a nested struct, is encoded by the same rule
/// without any change to the encoder or the specification.
#[test]
fn sections_follow_the_serde_form_of_any_variant() {
    #[derive(serde::Serialize)]
    struct Summary {
        count: u64,
        first_ns: u64,
    }
    #[derive(serde::Serialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Future {
        HostCallRun {
            summary: Summary,
            #[serde(skip_serializing_if = "Option::is_none")]
            note: Option<String>,
        },
    }
    let section = section_of(
        &Future::HostCallRun {
            summary: Summary {
                count: 3,
                first_ns: 7,
            },
            note: None,
        },
        "type",
        "action",
    )
    .unwrap();
    assert_eq!(section.kind, "host_call_run");
    let names: Vec<&str> = section
        .fields
        .iter()
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(names, ["summary"]);
    assert_eq!(
        hex::encode(section.fields[0].1.encode()),
        // {"count": 3, "first_ns": 7}
        "a265636f756e74036866697273745f6e7307"
    );
    // A value whose serde form is not a tagged object cannot be encoded.
    assert!(section_of(&42_u64, "type", "action").is_err());
}

#[test]
fn outcome_text_is_signed_in_full() {
    let authorization = AuthorizationProof::System { reason: "r".into() };
    let short = body_with(
        AuditAction::ConfigReloaded,
        authorization.clone(),
        AuditOutcome::failure("disk full"),
    );
    let long = body_with(
        AuditAction::ConfigReloaded,
        authorization,
        AuditOutcome::failure("disk full!"),
    );
    assert_ne!(short, long);
}

#[test]
fn json_params_map_to_unambiguous_cbor() {
    let value = serde_json::json!({
        "b": -2,
        "aa": [null, true, 18_446_744_073_709_551_615_u64],
        "c": 0.5,
        "d": "0.5",
    });
    // Keys sort by encoding: "b", "c", "d", then "aa". -2 is a negative
    // integer; 0.5 is its JSON text as a byte string, distinct from the
    // string "0.5".
    assert_eq!(
        hex::encode(to_cbor(&value).encode()),
        "a4616221616343302e35616463302e3562616183f6f51bffffffffffffffff"
    );
}

#[test]
fn salts_differ_per_field_and_per_entry() {
    let registry = kat_registry();
    let entry = kat_entry(&registry);
    let salts: Vec<[u8; 16]> = entry
        .v2_field_disclosures()
        .unwrap()
        .iter()
        .map(|disclosure| disclosure.salt)
        .collect();
    let mut unique = salts.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), salts.len());

    let first = AuditEntry::create_v2(
        draft(
            &registry,
            &kat_session(),
            None,
            None,
            AuditAction::FileRead { path: "/a".into() },
        ),
        &key(1),
    )
    .unwrap();
    let second = AuditEntry::create_v2(
        draft(
            &registry,
            &kat_session(),
            None,
            None,
            AuditAction::FileRead { path: "/a".into() },
        ),
        &key(1),
    )
    .unwrap();
    assert_ne!(
        first.v2_field_disclosures().unwrap()[0].commitment,
        second.v2_field_disclosures().unwrap()[0].commitment,
        "the same low-entropy value must not produce a guessable commitment"
    );
}
