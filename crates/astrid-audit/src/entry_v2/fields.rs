//! Sections: the action, authorization and outcome of an entry, taken from
//! their stored serde form so that every variant, present and future, is
//! encoded by one rule.
//!
//! Each of the three enums is an internally tagged serde enum. Its stored
//! JSON form is an object with one tag member naming the variant (`type` for
//! actions and authorizations, `status` for outcomes) and one member per
//! field. A section carries the tag as its kind and every other member as a
//! committed field keyed by the member name. A new variant, or a new optional
//! field skipped when absent, therefore needs no change here or in the
//! specification, and leaves the encoding of existing entries unchanged.

use serde::Serialize;
use serde_json::Value;

use super::cbor::Cbor;
use super::json;
use crate::entry::{AuditAction, AuditOutcome, AuthorizationProof};
use crate::error::{AuditError, AuditResult};

/// A section before commitments are computed: its kind and each field's
/// name and CBOR value, in the stored member order (the body sorts them).
#[derive(Clone, Debug)]
pub(super) struct Section {
    pub(super) kind: String,
    pub(super) fields: Vec<(String, Cbor)>,
}

/// Serde tag member of [`AuditAction`] and [`AuthorizationProof`].
const TYPE_TAG: &str = "type";
/// Serde tag member of [`AuditOutcome`].
const STATUS_TAG: &str = "status";

pub(super) fn section_of<T: Serialize>(value: &T, tag: &str, what: &str) -> AuditResult<Section> {
    let unencodable = |reason: &str| {
        AuditError::SerializationError(format!("cannot encode the {what} of a v2 entry: {reason}"))
    };
    let value = serde_json::to_value(value).map_err(|error| unencodable(&error.to_string()))?;
    let Value::Object(mut members) = value else {
        return Err(unencodable("its serde form is not an object"));
    };
    let Some(Value::String(kind)) = members.remove(tag) else {
        return Err(unencodable("its serde form has no text tag"));
    };
    Ok(Section {
        kind,
        fields: members
            .iter()
            .map(|(name, value)| (name.clone(), json::to_cbor(value)))
            .collect(),
    })
}

/// Section 9: the audited action.
pub(super) fn action_section(action: &AuditAction) -> AuditResult<Section> {
    section_of(action, TYPE_TAG, "action")
}

/// Section 10: how the action was authorized.
pub(super) fn authorization_section(authorization: &AuthorizationProof) -> AuditResult<Section> {
    section_of(authorization, TYPE_TAG, "authorization")
}

/// Section 11: the full outcome.
pub(super) fn outcome_section(outcome: &AuditOutcome) -> AuditResult<Section> {
    section_of(outcome, STATUS_TAG, "outcome")
}
