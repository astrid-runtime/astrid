//! Interoperable typed form elicitation for the MCP stdio shim.
//!
//! `rmcp::Peer::elicit::<T>()` derives a JSON schema with top-level `title`
//! and, when the Rust type has documentation, `description` annotations.
//! Those annotations are optional in MCP form elicitation, and strict clients
//! such as Codex reject them before presenting the user prompt. Keep the
//! strongly typed response path while emitting the smallest interoperable
//! top-level schema.

use rmcp::ErrorData as McpError;
use rmcp::model::{ElicitRequestParams, ElicitationAction, ElicitationSchema};
use rmcp::service::{
    ElicitationError, ElicitationMode, ElicitationSafe, Peer, RoleServer, ServiceError,
};

/// Build the restricted form schema accepted by strict MCP clients.
fn interoperable_schema<T>() -> Result<ElicitationSchema, ElicitationError>
where
    T: ElicitationSafe,
{
    let mut schema = ElicitationSchema::from_type::<T>().map_err(|error| {
        ElicitationError::Service(ServiceError::McpError(McpError::invalid_params(
            format!(
                "Invalid schema for type {}: {error}",
                std::any::type_name::<T>()
            ),
            None,
        )))
    })?;

    // Optional annotations add no validation or authority. Omitting them keeps
    // the wire schema compatible with clients whose typed MCP parser accepts
    // only `$schema`, `type`, `properties`, and `required` at the top level.
    schema.title = None;
    schema.description = None;
    Ok(schema)
}

/// Elicit a typed form while using the restricted interoperable wire schema.
///
/// This intentionally mirrors `rmcp::Peer::elicit`: the capability check,
/// response decoding, and error semantics remain identical. Only optional
/// top-level schema annotations are removed.
pub(super) async fn elicit<T>(
    peer: &Peer<RoleServer>,
    message: impl Into<String>,
) -> Result<Option<T>, ElicitationError>
where
    T: ElicitationSafe + for<'de> serde::Deserialize<'de>,
{
    if !peer
        .supported_elicitation_modes()
        .contains(&ElicitationMode::Form)
    {
        return Err(ElicitationError::CapabilityNotSupported);
    }

    let response = peer
        .create_elicitation(ElicitRequestParams::FormElicitationParams {
            meta: None,
            message: message.into(),
            requested_schema: interoperable_schema::<T>()?,
        })
        .await?;

    match response.action {
        ElicitationAction::Accept => match response.content {
            Some(value) => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|error| ElicitationError::ParseError { error, data: value }),
            None => Err(ElicitationError::NoContent),
        },
        ElicitationAction::Decline => Err(ElicitationError::UserDeclined),
        // This covers `Cancel` and future variants because
        // `ElicitationAction` is non-exhaustive. An unknown action cannot
        // imply consent until Astrid understands its semantics, so fail closed.
        _ => Err(ElicitationError::UserCancelled),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use rmcp::schemars::{self, JsonSchema};
    use serde::Deserialize;

    use super::*;

    /// Documentation deliberately makes schemars derive top-level annotations.
    #[derive(Deserialize, JsonSchema)]
    struct DocumentedForm {
        /// Whether to allow the operation.
        allow: bool,
    }

    rmcp::elicit_safe!(DocumentedForm);

    #[test]
    fn strips_annotations_rejected_by_strict_clients() {
        let derived = ElicitationSchema::from_type::<DocumentedForm>()
            .expect("documented form should produce an elicitation schema");
        assert!(derived.title.is_some());

        let schema = interoperable_schema::<DocumentedForm>()
            .expect("interoperable form schema should build");
        assert!(schema.title.is_none());
        assert!(schema.description.is_none());

        let wire = serde_json::to_value(schema).expect("schema should serialize");
        let keys: BTreeSet<_> = wire
            .as_object()
            .expect("elicitation schema should be an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, BTreeSet::from(["properties", "required", "type"]));
        assert_eq!(wire["properties"]["allow"]["type"], "boolean");
    }

    #[test]
    fn typed_form_remains_elicitation_safe() {
        let schema = interoperable_schema::<DocumentedForm>();
        assert!(schema.is_ok(), "typed form must remain valid: {schema:?}");
    }
}
