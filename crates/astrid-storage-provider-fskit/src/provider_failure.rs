//! CLI-valid structured provider failures.

use astrid_core::storage_provider::StorageProviderFailureV1;

/// Stable failure code for a missing or disabled macOS `FSKit` extension.
pub(crate) const FSKIT_EXTENSION_UNAVAILABLE_CODE: &str = "fskit-extension-unavailable";

/// Message token that upgrade proofs may treat as a named `FSKit` gap.
const FSKIT_EXTENSION_UNAVAILABLE_TOKEN: &str = "FSKIT_EXTENSION_UNAVAILABLE";

/// Protocol ceiling that must match CLI `render_response` (`message.len() <= 4096`).
/// This is a wire-format guard, not an operator knob.
const MAX_FAILURE_MESSAGE_BYTES: usize = 4096;
const PROVIDER_OPERATION_CODE: &str = "provider-operation";

/// Convert a native operation error into a CLI-valid structured failure.
pub(crate) fn provider_failure(error: &anyhow::Error) -> StorageProviderFailureV1 {
    let chained = format!("{error:#}");
    let rollback_failed = chained.contains("mount rollback incomplete")
        || chained.contains("rollback left the lease");
    let code = if chained.contains(FSKIT_EXTENSION_UNAVAILABLE_TOKEN) && !rollback_failed {
        FSKIT_EXTENSION_UNAVAILABLE_CODE
    } else {
        PROVIDER_OPERATION_CODE
    };
    StorageProviderFailureV1 {
        code: code.to_owned(),
        message: sanitize_provider_message(&error.to_string()),
    }
}

fn sanitize_provider_message(message: &str) -> String {
    let mut out = String::new();
    for ch in message.chars() {
        let next = if ch.is_control() { ' ' } else { ch };
        match out.len().checked_add(next.len_utf8()) {
            Some(next_len) if next_len <= MAX_FAILURE_MESSAGE_BYTES => out.push(next),
            _ => break,
        }
    }
    let trimmed = out.trim();
    if trimmed.is_empty() {
        "provider operation failed".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount_failure::{
        NativeMountFailure, classify_native_mount_failure, native_mount_failure_message,
    };

    #[test]
    fn helper_output_round_trips_json_as_a_named_cli_valid_gap() {
        let classified = classify_native_mount_failure(
            Some(72),
            "mount_astridfs: first line\nsecond line",
            "stdout hint",
        );
        assert!(matches!(
            classified,
            NativeMountFailure::ExtensionUnavailable { code: Some(72), .. }
        ));
        let error = anyhow::anyhow!(native_mount_failure_message(&classified));
        let failure = provider_failure(&error);
        let json = serde_json::to_vec(&failure).expect("encode structured failure");
        let decoded: StorageProviderFailureV1 =
            serde_json::from_slice(&json).expect("decode structured failure");
        assert_eq!(decoded.code, FSKIT_EXTENSION_UNAVAILABLE_CODE);
        assert!(decoded.message.contains(FSKIT_EXTENSION_UNAVAILABLE_TOKEN));
        assert!(
            !decoded.message.chars().any(char::is_control),
            "JSON message must be CLI-renderable: {:?}",
            decoded.message
        );
        assert!(decoded.message.len() <= MAX_FAILURE_MESSAGE_BYTES);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&json)
                .expect("json value")
                .get("code")
                .and_then(serde_json::Value::as_str),
            Some(FSKIT_EXTENSION_UNAVAILABLE_CODE)
        );
    }

    #[test]
    fn rollback_failure_stays_a_generic_operation_error() {
        let outer = anyhow::anyhow!("FSKIT_EXTENSION_UNAVAILABLE: missing")
            .context("mount rollback incomplete: revoke: kernel refused");
        let failure = provider_failure(&outer);
        let json = serde_json::to_vec(&failure).expect("encode rollback failure");
        let decoded: StorageProviderFailureV1 =
            serde_json::from_slice(&json).expect("decode rollback failure");
        assert_eq!(decoded.code, PROVIDER_OPERATION_CODE);
        assert!(decoded.message.contains("mount rollback incomplete"));
        assert!(!decoded.message.contains('\n'));
    }

    #[test]
    fn control_only_messages_get_a_non_empty_fallback() {
        let failure = provider_failure(&anyhow::anyhow!("\n\r\t"));
        assert_eq!(failure.code, PROVIDER_OPERATION_CODE);
        assert_eq!(failure.message, "provider operation failed");
        assert!(failure.message.len() <= MAX_FAILURE_MESSAGE_BYTES);
    }

    #[test]
    fn oversize_messages_are_truncated_to_the_cli_byte_bound() {
        let failure = provider_failure(&anyhow::anyhow!("x".repeat(5000)));
        assert_eq!(failure.message.len(), MAX_FAILURE_MESSAGE_BYTES);
        assert!(!failure.message.chars().any(char::is_control));
    }
}
