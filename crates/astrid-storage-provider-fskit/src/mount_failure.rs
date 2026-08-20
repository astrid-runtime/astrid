//! Classify native FSKit mount failures without treating every error as a gap.

/// Stable sentinel for "the Astrid FSKit extension is not installed or enabled".
///
/// Upgrade proofs and CI may record a named gap only when this exact token is
/// present. Generic mount, permission, lease, and rollback failures must not
/// emit it.
pub(crate) const FSKIT_EXTENSION_UNAVAILABLE: &str = "FSKIT_EXTENSION_UNAVAILABLE";

/// Outcome of a failed `/sbin/mount -t astridfs` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NativeMountFailure {
    /// Missing, unsigned, or disabled `astridfs.fs` extension.
    ExtensionUnavailable {
        /// Process exit code from `/sbin/mount`, if any.
        code: Option<i32>,
        /// Combined stderr/stdout from the mount helper.
        detail: String,
    },
    /// Any other native failure. Must hard-fail proofs.
    Other {
        /// Process exit code from `/sbin/mount`, if any.
        code: Option<i32>,
        /// Combined stderr/stdout from the mount helper.
        detail: String,
    },
}

/// Decide whether a native mount failure is an unavailable extension.
///
/// macOS reports missing FSKit filesystem types as exit status 72. Other
/// signals are exact extension-path or filesystem-type text. Generic
/// "FSKit mount failed" and rollback strings are not sufficient.
pub(crate) fn classify_native_mount_failure(
    code: Option<i32>,
    stderr: &str,
    stdout: &str,
) -> NativeMountFailure {
    let detail = combined_output(stderr, stdout);
    let lower = detail.to_ascii_lowercase();
    let extension_unavailable = code == Some(72)
        || lower.contains("astridfs.fs")
        || lower.contains("not installed beside")
        || lower.contains("unknown filesystem")
        || lower.contains("file system not found")
        || lower.contains("no such file system")
        || (lower.contains("unsigned") && lower.contains("astridfs"));
    if extension_unavailable {
        NativeMountFailure::ExtensionUnavailable { code, detail }
    } else {
        NativeMountFailure::Other { code, detail }
    }
}

/// Render a native mount failure for provider stderr and caller logs.
pub(crate) fn native_mount_failure_message(failure: &NativeMountFailure) -> String {
    match failure {
        NativeMountFailure::ExtensionUnavailable { code, detail } => {
            format!(
                "{FSKIT_EXTENSION_UNAVAILABLE}: macOS FSKit extension is not installed or enabled (mount status {code:?}): {detail}"
            )
        },
        NativeMountFailure::Other { code, detail } => {
            format!("macOS FSKit mount failed with status {code:?}: {detail}")
        },
    }
}

fn combined_output(stderr: &str, stdout: &str) -> String {
    match (stderr.trim().is_empty(), stdout.trim().is_empty()) {
        (true, true) => String::new(),
        (false, true) => stderr.trim().to_owned(),
        (true, false) => stdout.trim().to_owned(),
        (false, false) => format!("{}\n{}", stderr.trim(), stdout.trim()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_72_is_extension_unavailable() {
        let failure = classify_native_mount_failure(Some(72), "mount_astridfs failed", "");
        assert!(matches!(
            failure,
            NativeMountFailure::ExtensionUnavailable { code: Some(72), .. }
        ));
        let message = native_mount_failure_message(&failure);
        assert!(message.contains(FSKIT_EXTENSION_UNAVAILABLE));
        assert!(message.contains("not installed or enabled"));
    }

    #[test]
    fn generic_status_one_is_not_a_gap() {
        let failure = classify_native_mount_failure(
            Some(1),
            "macOS FSKit mount failed with exit status: 1",
            "",
        );
        assert!(matches!(
            failure,
            NativeMountFailure::Other { code: Some(1), .. }
        ));
        let message = native_mount_failure_message(&failure);
        assert!(
            !message.contains(FSKIT_EXTENSION_UNAVAILABLE),
            "generic mount failure must not mint the gap sentinel: {message}"
        );
        assert!(message.contains("macOS FSKit mount failed with status"));
    }

    #[test]
    fn rollback_text_alone_is_not_a_gap() {
        let failure = classify_native_mount_failure(
            Some(1),
            "mount rollback incomplete: revoke: kernel refused storage lifecycle request",
            "",
        );
        assert!(matches!(failure, NativeMountFailure::Other { .. }));
        assert!(!native_mount_failure_message(&failure).contains(FSKIT_EXTENSION_UNAVAILABLE));
    }

    #[test]
    fn missing_bundle_text_is_extension_unavailable() {
        let failure = classify_native_mount_failure(
            Some(1),
            "astridfs.fs is not installed beside the provider",
            "",
        );
        assert!(matches!(
            failure,
            NativeMountFailure::ExtensionUnavailable { .. }
        ));
        assert!(native_mount_failure_message(&failure).contains(FSKIT_EXTENSION_UNAVAILABLE));
    }
}
