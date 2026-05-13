//! Helpers for surfaces deferred to a later kernel layer.
//!
//! Issue #657 phases the CLI redesign across multiple landings. The
//! admin-surface bulk lands now (Layer 6 #672 merged); sub-agent
//! delegation, vouchers, audit, trust, and remote A2A flows wait on
//! later issues. These commands are *registered* in the clap tree so
//! `astrid --help` documents the full surface and CI scripts written
//! against the future shape fail with a clear, actionable error rather
//! than a clap parse error that looks like the script is malformed.

use std::process::ExitCode;

/// Tracking issue with a one-line label.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TrackingIssue {
    /// GitHub issue number.
    pub number: u32,
    /// Short human label describing what the issue covers.
    pub label: &'static str,
}

impl TrackingIssue {
    /// Build the URL for the issue in the upstream repo.
    pub(crate) fn url(self) -> String {
        format!(
            "https://github.com/unicity-astrid/astrid/issues/{}",
            self.number
        )
    }
}

/// Print a "deferred until issue X ships" message to stderr and exit
/// with code 2. The caller is expected to use this from the leaf of a
/// stubbed clap subcommand handler.
///
/// The exit code distinguishes a deferred surface (2) from a runtime
/// error (1) so CI can pattern-match: `astrid voucher create ... ; if
/// [ $? -eq 2 ]; then skip; fi`.
pub(crate) fn deferred(feature: &str, issues: &[TrackingIssue]) -> ExitCode {
    eprintln!("astrid: {feature} is not available in this release.");
    if issues.len() == 1 {
        let issue = issues[0];
        eprintln!(
            "  Tracking issue #{} ({}) — see {}",
            issue.number,
            issue.label,
            issue.url()
        );
    } else {
        eprintln!("  Tracking issues:");
        for issue in issues {
            eprintln!("    #{} ({}) — {}", issue.number, issue.label, issue.url());
        }
    }
    ExitCode::from(2)
}

// ── Tracking-issue constants ────────────────────────────────────────

/// #656 — Sub-agent delegation, capability vouchers, OS-level enforcement.
pub(crate) const ISSUE_DELEGATION: TrackingIssue = TrackingIssue {
    number: 656,
    label: "sub-agent delegation, capability vouchers, OS-level enforcement",
};

/// #658 — Remote auth + A2A endpoints.
pub(crate) const ISSUE_REMOTE_AUTH: TrackingIssue = TrackingIssue {
    number: 658,
    label: "remote CLI auth + A2A endpoints",
};

/// #675 — Layer 7 audit trail (per-principal routing + admin queries).
pub(crate) const ISSUE_AUDIT: TrackingIssue = TrackingIssue {
    number: 675,
    label: "Layer 7 audit log routing",
};

/// #653 — Production multi-tenancy (parent of the budget admin IPC track).
pub(crate) const ISSUE_BUDGET: TrackingIssue = TrackingIssue {
    number: 653,
    label: "kernel-side budget admin IPC",
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_matches_template() {
        assert_eq!(
            ISSUE_DELEGATION.url(),
            "https://github.com/unicity-astrid/astrid/issues/656"
        );
    }

    #[test]
    fn deferred_returns_exit_code_two() {
        // Capture exit code: ExitCode::from(2) compares equal to itself.
        let code = deferred("test", &[ISSUE_DELEGATION]);
        // ExitCode does not implement PartialEq publicly; use Debug
        // formatting as a proxy.
        let s = format!("{code:?}");
        assert!(s.contains('2'), "expected exit code 2, got {s}");
    }
}
