//! Shared grammar and validation for static capability strings (issue #670).
//!
//! The management-API policy model uses a colon-delimited identifier
//! namespace for capabilities:
//!
//! ```text
//! capability  := segment (':' segment)*
//! segment     := '*' | [a-zA-Z0-9_-]+
//! ```
//!
//! This is a **different namespace** from the runtime
//! [`CapabilityToken`](../../../astrid-capabilities/src/token.rs) resource
//! patterns (URI-based `mcp://server:tool`, globset-powered). Static
//! capabilities identify role membership and are stored in principal
//! profiles and group configs; runtime tokens gate individual tool calls.
//!
//! The grammar is deliberately restrictive — ASCII-only, no shell
//! metacharacters, no double-glob — so that capability strings round-trip
//! through TOML and the audit log without escaping surprises.

use thiserror::Error;

/// Upper bound on the total length of a capability pattern, in bytes.
///
/// A single capability identifier never legitimately approaches this
/// limit; the cap exists purely to reject pathological entries before
/// they reach the matcher.
pub const MAX_CAPABILITY_LEN: usize = 256;

/// Capability that exempts a principal from per-principal capsule resource
/// bounds (run-loop CPU epoch interrupt + linear-memory cap).
///
/// A principal holding this capability — directly, via a grant, or via a
/// group whose capability set matches it (the built-in `admin` group's `*`
/// matches everything) — runs its capsules **unbounded**: never
/// epoch-interrupt-trapped, and the full
/// [`DEFAULT_MAX_MEMORY_BYTES`](crate::DEFAULT_MAX_MEMORY_BYTES) linear-memory
/// ceiling.
///
/// The exemption axis is the **capability**, never a group-name string match:
/// admin is unbounded automatically because `*` matches this string
/// ([`capability_matches`](crate::capability_matches)), with no special case.
/// A capsule can never influence its own exemption — it does not choose its
/// load principal (always [`PrincipalId::default`](crate::PrincipalId::default))
/// nor its operator-owned profile capabilities. The grammar already accepts
/// this string (colon-delimited `a-zA-Z0-9_-` segments); no grammar change is
/// needed. The default for every non-holder is **bounded** (fail-secure).
pub const CAP_RESOURCES_UNBOUNDED: &str = "system:resources:unbounded";

/// Capability that authorizes a principal to bind/accept network sockets
/// (the CLI/web/Discord uplink proxy pattern).
///
/// This is the **principal-profile** capability — operator/user-granted via
/// groups or grants — NOT the capsule-authored `[capabilities] net_bind`
/// manifest field. The manifest field is untrusted self-declaration; THIS
/// string is what an operator grants a trusted uplink's load principal. A
/// holder's run-loop is exempt from the per-principal CPU+memory bound,
/// because a uplink legitimately blocks indefinitely on socket-accept and
/// must never be epoch-trapped. admin holds it via `*`. A capsule that merely
/// *declares* `net_bind` in its own manifest without the principal holding
/// this granted capability is **bounded** (not exempt). Bare single segment,
/// grammar-valid (`a-zA-Z0-9_-`); no grammar change needed.
pub const CAP_NET_BIND: &str = "net_bind";

/// Capability that authorizes a principal to register as a long-lived uplink
/// daemon (parallel to [`CAP_NET_BIND`] for the manifest `uplink` bool).
///
/// Operator/user-granted on the principal profile; a holder's run-loop is
/// exempt from the per-principal CPU+memory bound for the same reason as
/// [`CAP_NET_BIND`] — a uplink daemon blocks indefinitely and must not be
/// epoch-trapped. admin holds it via `*`. Manifest self-declaration of
/// `uplink` does NOT confer it.
pub const CAP_UPLINK: &str = "uplink";

/// The capabilities that exempt a principal from the per-principal CPU+memory
/// bound — the single source of truth shared by every site that decides
/// exemption.
///
/// A principal is exempt iff it holds ANY of these (admin matches all three via
/// `*`). Both the enforcement path
/// (`astrid_capsule::engine::wasm::resolve_exemption`) and the read path
/// (`astrid quota`'s usage report) iterate this array, so displayed-exempt can
/// never drift from enforced-exempt — adding or removing an exemption is a
/// one-line edit here, reflected on both sides. The default for a holder of
/// none is **bounded** (fail-secure).
pub const EXEMPT_CAPABILITIES: [&str; 3] = [CAP_RESOURCES_UNBOUNDED, CAP_NET_BIND, CAP_UPLINK];

/// Errors raised by [`validate_capability`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapabilityGrammarError {
    /// Capability string is empty.
    #[error("capability must not be empty")]
    Empty,
    /// Capability string exceeds [`MAX_CAPABILITY_LEN`] bytes.
    #[error("capability exceeds {MAX_CAPABILITY_LEN} bytes")]
    TooLong,
    /// Capability contains the double-glob sequence `**` (reserved).
    #[error("capability may not contain '**' (double glob is reserved)")]
    DoubleStar,
    /// A segment between `:` separators is empty (leading, trailing,
    /// or consecutive colons).
    #[error("capability contains an empty segment (leading, trailing, or consecutive ':')")]
    EmptySegment,
    /// A segment contains a character outside the allowed grammar.
    #[error(
        "capability segment {segment:?} contains invalid character {bad:?} (allowed: a-z, A-Z, 0-9, -, _, or literal '*')"
    )]
    InvalidCharacter {
        /// Segment that failed validation.
        segment: String,
        /// First offending character.
        bad: char,
    },
    /// A segment mixes `*` with other characters (e.g. `foo*`).
    #[error(
        "capability segment {segment:?} mixes '*' with other characters; '*' must stand alone in a segment"
    )]
    PartialStar {
        /// Segment that failed validation.
        segment: String,
    },
}

/// Validate a capability string against the colon-delimited grammar.
///
/// Accepts both exact identifiers (`system:shutdown`) and patterns
/// (`self:*`, `a:*:b`, `*`). Rejects empty segments, double-globs,
/// non-ASCII characters, shell metacharacters, and segments that mix
/// `*` with literal characters.
///
/// # Errors
///
/// Returns the first [`CapabilityGrammarError`] encountered; rule order
/// is not part of the public contract.
pub fn validate_capability(cap: &str) -> Result<(), CapabilityGrammarError> {
    if cap.is_empty() {
        return Err(CapabilityGrammarError::Empty);
    }
    if cap.len() > MAX_CAPABILITY_LEN {
        return Err(CapabilityGrammarError::TooLong);
    }
    if cap.contains("**") {
        return Err(CapabilityGrammarError::DoubleStar);
    }
    for segment in cap.split(':') {
        if segment.is_empty() {
            return Err(CapabilityGrammarError::EmptySegment);
        }
        if segment == "*" {
            continue;
        }
        if segment.contains('*') {
            return Err(CapabilityGrammarError::PartialStar {
                segment: segment.to_string(),
            });
        }
        if let Some(bad) = segment
            .chars()
            .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
        {
            return Err(CapabilityGrammarError::InvalidCharacter {
                segment: segment.to_string(),
                bad,
            });
        }
    }
    Ok(())
}

/// Test whether a capability `pattern` matches the concrete capability
/// `cap`. Both inputs are expected to be pre-validated via
/// [`validate_capability`]; behaviour on malformed input is unspecified.
///
/// Matching rules:
///
/// - `*` alone matches any capability.
/// - A trailing `*` segment (`self:*`) matches one-or-more remaining
///   segments (`self:capsule:install`).
/// - A `*` segment elsewhere matches exactly one segment.
/// - Otherwise segments must match literally and the segment counts
///   must agree.
#[must_use]
pub fn capability_matches(pattern: &str, cap: &str) -> bool {
    if pattern == "*" {
        return true;
    }

    // Walk both strings segment-by-segment with iterators — no Vec
    // allocation on the hot path. The enforcement preamble evaluates
    // this on every admin-API request and per-group-capability, so
    // saving the two `Vec<&str>` collections is worthwhile.
    let mut pat_iter = pattern.split(':').peekable();
    let mut cap_iter = cap.split(':');

    loop {
        match (pat_iter.next(), cap_iter.next()) {
            (Some("*"), Some(_)) => {
                // Trailing `*` absorbs every remaining resource segment.
                // A middle `*` matches exactly one and we continue the loop.
                if pat_iter.peek().is_none() {
                    return true;
                }
            },
            (Some(p), Some(c)) => {
                if p != c {
                    return false;
                }
            },
            (None, None) => return true,
            // Pattern and resource had different segment counts.
            (Some(_), None) | (None, Some(_)) => return false,
        }
    }
}

/// Coarse category for dashboard grouping. Dashboards bucket
/// capabilities by category to render permissions panels
/// Discord-style (one collapsible section per family).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityCategory {
    /// Agent (principal) lifecycle: create, delete, enable, modify, list.
    Agent,
    /// Direct capability grants and revokes on a principal.
    Caps,
    /// Per-principal resource quotas (RAM / CPU / IPC).
    Quota,
    /// Capability-group definitions and memberships.
    Group,
    /// Invite-token lifecycle for onboarding new principals.
    Invite,
    /// Capsule install / list / reload / inspect.
    Capsule,
    /// Daemon-wide system operations (status, shutdown).
    System,
    /// Approval responses for capability requests held in escrow.
    Approval,
}

/// Self vs global scope. `Self_` capabilities only let a principal
/// act on their own state; `Global` lets the holder act on every
/// principal. The kernel's static tables determine which form
/// applies to which operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityScope {
    /// Operation targets the caller's own principal only.
    #[serde(rename = "self")]
    Self_,
    /// Operation can target any principal / system-wide state.
    Global,
}

/// Risk tier for dashboard rendering. Dashboards use this to decide
/// whether to require a confirmation prompt, paint the toggle red,
/// or hide the capability behind an "advanced" disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityDanger {
    /// Read-only or limited to the caller's own state. No
    /// cross-principal effects.
    Safe,
    /// Routine mutation visible to others (e.g. `agent:create`).
    Normal,
    /// Permission management — grants / revokes / group edits.
    /// Compounds: holding it lets the principal grant more caps to
    /// themselves or others. Confirmation prompt recommended.
    Elevated,
    /// System-wide impact (`system:shutdown`, `capsule:install`).
    /// Confirmation + audit emphasis strongly recommended.
    Extreme,
}

/// Structured catalog entry describing one capability.
///
/// Single source of truth shared by the kernel's drift tests and
/// the HTTP gateway's `/api/sys/capabilities` route. Dashboards
/// consume this directly to render permissions panels without
/// hardcoding any per-capability metadata client-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilityInfo {
    /// The capability identifier as it appears in policy. Stable
    /// wire format — never change without a policy-version bump.
    pub id: &'static str,
    /// Short human-readable label for the dashboard toggle.
    pub label: &'static str,
    /// One-sentence operator-facing description. Suitable for a
    /// tooltip or inline hint.
    pub description: &'static str,
    /// Family bucket for UI grouping.
    pub category: CapabilityCategory,
    /// Self vs global authority scope.
    pub scope: CapabilityScope,
    /// Risk tier for confirmation prompts.
    pub danger: CapabilityDanger,
}

/// Structured catalog of every static capability the kernel
/// recognises. **Single source of truth** for grantable
/// capabilities. Mirrors the static match tables in
/// `astrid-kernel::kernel_router::{required_capability,
/// admin::required_capability_for_admin_request}`.
///
/// Order is part of the public API — dashboards render in this
/// order for a stable display. Within each category the
/// `Global` variant precedes its `self:`-prefixed sibling so the
/// operator-facing form is the visual default.
pub const CAPABILITY_CATALOG: &[CapabilityInfo] = {
    use CapabilityCategory::{Agent, Approval, Caps, Capsule, Group, Invite, Quota, System};
    use CapabilityDanger::{Elevated, Extreme, Normal, Safe};
    use CapabilityScope::{Global, Self_};
    &[
        // ── System ──
        CapabilityInfo {
            id: "system:shutdown",
            label: "Shut down daemon",
            description: "Gracefully stop the Astrid daemon. The CLI and dashboard disconnect; pending work is allowed to finish under the configured shutdown grace period.",
            category: System,
            scope: Global,
            danger: Extreme,
        },
        CapabilityInfo {
            id: "system:status",
            label: "Read daemon status",
            description: "View daemon PID, uptime, connected-client count, and loaded-capsule list.",
            category: System,
            scope: Global,
            danger: Safe,
        },
        // ── Capsules ──
        CapabilityInfo {
            id: "capsule:install",
            label: "Install capsules",
            description: "Install a new capsule into the system-wide capsule directory. Affects every principal on the host.",
            category: Capsule,
            scope: Global,
            danger: Extreme,
        },
        CapabilityInfo {
            id: "self:capsule:install",
            label: "Install capsules (own workspace)",
            description: "Install a capsule into the caller's own workspace. Future kernel work; see also: capsule:install.",
            category: Capsule,
            scope: Self_,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "capsule:reload",
            label: "Reload all capsules",
            description: "Trigger a re-discovery of installed capsules system-wide. Causes a brief pause as capsules unload and reload.",
            category: Capsule,
            scope: Global,
            danger: Normal,
        },
        CapabilityInfo {
            id: "self:capsule:reload",
            label: "Reload capsules (self)",
            description: "Self-scoped variant of capsule:reload.",
            category: Capsule,
            scope: Self_,
            danger: Normal,
        },
        CapabilityInfo {
            id: "capsule:remove",
            label: "Remove capsules",
            description: "Remove an installed capsule from the system-wide capsule directory and unload it from the running daemon. Affects every principal on the host; reversible by reinstalling.",
            category: Capsule,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "self:capsule:remove",
            label: "Remove capsules (self)",
            description: "Self-scoped variant of capsule:remove.",
            category: Capsule,
            scope: Self_,
            danger: Normal,
        },
        CapabilityInfo {
            id: "capsule:list",
            label: "List all capsules",
            description: "Enumerate every capsule installed on the host, including manifest metadata.",
            category: Capsule,
            scope: Global,
            danger: Safe,
        },
        CapabilityInfo {
            id: "self:capsule:list",
            label: "List capsules (self)",
            description: "Self-scoped variant of capsule:list. Always granted to the agent built-in.",
            category: Capsule,
            scope: Self_,
            danger: Safe,
        },
        // ── Agents (principals) ──
        CapabilityInfo {
            id: "agent:create",
            label: "Create agents",
            description: "Provision a new agent principal. Doesn't grant any caps by itself — combine with caps:grant or move the new agent into a group.",
            category: Agent,
            scope: Global,
            danger: Normal,
        },
        CapabilityInfo {
            id: "agent:delete",
            label: "Delete agents",
            description: "Remove an agent principal. Cannot delete the bootstrap `default` principal. The principal's home directory is NOT scrubbed (ops concern).",
            category: Agent,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "agent:enable",
            label: "Enable agents",
            description: "Re-enable a previously disabled agent. New invocations resume.",
            category: Agent,
            scope: Global,
            danger: Normal,
        },
        CapabilityInfo {
            id: "agent:disable",
            label: "Disable agents",
            description: "Suspend an agent without deleting it. In-flight invocations finish under the old value; new ones are refused.",
            category: Agent,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "agent:modify",
            label: "Modify agent groups",
            description: "Add or remove group memberships on an agent. Changes which capabilities the agent inherits.",
            category: Agent,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "agent:list",
            label: "List all agents",
            description: "Enumerate every agent principal on this host with their groups, grants, and revokes.",
            category: Agent,
            scope: Global,
            danger: Safe,
        },
        CapabilityInfo {
            id: "self:agent:list",
            label: "View own agent row",
            description: "Read this principal's own AgentSummary. Always granted to the agent built-in so members can introspect their own permissions.",
            category: Agent,
            scope: Self_,
            danger: Safe,
        },
        // ── Quotas ──
        CapabilityInfo {
            id: "quota:set",
            label: "Set agent quotas",
            description: "Set resource ceilings (RAM, CPU time, IPC throughput) on any agent.",
            category: Quota,
            scope: Global,
            danger: Normal,
        },
        CapabilityInfo {
            id: "self:quota:set",
            label: "Set own quotas",
            description: "Self-scoped quota:set — typically only used to relax quotas the operator already permits.",
            category: Quota,
            scope: Self_,
            danger: Normal,
        },
        CapabilityInfo {
            id: "quota:get",
            label: "Read agent quotas",
            description: "View the resource ceilings configured on any agent.",
            category: Quota,
            scope: Global,
            danger: Safe,
        },
        CapabilityInfo {
            id: "self:quota:get",
            label: "Read own quotas",
            description: "Read the caller's own resource ceilings. Always granted to the agent built-in.",
            category: Quota,
            scope: Self_,
            danger: Safe,
        },
        // ── Groups ──
        CapabilityInfo {
            id: "group:create",
            label: "Create capability groups",
            description: "Define a new custom capability group. Members inherit the group's capabilities.",
            category: Group,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "group:delete",
            label: "Delete capability groups",
            description: "Remove a custom capability group. Built-in groups (admin, agent, restricted) cannot be deleted.",
            category: Group,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "group:modify",
            label: "Modify capability groups",
            description: "Edit the capabilities, description, or `unsafe_admin` flag on a custom group. Changes propagate to every member on the next authz check.",
            category: Group,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "group:list",
            label: "List all groups",
            description: "Enumerate every group (built-in + custom) with its capability set.",
            category: Group,
            scope: Global,
            danger: Safe,
        },
        CapabilityInfo {
            id: "self:group:list",
            label: "List groups (self-membership)",
            description: "Self-scoped group:list — for resolving the caller's own inherited capabilities. Always granted to the agent built-in.",
            category: Group,
            scope: Self_,
            danger: Safe,
        },
        // ── Caps (direct grant/revoke) ──
        CapabilityInfo {
            id: "caps:grant",
            label: "Grant capabilities",
            description: "Append capability patterns to a principal's grants. With `unsafe_admin`, can mint wildcard (`*`) grants. Effectively a meta-permission — anyone with this can elevate themselves.",
            category: Caps,
            scope: Global,
            danger: Extreme,
        },
        CapabilityInfo {
            id: "caps:revoke",
            label: "Revoke capabilities",
            description: "Append capability patterns to a principal's revokes (highest-precedence deny). Cannot revoke from the bootstrap `default` principal.",
            category: Caps,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "caps:token:mint",
            label: "Mint capability tokens",
            description: "Mint a signed capability token pre-granting a principal access to a resource (e.g. `mcp://server:tool`), bypassing per-use approval. An escalation primitive — anyone with this can pre-authorize tool access.",
            category: Caps,
            scope: Global,
            danger: Extreme,
        },
        CapabilityInfo {
            id: "caps:token:revoke",
            label: "Revoke capability tokens",
            description: "Revoke a previously minted capability token by id. Revocation is global and final — the token no longer authorizes for any principal.",
            category: Caps,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "caps:token:list",
            label: "List capability tokens",
            description: "List the non-revoked, non-expired capability tokens minted for a principal.",
            category: Caps,
            scope: Global,
            danger: Safe,
        },
        // ── Invites ──
        CapabilityInfo {
            id: "invite:issue",
            label: "Issue invite tokens",
            description: "Mint invite tokens that let new principals self-enroll into a designated group. The token IS the auth — anyone holding it can redeem.",
            category: Invite,
            scope: Global,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "invite:redeem",
            label: "Redeem invite tokens (no-op grant)",
            description: "Capability name preserved for completeness — the kernel bypasses the cap check on redemption because the token itself is the auth. Granting this to anyone is a no-op.",
            category: Invite,
            scope: Global,
            danger: Normal,
        },
        CapabilityInfo {
            id: "invite:list",
            label: "List outstanding invites",
            description: "Enumerate outstanding invite tokens by fingerprint (never the raw token).",
            category: Invite,
            scope: Global,
            danger: Safe,
        },
        CapabilityInfo {
            id: "invite:revoke",
            label: "Revoke invites",
            description: "Invalidate an outstanding invite token before it's redeemed.",
            category: Invite,
            scope: Global,
            danger: Normal,
        },
        // ── Audit ──
        CapabilityInfo {
            id: "audit:read_all",
            label: "View full audit firehose",
            description: "Subscribe to every audit entry across every principal via /api/events. Without this cap, the SSE stream is filtered to the caller's own entries only.",
            category: System,
            scope: Global,
            danger: Elevated,
        },
        // ── Approval ──
        CapabilityInfo {
            id: "self:approval:respond",
            label: "Approve own capability requests",
            description: "Respond to capability-approval prompts addressed to this principal. Always granted to the agent built-in (an agent can only approve its own requests, never another's).",
            category: Approval,
            scope: Self_,
            danger: Safe,
        },
        // ── Auth (pair-device) ──
        CapabilityInfo {
            id: "self:auth:pair",
            label: "Pair an additional device",
            description: "Mint a short-lived pair-device token that lets a new device add its ed25519 public key to this principal's AuthConfig.public_keys. The kernel always binds the token to the caller's own principal regardless of wire-level hints.",
            category: Approval,
            scope: Self_,
            danger: Normal,
        },
        CapabilityInfo {
            id: "self:auth:pair:admin",
            label: "Pair a full-scope device",
            description: "Mint a FULL-scope (unattenuated) pair-device token; a scoped device cannot. A device paired without this capability is restricted to a capability scope that can never widen the principal's effective permissions, so this gates the ability to add a device that acts with the principal's full authority.",
            category: Approval,
            scope: Self_,
            danger: Elevated,
        },
        CapabilityInfo {
            id: "auth:pair:redeem",
            label: "Redeem pair-device tokens (no-op grant)",
            description: "Capability name preserved for completeness — the kernel bypasses the cap check on pair-device redemption because the token itself is the auth. Granting this to anyone is a no-op.",
            category: Approval,
            scope: Global,
            danger: Normal,
        },
    ]
};

/// Borrow the catalog as a flat slice of ids — the historical shape
/// used by kernel drift tests. Now a thin view over
/// [`CAPABILITY_CATALOG`]; the structured catalog is the canonical
/// declaration.
///
/// Kept as a function rather than a `const` because the constant
/// version would require an extra hand-mirrored array; the function
/// makes the kernel-test drift check call
/// `known_capabilities().any(|c| c == cap)` which is unambiguous.
pub fn known_capabilities() -> impl Iterator<Item = &'static str> {
    CAPABILITY_CATALOG.iter().map(|c| c.id)
}

/// Backwards-compatible flat-list view. Materialises once on
/// first access and re-uses the cached slice on subsequent calls.
pub fn known_capabilities_list() -> &'static [&'static str] {
    static CACHED: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    CACHED.get_or_init(|| known_capabilities().collect())
}

/// Compile-time pin on the size of [`CAPABILITY_CATALOG`]. Bumped
/// in the same commit that adds a new capability so a kernel
/// addition without updating the catalog fails the consuming
/// crate's tests.
pub const KNOWN_CAPABILITIES_COUNT: usize = 40;

const _: () = assert!(
    CAPABILITY_CATALOG.len() == KNOWN_CAPABILITIES_COUNT,
    "KNOWN_CAPABILITIES_COUNT is stale; bump it when adding a capability"
);

#[cfg(test)]
mod tests {
    use super::*;

    // ── validate_capability ─────────────────────────────────────────────

    #[test]
    fn accepts_literal() {
        validate_capability("system:shutdown").unwrap();
        validate_capability("self:capsule:install").unwrap();
        validate_capability("audit:read:alice").unwrap();
        validate_capability("agent-007").unwrap();
    }

    #[test]
    fn accepts_universal_and_prefix_patterns() {
        validate_capability("*").unwrap();
        validate_capability("self:*").unwrap();
        validate_capability("a:*:b").unwrap();
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(validate_capability(""), Err(CapabilityGrammarError::Empty));
    }

    #[test]
    fn rejects_double_glob() {
        assert_eq!(
            validate_capability("**"),
            Err(CapabilityGrammarError::DoubleStar)
        );
        assert_eq!(
            validate_capability("self:**"),
            Err(CapabilityGrammarError::DoubleStar)
        );
        assert_eq!(
            validate_capability("**:read"),
            Err(CapabilityGrammarError::DoubleStar)
        );
    }

    #[test]
    fn rejects_empty_segment() {
        assert_eq!(
            validate_capability(":read"),
            Err(CapabilityGrammarError::EmptySegment)
        );
        assert_eq!(
            validate_capability("read:"),
            Err(CapabilityGrammarError::EmptySegment)
        );
        assert_eq!(
            validate_capability("a::b"),
            Err(CapabilityGrammarError::EmptySegment)
        );
    }

    #[test]
    fn rejects_shell_metachars() {
        for bad in [
            "system:shut down",
            "system:shutdown;rm",
            "system:`whoami`",
            "system:$(pwd)",
            "system:shutdown|id",
            "self:>log",
        ] {
            assert!(
                matches!(
                    validate_capability(bad),
                    Err(CapabilityGrammarError::InvalidCharacter { .. })
                ),
                "{bad:?} should be rejected",
            );
        }
    }

    #[test]
    fn rejects_partial_star() {
        assert!(matches!(
            validate_capability("self:foo*"),
            Err(CapabilityGrammarError::PartialStar { .. })
        ));
        assert!(matches!(
            validate_capability("*foo"),
            Err(CapabilityGrammarError::PartialStar { .. })
        ));
    }

    #[test]
    fn rejects_over_length() {
        let long = "a".repeat(MAX_CAPABILITY_LEN + 1);
        assert_eq!(
            validate_capability(&long),
            Err(CapabilityGrammarError::TooLong)
        );
    }

    // ── capability_matches ──────────────────────────────────────────────

    #[test]
    fn universal_matches_everything() {
        assert!(capability_matches("*", "system:shutdown"));
        assert!(capability_matches("*", "self:capsule:install"));
        assert!(capability_matches("*", "anything"));
    }

    #[test]
    fn exact_match() {
        assert!(capability_matches("system:shutdown", "system:shutdown"));
        assert!(!capability_matches("system:shutdown", "system:status"));
        assert!(!capability_matches(
            "system:shutdown",
            "self:system:shutdown"
        ));
    }

    #[test]
    fn trailing_star_matches_one_or_more() {
        assert!(capability_matches("self:*", "self:capsule"));
        assert!(capability_matches("self:*", "self:capsule:install"));
        assert!(capability_matches("self:*", "self:capsule:install:alice"));
        assert!(!capability_matches("self:*", "self"));
        assert!(!capability_matches("self:*", "capsule:install"));
    }

    #[test]
    fn middle_star_matches_single_segment() {
        assert!(capability_matches("a:*:b", "a:x:b"));
        assert!(!capability_matches("a:*:b", "a:x:y:b"));
        assert!(!capability_matches("a:*:b", "a:b"));
    }

    #[test]
    fn mixed_patterns() {
        assert!(capability_matches("audit:read:*", "audit:read:alice"));
        assert!(!capability_matches("audit:read:*", "audit:write:alice"));
    }
}
