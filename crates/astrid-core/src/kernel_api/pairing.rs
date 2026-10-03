//! Device pairing capability-scope wire contract.

use serde::{Deserialize, Serialize};

/// Requested capability scope for a [`super::AdminRequestKind::PairDeviceIssue`]
/// token — what the redeemed device is allowed to do with the principal's
/// authority.
///
/// The kernel resolves this against the ISSUER's *effective* capability set at
/// issue time (no-escalation: a device can never confer more than the issuer
/// holds, where the issuer's effective set is itself narrowed by the issuer's
/// own authenticating device scope) and stamps the resolved
/// [`DeviceScope`](crate::DeviceScope) onto the minted token, so the redeemed
/// device is attenuated to exactly the granted scope on every transport.
///
/// On the wire it is an internally-tagged object: `{ "kind": "full" }`,
/// `{ "kind": "preset", "name": "use-only" }`, or
/// `{ "kind": "explicit", "allow": [...], "deny": [...] }`. The `scope` field
/// on `PairDeviceIssue` defaults to [`PairScopeArg::Full`] when omitted, so
/// pre-scope callers (and single-tenant admin flows) keep their existing
/// behaviour — but minting a `Full` device additionally requires the issuer to
/// hold `self:auth:pair:admin`, enforced by the authorization preamble and
/// rechecked with the issuer's pinned policy snapshot before persistence.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PairScopeArg {
    /// Mint an unattenuated device — it acts with the principal's full
    /// effective capability set. Requires the issuer to hold
    /// `self:auth:pair:admin`. The default when `scope` is omitted (the
    /// permissive default is still gated on the admin cap, so it does not
    /// relax authority).
    #[default]
    Full,
    /// Resolve a named scope preset (e.g. `"use-only"`) via
    /// [`DeviceScope::preset`](crate::DeviceScope::preset). An unknown name is
    /// rejected at issue time.
    Preset {
        /// The preset name.
        name: String,
    },
    /// An explicit allow/deny capability scope. Every `allow` pattern must be
    /// held by the issuer (subset check); `deny` patterns purely restrict.
    Explicit {
        /// Capability patterns the device may exercise.
        #[serde(default)]
        allow: Vec<String>,
        /// Capability patterns the device is forbidden to exercise (deny wins).
        #[serde(default)]
        deny: Vec<String>,
    },
}

/// Serde default for [`super::AdminRequestKind::PairDeviceIssue::scope`] — `Full`,
/// for back-compat with callers that predate the `scope` field. A `Full` mint
/// is independently gated on `self:auth:pair:admin`, so the permissive
/// *default* does not relax the *authority* required to use it.
pub(super) fn default_pair_scope() -> PairScopeArg {
    PairScopeArg::Full
}
