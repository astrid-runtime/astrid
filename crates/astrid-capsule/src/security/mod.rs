//! Security gate trait for capsule host function calls.
//!
//! Decouples the capsule WASM runtime from the full security interceptor stack.
//! The production implementation ([`ManifestSecurityGate`]) lives in
//! [`manifest_gate`]. Test-only stubs ([`AllowAllGate`], [`DenyAllGate`]) live
//! in [`test_gates`].

use async_trait::async_trait;

mod manifest_gate;
#[cfg(test)]
mod test_gates;

pub(crate) use manifest_gate::{ManifestSecurityGate, net_connect_pattern_matches};
#[cfg(test)]
pub(crate) use test_gates::AllowAllGate;

/// Identity operations that can be gated by the security gate.
///
/// Typed enum prevents string-matching bugs. Each variant maps to a
/// required capability level in the manifest's `identity` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityOperation {
    /// Resolve a platform user to an AstridUserId (requires "resolve").
    Resolve,
    /// Create a platform link (requires "link").
    Link,
    /// Remove a platform link (requires "link").
    Unlink,
    /// List links for a user (requires "link").
    ListLinks,
    /// Create a new user (requires "admin").
    CreateUser,
}

impl IdentityOperation {
    /// Return the minimum capability level required for this operation.
    ///
    /// The hierarchy is: `admin > link > resolve`.
    #[must_use]
    pub fn required_capability(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Link | Self::Unlink | Self::ListLinks => "link",
            Self::CreateUser => "admin",
        }
    }
}

/// Check whether a set of declared capability strings satisfies a required level.
///
/// The hierarchy is `admin > link > resolve`. Having `"admin"` implies
/// `"link"` and `"resolve"`.
pub(super) fn identity_capability_satisfies(declared: &[String], required: &str) -> bool {
    // Direct match.
    if declared.iter().any(|d| d == required) {
        return true;
    }
    // Hierarchy: admin implies everything, link implies resolve.
    match required {
        "resolve" => declared.iter().any(|d| d == "link" || d == "admin"),
        "link" => declared.iter().any(|d| d == "admin"),
        _ => false,
    }
}

/// Security gate for capsule host function calls.
///
/// Each method corresponds to a class of sensitive operation that a WASM
/// capsule can request through host functions. Implementors decide whether
/// to permit or deny the operation.
#[async_trait]
pub trait CapsuleSecurityGate: Send + Sync {
    /// Check whether the capsule is allowed to make an HTTP request.
    async fn check_http_request(
        &self,
        capsule_id: &str,
        method: &str,
        url: &str,
    ) -> Result<(), String>;

    /// Check whether the capsule is allowed to read a file.
    ///
    /// `principal_home` overrides the construction-time `home_root` for
    /// per-invocation scoping. When `Some`, any `home://` pattern in the
    /// manifest allow-list resolves against that path instead. When `None`,
    /// the construction-time `home_root` (if any) is used — this is the
    /// single-tenant / boot-time path.
    async fn check_file_read(
        &self,
        capsule_id: &str,
        path: &str,
        principal_home: Option<&std::path::Path>,
    ) -> Result<(), String>;

    /// Check whether the capsule is allowed to write a file.
    ///
    /// See [`check_file_read`](CapsuleSecurityGate::check_file_read) for
    /// the `principal_home` semantics.
    async fn check_file_write(
        &self,
        capsule_id: &str,
        path: &str,
        principal_home: Option<&std::path::Path>,
    ) -> Result<(), String>;

    /// Check whether the capsule is allowed to spawn a host process.
    async fn check_host_process(&self, capsule_id: &str, command: &str) -> Result<(), String>;

    /// Check whether the capsule is allowed to accept connections on a bound socket.
    ///
    /// Default implementation denies all bind operations. Override to permit
    /// capsules that declare `net_bind` capabilities.
    ///
    /// NOTE: This method currently takes no socket path argument because the
    /// kernel pre-binds the socket and the path is not user-controllable.
    /// If future work introduces capsule-specified bind addresses, add a
    /// `socket_path: &str` parameter and enforce path-based confinement.
    async fn check_net_bind(&self, capsule_id: &str) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: net_bind not permitted (default)"
        ))
    }

    /// Check whether the capsule is allowed to open an outbound TCP connection.
    ///
    /// Default implementation denies. Override to permit capsules that
    /// declare `net_connect` capabilities matching `host:port`.
    ///
    /// The check is on the literal `host:port` the capsule passed to
    /// `net.connect-tcp`; DNS resolution and the SSRF airlock run
    /// kernel-side *after* this gate returns `Ok`.
    async fn check_net_connect(
        &self,
        capsule_id: &str,
        _host: &str,
        _port: u16,
    ) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: net_connect not permitted (default)"
        ))
    }

    /// Check whether the capsule is allowed to register a uplink.
    ///
    /// Default implementation permits all registrations. Override to enforce
    /// uplink policies (e.g. platform allowlists per capsule).
    ///
    /// RATIONALE: This has a permissive default (unlike the required file/HTTP
    /// methods) to maintain backward compatibility with existing
    /// `CapsuleSecurityGate` implementors. The `has_uplink_capability` flag
    /// on `HostState` already gates access - this method adds operator-level
    /// policy on top.
    async fn check_uplink_register(
        &self,
        _capsule_id: &str,
        _uplink_name: &str,
        _platform: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Check whether the capsule is allowed to perform an identity operation.
    ///
    /// Default implementation denies all identity operations (fail-closed).
    async fn check_identity(
        &self,
        capsule_id: &str,
        operation: IdentityOperation,
    ) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: identity operation '{:?}' not permitted (default)",
            operation
        ))
    }
}
