//! Test-only [`CapsuleSecurityGate`] implementations.
//!
//! [`AllowAllGate`] permits every operation; [`DenyAllGate`] rejects every
//! operation. Used by unit and integration tests to decouple gate policy
//! from the code under test.

use async_trait::async_trait;

use super::{CapsuleSecurityGate, IdentityOperation};

/// Security gate that permits all operations (for testing).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AllowAllGate;

#[async_trait]
impl CapsuleSecurityGate for AllowAllGate {
    async fn check_http_request(
        &self,
        _capsule_id: &str,
        _method: &str,
        _url: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_file_read(
        &self,
        _capsule_id: &str,
        _path: &str,
        _principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_file_write(
        &self,
        _capsule_id: &str,
        _path: &str,
        _principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_host_process(&self, _capsule_id: &str, _command: &str) -> Result<(), String> {
        Ok(())
    }

    async fn check_net_bind(&self, _capsule_id: &str) -> Result<(), String> {
        Ok(())
    }

    async fn check_net_connect(
        &self,
        _capsule_id: &str,
        _host: &str,
        _port: u16,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_uplink_register(
        &self,
        _capsule_id: &str,
        _uplink_name: &str,
        _platform: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn check_identity(
        &self,
        _capsule_id: &str,
        _operation: IdentityOperation,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// Security gate that denies all operations (for testing).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DenyAllGate;

#[async_trait]
impl CapsuleSecurityGate for DenyAllGate {
    async fn check_http_request(
        &self,
        capsule_id: &str,
        method: &str,
        url: &str,
    ) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: {method} {url} (DenyAllGate)"
        ))
    }

    async fn check_file_read(
        &self,
        capsule_id: &str,
        path: &str,
        _principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: read {path} (DenyAllGate)"
        ))
    }

    async fn check_file_write(
        &self,
        capsule_id: &str,
        path: &str,
        _principal_home: Option<&std::path::Path>,
    ) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: write {path} (DenyAllGate)"
        ))
    }

    async fn check_host_process(&self, capsule_id: &str, command: &str) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: spawn host process {command} (DenyAllGate)"
        ))
    }

    async fn check_net_bind(&self, capsule_id: &str) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: net_bind (DenyAllGate)"
        ))
    }

    async fn check_net_connect(
        &self,
        capsule_id: &str,
        host: &str,
        port: u16,
    ) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: net_connect {host}:{port} (DenyAllGate)"
        ))
    }

    async fn check_uplink_register(
        &self,
        capsule_id: &str,
        uplink_name: &str,
        platform: &str,
    ) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: register uplink {uplink_name} ({platform}) (DenyAllGate)"
        ))
    }

    async fn check_identity(
        &self,
        capsule_id: &str,
        operation: IdentityOperation,
    ) -> Result<(), String> {
        Err(format!(
            "capsule '{capsule_id}' denied: identity {:?} (DenyAllGate)",
            operation
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn allow_all_gate_permits_everything() {
        let gate = AllowAllGate;
        assert!(
            gate.check_http_request("p", "GET", "http://x")
                .await
                .is_ok()
        );
        assert!(gate.check_file_read("p", "/tmp/f", None).await.is_ok());
        assert!(gate.check_file_write("p", "/tmp/f", None).await.is_ok());
        assert!(gate.check_net_bind("p").await.is_ok());
        assert!(
            gate.check_uplink_register("p", "my-conn", "discord")
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn deny_all_gate_rejects_everything() {
        let gate = DenyAllGate;
        assert!(
            gate.check_http_request("p", "GET", "http://x")
                .await
                .is_err()
        );
        assert!(gate.check_file_read("p", "/tmp/f", None).await.is_err());
        assert!(gate.check_file_write("p", "/tmp/f", None).await.is_err());
        assert!(gate.check_net_bind("p").await.is_err());
        assert!(
            gate.check_uplink_register("p", "my-conn", "discord")
                .await
                .is_err()
        );
    }
}
