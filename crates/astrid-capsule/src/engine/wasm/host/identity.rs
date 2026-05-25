//! `astrid:identity@1.0.0` host implementation.

use crate::engine::wasm::bindings::astrid::identity::host::{
    self as identity, ErrorCode, IdentityCreateUserRequest, IdentityCreateUserResponse,
    IdentityLinkRequest, IdentityResolveRequest, IdentityResolveResponse, IdentityUnlinkRequest,
    PlatformLink,
};
use crate::engine::wasm::host::util;
use crate::engine::wasm::host_state::HostState;
use crate::security::IdentityOperation;

/// Map a storage / security error to a typed identity [`ErrorCode`].
fn map_store_err(err: impl std::fmt::Display) -> ErrorCode {
    let s = err.to_string();
    if s.contains("not found") {
        ErrorCode::UserNotFound
    } else if s.contains("already linked") || s.contains("already exists") {
        ErrorCode::AlreadyLinked
    } else if s.contains("denied") || s.contains("capability") {
        ErrorCode::CapabilityDenied
    } else {
        ErrorCode::StoreUnavailable
    }
}

impl identity::Host for HostState {
    fn identity_resolve(
        &mut self,
        request: IdentityResolveRequest,
    ) -> Result<IdentityResolveResponse, ErrorCode> {
        let identity_store = self
            .identity_store
            .clone()
            .ok_or(ErrorCode::StoreUnavailable)?;

        let security = self.security.clone().ok_or(ErrorCode::CapabilityDenied)?;

        let capsule_id = self.capsule_id.to_string();
        let runtime_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        let result = util::bounded_block_on(&runtime_handle, &host_semaphore, async {
            security
                .check_identity(&capsule_id, IdentityOperation::Resolve)
                .await
                .map_err(|e| ErrorCode::Unknown(format!("security: {e}")))?;

            identity_store
                .resolve(&request.platform, &request.platform_user_id)
                .await
                .map_err(map_store_err)
        })?;

        match result {
            Some(user) => Ok(IdentityResolveResponse {
                user_id: user.id.to_string(),
                display_name: user.display_name,
            }),
            None => Err(ErrorCode::LinkNotFound),
        }
    }

    fn identity_link(&mut self, request: IdentityLinkRequest) -> Result<(), ErrorCode> {
        let user_id =
            uuid::Uuid::parse_str(&request.astrid_user_id).map_err(|_| ErrorCode::InvalidInput)?;

        let identity_store = self
            .identity_store
            .clone()
            .ok_or(ErrorCode::StoreUnavailable)?;
        let security = self.security.clone().ok_or(ErrorCode::CapabilityDenied)?;
        let capsule_id = self.capsule_id.to_string();
        let runtime_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        util::bounded_block_on(&runtime_handle, &host_semaphore, async {
            security
                .check_identity(&capsule_id, IdentityOperation::Link)
                .await
                .map_err(|e| ErrorCode::Unknown(format!("security: {e}")))?;

            identity_store
                .link(
                    &request.platform,
                    &request.platform_user_id,
                    user_id,
                    &request.method,
                )
                .await
                .map(|_| ())
                .map_err(map_store_err)
        })
    }

    fn identity_unlink(&mut self, request: IdentityUnlinkRequest) -> Result<(), ErrorCode> {
        let identity_store = self
            .identity_store
            .clone()
            .ok_or(ErrorCode::StoreUnavailable)?;
        let security = self.security.clone().ok_or(ErrorCode::CapabilityDenied)?;
        let capsule_id = self.capsule_id.to_string();
        let runtime_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        let removed = util::bounded_block_on(&runtime_handle, &host_semaphore, async {
            security
                .check_identity(&capsule_id, IdentityOperation::Unlink)
                .await
                .map_err(|e| ErrorCode::Unknown(format!("security: {e}")))?;

            identity_store
                .unlink(&request.platform, &request.platform_user_id)
                .await
                .map_err(map_store_err)
        })?;

        if !removed {
            return Err(ErrorCode::LinkNotFound);
        }
        Ok(())
    }

    fn identity_create_user(
        &mut self,
        request: IdentityCreateUserRequest,
    ) -> Result<IdentityCreateUserResponse, ErrorCode> {
        let identity_store = self
            .identity_store
            .clone()
            .ok_or(ErrorCode::StoreUnavailable)?;
        let security = self.security.clone().ok_or(ErrorCode::CapabilityDenied)?;
        let capsule_id = self.capsule_id.to_string();
        let runtime_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        let created = util::bounded_block_on(&runtime_handle, &host_semaphore, async {
            security
                .check_identity(&capsule_id, IdentityOperation::CreateUser)
                .await
                .map_err(|e| ErrorCode::Unknown(format!("security: {e}")))?;

            identity_store
                .create_user(request.display_name.as_deref())
                .await
                .map_err(map_store_err)
        })?;

        Ok(IdentityCreateUserResponse {
            user_id: created.id.to_string(),
        })
    }

    fn identity_list_links(
        &mut self,
        astrid_user_id: String,
    ) -> Result<Vec<PlatformLink>, ErrorCode> {
        let user_id =
            uuid::Uuid::parse_str(&astrid_user_id).map_err(|_| ErrorCode::InvalidInput)?;

        let identity_store = self
            .identity_store
            .clone()
            .ok_or(ErrorCode::StoreUnavailable)?;
        let security = self.security.clone().ok_or(ErrorCode::CapabilityDenied)?;
        let capsule_id = self.capsule_id.to_string();
        let runtime_handle = self.runtime_handle.clone();
        let host_semaphore = self.host_semaphore.clone();

        let links = util::bounded_block_on(&runtime_handle, &host_semaphore, async {
            security
                .check_identity(&capsule_id, IdentityOperation::ListLinks)
                .await
                .map_err(|e| ErrorCode::Unknown(format!("security: {e}")))?;

            identity_store
                .list_links(user_id)
                .await
                .map_err(map_store_err)
        })?;

        Ok(links
            .into_iter()
            .map(|l| PlatformLink {
                platform: l.platform,
                platform_user_id: l.platform_user_id,
                linked_at: l.linked_at.to_rfc3339(),
                method: l.method,
            })
            .collect())
    }
}
