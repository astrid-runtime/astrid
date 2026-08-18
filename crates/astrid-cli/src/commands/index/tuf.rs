//! Adapter from configured sources to the real astrid-capsule-index-tuf
//! verifier.
//!
//! No signature or rollback logic is implemented here. The adapter builds a
//! `TrustConfig` with the persisted protocol identity and delegates all TUF
//! verification to the workspace TUF crate.

use std::path::PathBuf;

use url::Url;

use super::transport::ReqwestTufTransport;
use super::{
    IndexError, IndexSource, IndexStore, MetadataSnapshot, UpdateArgs, UpdateOutcome,
    metadata_digest,
};

/// Paths used by the TUF crate for high-water and datastore state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TufStatePaths {
    /// Atomic trusted-state JSON path.
    pub(crate) state_path: PathBuf,
    /// Tough metadata datastore directory.
    pub(crate) datastore_path: PathBuf,
}

/// Production adapter that delegates root rotation, expiry, rollback, and
/// role signatures to astrid-capsule-index-tuf.
#[derive(Debug, Clone)]
pub(crate) struct TufIndexAdapter {
    transport: ReqwestTufTransport,
}

impl TufIndexAdapter {
    /// Construct an HTTPS/no-redirect adapter with a response bound.
    pub(crate) fn new(max_response_bytes: usize) -> Result<Self, IndexError> {
        Ok(Self {
            transport: ReqwestTufTransport::new(max_response_bytes)?,
        })
    }

    /// Construct an adapter around an injected transport (for loopback or
    /// hermetic tests).
    pub(crate) fn with_transport(transport: ReqwestTufTransport) -> Self {
        Self { transport }
    }

    /// Verify one source through the real TUF crate.
    pub(crate) async fn verify(
        &self,
        source: &IndexSource,
        metadata_base_url: Url,
        targets_base_url: Url,
        state_paths: TufStatePaths,
    ) -> Result<astrid_capsule_index_tuf::VerifiedIndex, IndexError> {
        self.verify_with_transport(
            source,
            metadata_base_url,
            targets_base_url,
            state_paths,
            self.transport.clone(),
        )
        .await
    }

    /// Verify through an injected tough transport. This keeps unit tests and
    /// offline callers hermetic while production uses the bounded reqwest
    /// transport above.
    pub(crate) async fn verify_with_transport<T>(
        &self,
        source: &IndexSource,
        metadata_base_url: Url,
        targets_base_url: Url,
        state_paths: TufStatePaths,
        transport: T,
    ) -> Result<astrid_capsule_index_tuf::VerifiedIndex, IndexError>
    where
        T: tough::Transport + Clone + Send + Sync + 'static,
    {
        let identity = source.protocol_identity()?;
        let root_bytes = source.root.bytes()?;
        let config = astrid_capsule_index_tuf::TrustConfig::new(
            identity,
            root_bytes,
            metadata_base_url,
            targets_base_url,
            state_paths.state_path,
            state_paths.datastore_path,
        )
        .map_err(|source| IndexError::Network {
            operation: "construct TUF trust config".to_owned(),
            message: source.to_string(),
        })?;
        astrid_capsule_index_tuf::load(config, transport)
            .await
            .map_err(|source| IndexError::Network {
                operation: "verify TUF Index metadata".to_owned(),
                message: source.to_string(),
            })
    }

    /// Verify and persist the resulting TUF high-water state through the
    /// source store. The state JSON is retained as an auditable metadata
    /// snapshot; the TUF crate remains authoritative for trust decisions.
    pub(crate) async fn update_store(
        &self,
        store: &IndexStore,
        args: UpdateArgs,
        metadata_base_url: Url,
        targets_base_url: Url,
        state_paths: TufStatePaths,
    ) -> Result<UpdateOutcome, IndexError> {
        self.update_store_with_transport(
            store,
            args,
            metadata_base_url,
            targets_base_url,
            state_paths,
            self.transport.clone(),
        )
        .await
    }

    /// Verify and persist using an injected tough transport.
    pub(crate) async fn update_store_with_transport<T>(
        &self,
        store: &IndexStore,
        args: UpdateArgs,
        metadata_base_url: Url,
        targets_base_url: Url,
        state_paths: TufStatePaths,
        transport: T,
    ) -> Result<UpdateOutcome, IndexError>
    where
        T: tough::Transport + Clone + Send + Sync + 'static,
    {
        let source = store
            .load()?
            .into_iter()
            .find(|source| source.id == args.id)
            .ok_or_else(|| IndexError::NotFound(args.id.clone()))?;
        let verified = self
            .verify_with_transport(
                &source,
                metadata_base_url,
                targets_base_url,
                state_paths,
                transport,
            )
            .await?;
        let bytes = serde_json::to_vec(verified.state()).map_err(|source| IndexError::Network {
            operation: "serialize verified TUF state".to_owned(),
            message: source.to_string(),
        })?;
        let version = verified.state().snapshot_version;
        let snapshot = MetadataSnapshot::new(version, &bytes, &metadata_digest(&bytes))?;
        store.record_verified_metadata(args.id, &source.root.fingerprint, snapshot)
    }
}
