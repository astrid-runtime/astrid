//! Constructors for the principal content projection.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::Mutex;

use crate::content::catalog::CatalogValidation;
use crate::content::store::PrincipalContentStore;
use crate::kv::{KvQuotaResolver, KvValidationCache};

use super::ContentReadLeaseRegistry;

impl<P: Ord, E> PrincipalContentStore<P, E> {
    /// Bind durable owner-internal workspace branches to this content store.
    #[must_use]
    pub fn workspace_branches(self: &Arc<Self>) -> super::WorkspaceBranchStore<P, E> {
        super::WorkspaceBranchStore::new(Arc::clone(self))
    }

    /// Construct with live principal quota resolution.
    #[must_use]
    pub fn from_engine_with_quota(engine: Arc<E>, quota: Arc<dyn KvQuotaResolver<P>>) -> Self {
        Self {
            engine,
            quota: Some(quota),
            validated_catalogs: Arc::new(Mutex::new(BTreeMap::new())),
            decoded_headers: Arc::new(Mutex::new(BTreeMap::new())),
            validated_kv: Arc::new(KvValidationCache::default()),
            read_leases: Arc::new(ContentReadLeaseRegistry::default()),
            #[cfg(test)]
            list_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            list_prefix_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            prefix_exists_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            decode_header_invocations: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub(crate) fn from_engine_with_quota_and_validation(
        engine: Arc<E>,
        quota: Arc<dyn KvQuotaResolver<P>>,
        validated_catalogs: Arc<Mutex<BTreeMap<P, CatalogValidation>>>,
        validated_kv: Arc<KvValidationCache<P>>,
    ) -> Self {
        Self {
            engine,
            quota: Some(quota),
            validated_catalogs,
            decoded_headers: Arc::new(Mutex::new(BTreeMap::new())),
            validated_kv,
            read_leases: Arc::new(ContentReadLeaseRegistry::default()),
            #[cfg(test)]
            list_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            list_prefix_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            prefix_exists_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            decode_header_invocations: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub(crate) fn from_engine_with_validation(
        engine: Arc<E>,
        validated_catalogs: Arc<Mutex<BTreeMap<P, CatalogValidation>>>,
    ) -> Self {
        Self {
            engine,
            quota: None,
            validated_catalogs,
            decoded_headers: Arc::new(Mutex::new(BTreeMap::new())),
            validated_kv: Arc::new(KvValidationCache::default()),
            read_leases: Arc::new(ContentReadLeaseRegistry::default()),
            #[cfg(test)]
            list_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            list_prefix_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            prefix_exists_invocations: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            decode_header_invocations: std::sync::atomic::AtomicU64::new(0),
        }
    }
}
