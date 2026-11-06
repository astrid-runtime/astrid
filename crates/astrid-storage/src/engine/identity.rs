//! Process-local hasher binding for KV tree construction.
//!
//! A [`KvIdentitySession`] pairs one engine's actual [`ObjectIdentity`]
//! implementation with that engine's admission authority. Tree construction
//! captures the pair once and uses it for every locally created record. Public
//! [`RootTransaction::new`] stays untrusted. Matching authority may skip only
//! the identity loop; collision, closure, quota, root CAS, and foreign engines
//! still verify.

use std::sync::Arc;

use crate::storage_model::{ObjectId, ObjectIdentity, ObjectRecord, RootState};

use super::RootTransaction;

/// Hasher bound to one concrete engine's process-local admission authority.
///
/// Fields are private. The only constructors live in this crate's production
/// engines. External [`super::KvProjectionEngine`] implementations may forward
/// a session they received, but they cannot mint one that pairs a different
/// hasher with a forwarded authority.
///
/// When the engine supplies this session, tree construction uses its bound
/// hasher instead of the overridable generic identification method. The same
/// captured session seals the finished transaction; a later getter result
/// cannot change the binding. Cloning a transaction removes that seal.
#[derive(Clone, Copy)]
pub struct KvIdentitySession<'a> {
    identity: &'a (dyn ObjectIdentity + Send + Sync),
    authority: &'a Arc<()>,
}

impl<'a> KvIdentitySession<'a> {
    pub(crate) fn bind(
        identity: &'a (dyn ObjectIdentity + Send + Sync),
        authority: &'a Arc<()>,
    ) -> Self {
        Self {
            identity,
            authority,
        }
    }

    pub(crate) fn identify(&self, record: &ObjectRecord) -> ObjectId {
        self.identity.identify(record)
    }

    pub(crate) fn seal_transaction<P>(
        self,
        principal: P,
        expected: Option<RootState>,
        commit: ObjectId,
        records: Vec<(ObjectId, ObjectRecord)>,
    ) -> RootTransaction<P> {
        RootTransaction {
            principal,
            expected,
            commit,
            records,
            identity_proof: IdentityProof::Engine(Arc::clone(self.authority)),
        }
    }
}

/// Process-local proof that a transaction's declared identities were computed
/// by the same engine instance that now consumes it.
#[derive(Debug)]
pub(crate) enum IdentityProof {
    Untrusted,
    Engine(Arc<()>),
}

impl IdentityProof {
    pub(crate) fn matches(&self, authority: &Arc<()>) -> bool {
        match self {
            Self::Engine(bound) => Arc::ptr_eq(bound, authority),
            Self::Untrusted => false,
        }
    }
}
