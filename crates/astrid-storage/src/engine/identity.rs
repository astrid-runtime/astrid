//! Process-local hasher binding for KV tree construction.
//!
//! A [`KvIdentitySession`] pairs one engine's actual [`ObjectIdentity`]
//! implementation with that engine's admission authority. Tree construction
//! captures the pair once and uses it for every locally created record. Public
//! [`RootTransaction::new`] stays untrusted. Matching authority may skip only
//! the identity loop; collision, closure, quota, root CAS, and foreign engines
//! still verify.

use std::sync::Arc;

use crate::storage_model::{ModelError, ObjectId, ObjectIdentity, ObjectRecord, RootState};

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
            kv_checkpoint_publication: None,
        }
    }
}

/// Process-local proof that a transaction's declared identities were computed
/// by the same engine instance that now consumes it.
pub(crate) type IdentityProof = super::transaction_records::IdentityProof<Arc<()>>;

impl IdentityProof {
    pub(crate) fn admit_records(
        &self,
        authority: &Arc<()>,
        records: &[(ObjectId, ObjectRecord)],
        identify: impl Fn(&ObjectRecord) -> ObjectId,
    ) -> Result<super::transaction_records::Admission, ModelError> {
        self.admit(authority, Arc::ptr_eq, records, identify)
            .map_err(|(declared, computed)| ModelError::ObjectIdentityMismatch {
                declared,
                computed,
            })
    }
}
