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

    #[cfg(test)]
    pub(crate) fn seal_transaction<P>(
        self,
        principal: P,
        expected: Option<RootState>,
        commit: ObjectId,
        records: Vec<(ObjectId, ObjectRecord)>,
    ) -> RootTransaction<P> {
        RootTransaction {
            declaration: super::root_declaration::Declaration::sealed(
                super::root_declaration::Update {
                    principal,
                    expected,
                    commit,
                    records,
                },
                Arc::clone(self.authority),
            ),
            kv_checkpoint_publication: None,
        }
    }
}

impl<P> RootTransaction<P> {
    pub(crate) fn from_staged(
        principal: P,
        expected: Option<RootState>,
        commit: ObjectId,
        staged: std::collections::BTreeMap<ObjectId, ObjectRecord>,
        session: Option<KvIdentitySession<'_>>,
    ) -> Self {
        Self {
            declaration: super::root_declaration::Declaration::from_staged(
                principal,
                expected,
                commit,
                staged,
                session.map(|s| Arc::clone(s.authority)),
            ),
            kv_checkpoint_publication: None,
        }
    }
}

impl<P> super::root_declaration::Declaration<P, Arc<()>> {
    pub(super) fn admit_records<C>(
        self,
        authority: &Arc<()>,
        identify: impl Fn(&ObjectRecord) -> ObjectId,
        checkpoint: &mut Option<C>,
    ) -> Result<(super::root_declaration::Update<P>, Option<C>), ModelError> {
        self.admit_with_checkpoint(authority, Arc::ptr_eq, identify, checkpoint)
            .map_err(|(declared, computed)| ModelError::ObjectIdentityMismatch {
                declared,
                computed,
            })
    }
}
