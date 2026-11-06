//! Guarded owned-transaction integration for the in-memory engine.

use alloc::sync::Arc;
use alloc::vec::Vec;

use parking_lot::{RwLockUpgradableReadGuard, RwLockWriteGuard};

use super::World;
use crate::storage_model::{ModelError, ObjectId, ObjectRecord, RootGeneration, RootState};

impl<P: Ord> World<P> {
    /// Keep root readers live while validating an owned engine transaction.
    ///
    /// The upgradable guard excludes competing writers throughout validation;
    /// atomic upgrade preserves that proof until objects and the root publish.
    /// Return the actual writer so engine-local validation can publish before
    /// the new root becomes visible. No prepared admission escapes the guard.
    pub(crate) fn commit_closure_owned(
        guard: RwLockUpgradableReadGuard<'_, Self>,
        principal: P,
        expected: Option<RootState>,
        commit: ObjectId,
        records: Vec<(ObjectId, ObjectRecord)>,
    ) -> Result<(RwLockWriteGuard<'_, Self>, RootState, u64), ModelError> {
        let admission = (|| {
            let actual = guard.root(&principal);
            if actual != expected {
                return Err(ModelError::RootConflict { expected, actual });
            }
            let generation = match actual {
                Some(root) => root
                    .generation
                    .checked_next()
                    .ok_or(ModelError::ArithmeticOverflow)?,
                None => RootGeneration::INITIAL,
            };
            guard.validate_transaction_root(&records, commit)?;
            let staged = guard.classify_import(&records, commit)?;
            let inserted =
                u64::try_from(staged.len()).map_err(|_| ModelError::ArithmeticOverflow)?;
            Ok((RootState { generation, commit }, staged, inserted))
        })();
        let (root, mut staged, inserted) = match admission {
            Ok(admission) => admission,
            Err(error) => {
                // Do not hold the guard while rejected principal/record
                // ownership is released by this operation's return.
                drop(guard);
                return Err(error);
            },
        };
        let mut world = RwLockUpgradableReadGuard::upgrade(guard);
        // Every fallible check preceded upgrade. The same guard excluded
        // writers and GC, so resident closure records remain unchanged.
        world.objects.extend(
            records
                .into_iter()
                .filter(|(id, _)| staged.remove(id).is_some())
                .map(|(id, record)| (id, Arc::new(record))),
        );
        world.roots.insert(principal, root);
        Ok((world, root, inserted))
    }
}
