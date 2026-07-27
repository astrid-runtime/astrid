//! Verified partial state views and structural transition witnesses.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use super::world::closure_in;
use super::{ModelError, ObjectId, ObjectIdentity, ObjectRecord, ReferenceKind, ReferenceLabel};

/// Canonical sequence of reference labels from a source root to a selected
/// owned subtree.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ReferencePath(Vec<ReferenceLabel>);

impl ReferencePath {
    /// Construct a reference path. An empty path selects the source root.
    #[must_use]
    pub const fn new(labels: Vec<ReferenceLabel>) -> Self {
        Self(labels)
    }

    /// Borrow the ordered relation labels.
    #[must_use]
    pub fn labels(&self) -> &[ReferenceLabel] {
        &self.0
    }
}

/// Canonical set of non-redundant paths selected from one committed root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateSelector {
    paths: Vec<ReferencePath>,
}

impl StateSelector {
    /// Construct a selector from strictly ordered, non-overlapping paths.
    ///
    /// A path cannot be a prefix of another selected path because selecting the
    /// ancestor already selects its complete owned closure.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NonCanonicalSelector`] for an empty, unordered,
    /// duplicate, or prefix-redundant path set.
    pub fn new(paths: Vec<ReferencePath>) -> Result<Self, ModelError> {
        if paths.is_empty()
            || paths
                .windows(2)
                .any(|pair| pair[0] >= pair[1] || path_is_prefix(&pair[0], &pair[1]))
        {
            return Err(ModelError::NonCanonicalSelector);
        }
        Ok(Self { paths })
    }

    /// Borrow the selected paths.
    #[must_use]
    pub fn paths(&self) -> &[ReferencePath] {
        &self.paths
    }
}

/// Partial authenticated object set for a verified state view.
///
/// Records include every ancestor needed to follow each selected path and the
/// complete owning closure below every selected root. Unselected siblings stay
/// blinded as object identifiers inside their disclosed parent records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateViewProof {
    source: ObjectId,
    selector: StateSelector,
    records: Vec<(ObjectId, ObjectRecord)>,
}

impl StateViewProof {
    /// Construct a canonically ordered view proof.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NonCanonicalProofRecords`] if record identifiers
    /// are not strictly increasing.
    pub fn new(
        source: ObjectId,
        selector: StateSelector,
        records: Vec<(ObjectId, ObjectRecord)>,
    ) -> Result<Self, ModelError> {
        validate_record_order(&records)?;
        Ok(Self {
            source,
            selector,
            records,
        })
    }

    /// Verify object identities, selector paths, selected closures, and proof
    /// minimality.
    ///
    /// # Errors
    ///
    /// Rejects missing, substituted, non-owning, or extraneous proof objects.
    pub fn verify<I: ObjectIdentity>(&self, identity: &I) -> Result<VerifiedStateView, ModelError> {
        let records = verified_record_map(identity, &self.records)?;
        let mut allowed = BTreeSet::new();
        let mut selected_roots = Vec::with_capacity(self.selector.paths.len());

        for path in &self.selector.paths {
            let mut current = self.source;
            allowed.insert(current);
            for label in path.labels() {
                let record = records
                    .get(&current)
                    .ok_or(ModelError::MissingProofObject(current))?;
                let reference =
                    record
                        .reference(label)
                        .ok_or_else(|| ModelError::MissingReference {
                            label: label.clone(),
                        })?;
                if reference.kind != ReferenceKind::Owns {
                    return Err(ModelError::ReferenceNotOwned {
                        label: label.clone(),
                    });
                }
                current = reference.target;
                allowed.insert(current);
            }
            let closure = closure_in(&records, current)?;
            allowed.extend(closure);
            selected_roots.push(current);
        }

        if let Some(extraneous) = records.keys().find(|id| !allowed.contains(id)) {
            return Err(ModelError::ExtraneousProofObject(*extraneous));
        }

        Ok(VerifiedStateView {
            source: self.source,
            selected_roots,
            object_count: records.len(),
        })
    }
}

/// Result of successfully verifying a state view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedStateView {
    source: ObjectId,
    selected_roots: Vec<ObjectId>,
    object_count: usize,
}

impl VerifiedStateView {
    /// Return the committed source root.
    #[must_use]
    pub const fn source(&self) -> ObjectId {
        self.source
    }

    /// Borrow the roots selected in canonical path order.
    #[must_use]
    pub fn selected_roots(&self) -> &[ObjectId] {
        &self.selected_roots
    }

    /// Return the number of disclosed proof records.
    #[must_use]
    pub const fn object_count(&self) -> usize {
        self.object_count
    }
}

/// Smallest generic structural patch: replace one owned subtree at a labelled
/// path.
///
/// Subsystem-specific file and KV patch grammars can refine this operation.
/// This primitive proves only the authenticated root rewrite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnedSubtreePatch {
    path: ReferencePath,
    expected: ObjectId,
    replacement: ObjectId,
}

impl OwnedSubtreePatch {
    /// Construct an owned-subtree replacement.
    #[must_use]
    pub const fn new(path: ReferencePath, expected: ObjectId, replacement: ObjectId) -> Self {
        Self {
            path,
            expected,
            replacement,
        }
    }
}

/// Partial authenticated proof that one labelled subtree replacement advances
/// `before` to `after`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionWitness {
    before: ObjectId,
    after: ObjectId,
    patch: OwnedSubtreePatch,
    records: Vec<(ObjectId, ObjectRecord)>,
}

impl TransitionWitness {
    /// Construct a canonically ordered transition witness.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError::NonCanonicalProofRecords`] if record identifiers
    /// are not strictly increasing.
    pub fn new(
        before: ObjectId,
        after: ObjectId,
        patch: OwnedSubtreePatch,
        records: Vec<(ObjectId, ObjectRecord)>,
    ) -> Result<Self, ModelError> {
        validate_record_order(&records)?;
        Ok(Self {
            before,
            after,
            patch,
            records,
        })
    }

    /// Verify the partial before-state and recompute the after root.
    ///
    /// The replacement closure's durability is a separate commit invariant;
    /// this witness proves only the structural root transition.
    ///
    /// # Errors
    ///
    /// Rejects substituted roots, targets, paths, records, or non-owning edges.
    pub fn verify<I: ObjectIdentity>(&self, identity: &I) -> Result<ObjectId, ModelError> {
        let records = verified_record_map(identity, &self.records)?;
        if self.patch.path.labels().is_empty() {
            if let Some(extraneous) = records.keys().next() {
                return Err(ModelError::ExtraneousProofObject(*extraneous));
            }
            if self.before != self.patch.expected {
                return Err(ModelError::PatchTargetMismatch {
                    expected: self.patch.expected,
                    actual: self.before,
                });
            }
            if self.after != self.patch.replacement {
                return Err(ModelError::TransitionRootMismatch {
                    declared: self.after,
                    computed: self.patch.replacement,
                });
            }
            return Ok(self.after);
        }

        let mut current = self.before;
        let mut ancestors = Vec::<(ObjectId, ObjectRecord, ReferenceLabel, ObjectId)>::new();
        let mut used = BTreeSet::new();
        for label in self.patch.path.labels() {
            let record = records
                .get(&current)
                .ok_or(ModelError::MissingProofObject(current))?;
            let reference =
                record
                    .reference(label)
                    .ok_or_else(|| ModelError::MissingReference {
                        label: label.clone(),
                    })?;
            if reference.kind != ReferenceKind::Owns {
                return Err(ModelError::ReferenceNotOwned {
                    label: label.clone(),
                });
            }
            used.insert(current);
            ancestors.push((current, record.clone(), label.clone(), reference.target));
            current = reference.target;
        }

        if current != self.patch.expected {
            return Err(ModelError::PatchTargetMismatch {
                expected: self.patch.expected,
                actual: current,
            });
        }
        if let Some(extraneous) = records.keys().find(|id| !used.contains(id)) {
            return Err(ModelError::ExtraneousProofObject(*extraneous));
        }

        let mut replacement = self.patch.replacement;
        for (_, record, label, old_child) in ancestors.into_iter().rev() {
            let updated = record.replace_owned_target(&label, old_child, replacement)?;
            replacement = identity.identify(&updated);
        }
        if replacement != self.after {
            return Err(ModelError::TransitionRootMismatch {
                declared: self.after,
                computed: replacement,
            });
        }
        Ok(replacement)
    }
}

fn path_is_prefix(prefix: &ReferencePath, path: &ReferencePath) -> bool {
    prefix.labels().len() <= path.labels().len()
        && prefix
            .labels()
            .iter()
            .zip(path.labels())
            .all(|(left, right)| left == right)
}

fn validate_record_order(records: &[(ObjectId, ObjectRecord)]) -> Result<(), ModelError> {
    if records.windows(2).any(|pair| pair[0].0 >= pair[1].0) {
        return Err(ModelError::NonCanonicalProofRecords);
    }
    Ok(())
}

fn verified_record_map<I: ObjectIdentity>(
    identity: &I,
    records: &[(ObjectId, ObjectRecord)],
) -> Result<BTreeMap<ObjectId, ObjectRecord>, ModelError> {
    let mut result = BTreeMap::new();
    for (declared, record) in records {
        let computed = identity.identify(record);
        if computed != *declared {
            return Err(ModelError::ObjectIdentityMismatch {
                declared: *declared,
                computed,
            });
        }
        result.insert(*declared, record.clone());
    }
    Ok(result)
}
