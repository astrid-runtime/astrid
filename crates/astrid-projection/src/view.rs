//! Lookup-only projection view. There is no catalog dump.

use astrid_resource_types::ResourceTypeId;

use crate::error::ProjectionError;
use crate::object::SemanticObjectId;
use crate::presentation::PresentationLabel;
use crate::revision::ProjectionRevision;
use crate::snapshot::{ProjectionSnapshot, ProjectionUpdate};

/// Fixed-capacity view of projection snapshots.
///
/// Lookup requires the exact [`SemanticObjectId`]. Listing by type, label, or
/// "all" is refused. Existing objects are never overwritten in place: the
/// initial insert is unique, and later states go through [`Self::apply`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectionView<const N: usize> {
    slots: [Option<ProjectionSnapshot>; N],
}

impl<const N: usize> ProjectionView<N> {
    /// Empty view.
    #[must_use]
    pub const fn new() -> Self {
        Self { slots: [None; N] }
    }

    /// Insert the first snapshot for an object.
    ///
    /// # Errors
    ///
    /// Rejects non-initial revisions, duplicates, and a full view. Collision
    /// does not overwrite.
    pub fn insert_initial(&mut self, snapshot: ProjectionSnapshot) -> Result<(), ProjectionError> {
        if snapshot.revision() != ProjectionRevision::INITIAL {
            return Err(ProjectionError::InvalidRevision);
        }
        if self.get(snapshot.object()).is_some() {
            return Err(ProjectionError::AlreadyProjected);
        }
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(ProjectionError::ViewFull)?;
        *slot = Some(snapshot);
        Ok(())
    }

    /// Apply a successor update to a stored object.
    ///
    /// # Errors
    ///
    /// Unknown objects, type confusion, and stale revisions fail closed.
    pub fn apply(
        &mut self,
        update: &ProjectionUpdate,
    ) -> Result<&ProjectionSnapshot, ProjectionError> {
        let slot = self
            .slots
            .iter_mut()
            .find_map(|slot| match slot {
                Some(snapshot) if snapshot.object() == update.object() => Some(snapshot),
                _ => None,
            })
            .ok_or(ProjectionError::UnknownObject)?;
        *slot = slot.apply(update)?;
        Ok(slot)
    }

    /// Exact-id lookup.
    #[must_use]
    pub fn get(&self, object: SemanticObjectId) -> Option<&ProjectionSnapshot> {
        self.slots.iter().find_map(|slot| match slot {
            Some(snapshot) if snapshot.object() == object => Some(snapshot),
            _ => None,
        })
    }

    /// Exact-id lookup that also checks the revision.
    ///
    /// # Errors
    ///
    /// Unknown objects and stale revisions fail closed.
    pub fn get_revision(
        &self,
        object: SemanticObjectId,
        revision: ProjectionRevision,
    ) -> Result<&ProjectionSnapshot, ProjectionError> {
        let found = self.get(object).ok_or(ProjectionError::UnknownObject)?;
        if found.revision() != revision {
            return Err(ProjectionError::StaleRevision {
                found: found.revision().get(),
                requested: revision.get(),
            });
        }
        Ok(found)
    }

    /// Type-based listing is refused. Knowing a schema is not enumeration.
    ///
    /// # Errors
    ///
    /// Always [`ProjectionError::EnumerationRefused`].
    pub const fn by_type(
        &self,
        type_id: ResourceTypeId,
    ) -> Result<core::convert::Infallible, ProjectionError> {
        let _ = (self, type_id);
        Err(ProjectionError::EnumerationRefused)
    }

    /// Label-based listing is refused. Knowing a name is not lookup.
    ///
    /// # Errors
    ///
    /// Always [`ProjectionError::EnumerationRefused`].
    pub const fn by_label(
        &self,
        label: &PresentationLabel,
    ) -> Result<core::convert::Infallible, ProjectionError> {
        let _ = (self, label);
        Err(ProjectionError::EnumerationRefused)
    }

    /// Global catalog dump is refused.
    ///
    /// # Errors
    ///
    /// Always [`ProjectionError::EnumerationRefused`].
    pub const fn try_all(&self) -> Result<core::convert::Infallible, ProjectionError> {
        let _ = self;
        Err(ProjectionError::EnumerationRefused)
    }
}

impl<const N: usize> Default for ProjectionView<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presentation::{PresentationLabel, PresentationMetadata};
    use astrid_resource_types::{ResourceId, ResourceTypeId};

    fn snap(byte: u8, label: &str) -> ProjectionSnapshot {
        ProjectionSnapshot::new(
            SemanticObjectId::for_resource(ResourceId::from_bytes([byte; 32])),
            ResourceTypeId::from_bytes([byte; 32]),
            ProjectionRevision::INITIAL,
            PresentationLabel::from_utf8(label.as_bytes()).unwrap(),
            PresentationMetadata::EMPTY,
        )
    }

    #[test]
    fn insert_rejects_overwrite_and_non_initial() {
        let mut view = ProjectionView::<2>::new();
        let first = snap(1, "a");
        view.insert_initial(first).unwrap();
        assert_eq!(
            view.insert_initial(first),
            Err(ProjectionError::AlreadyProjected)
        );
        let mut second = snap(2, "b");
        // Direct constructor allows a non-initial snapshot; the view must not.
        second = ProjectionSnapshot::new(
            second.object(),
            second.type_id(),
            second.revision().checked_next().unwrap(),
            second.label(),
            second.metadata(),
        );
        assert_eq!(
            view.insert_initial(second),
            Err(ProjectionError::InvalidRevision)
        );
    }

    #[test]
    fn insert_rejects_a_full_view() {
        let mut view = ProjectionView::<1>::new();
        view.insert_initial(snap(1, "a")).unwrap();
        assert_eq!(
            view.insert_initial(snap(2, "b")),
            Err(ProjectionError::ViewFull)
        );
    }
}
