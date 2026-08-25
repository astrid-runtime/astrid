//! Honest and hostile in-crate projection fixtures.

use astrid_resource_types::{ResourceId, ResourceTypeId};

use crate::error::ProjectionError;
use crate::object::SemanticObjectId;
use crate::presentation::{PresentationLabel, PresentationMetadata};
use crate::revision::ProjectionRevision;
use crate::snapshot::ProjectionSnapshot;
use crate::view::ProjectionView;

/// Honest two-object view used by consumer tests.
///
/// # Errors
///
/// Propagates view insert failures. Fixture labels are short UTF-8.
pub fn honest_two_object_view() -> Result<ProjectionView<4>, ProjectionError> {
    let mut view = ProjectionView::new();
    view.insert_initial(honest_snapshot(1, 11, "alpha")?)?;
    view.insert_initial(honest_snapshot(2, 22, "beta")?)?;
    Ok(view)
}

/// Honest initial snapshot bound to a resource and type identity.
///
/// # Errors
///
/// Returns [`ProjectionError::InvalidUtf8`] or [`ProjectionError::LabelTooLong`].
pub fn honest_snapshot(
    resource_byte: u8,
    type_byte: u8,
    label: &str,
) -> Result<ProjectionSnapshot, ProjectionError> {
    Ok(ProjectionSnapshot::new(
        SemanticObjectId::for_resource(ResourceId::from_bytes([resource_byte; 32])),
        ResourceTypeId::from_bytes([type_byte; 32]),
        ProjectionRevision::INITIAL,
        PresentationLabel::from_utf8(label.as_bytes())?,
        PresentationMetadata::EMPTY,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{DescriptorDecode, DescriptorEncode};
    use crate::snapshot::ProjectionUpdate;
    use astrid_resource_types::CanonicalEncode;

    #[test]
    fn honest_lookup_is_exact_id_only() {
        let view = honest_two_object_view().unwrap();
        let alpha = honest_snapshot(1, 11, "alpha").unwrap();
        let found = view.get(alpha.object()).unwrap();
        assert_eq!(found.label().as_str(), "alpha");
        assert_eq!(found.object().resource(), ResourceId::from_bytes([1; 32]));
        assert!(
            view.get(SemanticObjectId::for_resource(ResourceId::from_bytes(
                [9; 32]
            )))
            .is_none()
        );
        assert_eq!(
            view.get_revision(alpha.object(), ProjectionRevision::INITIAL)
                .unwrap()
                .revision(),
            ProjectionRevision::INITIAL
        );
    }

    #[test]
    fn hostile_enumeration_and_stale_revision_fail_closed() {
        let mut view = honest_two_object_view().unwrap();
        let alpha = honest_snapshot(1, 11, "alpha").unwrap();
        assert_eq!(
            view.by_type(alpha.type_id()).unwrap_err(),
            ProjectionError::EnumerationRefused
        );
        assert_eq!(
            view.by_label(&alpha.label()).unwrap_err(),
            ProjectionError::EnumerationRefused
        );
        assert_eq!(
            view.try_all().unwrap_err(),
            ProjectionError::EnumerationRefused
        );
        let stale = alpha.revision().checked_next().unwrap();
        assert!(matches!(
            view.get_revision(alpha.object(), stale),
            Err(ProjectionError::StaleRevision { .. })
        ));
        let later = ProjectionUpdate::advance(
            alpha.object(),
            alpha.type_id(),
            stale,
            alpha.label(),
            alpha.metadata(),
        )
        .unwrap();
        assert!(matches!(
            view.apply(&later),
            Err(ProjectionError::StaleRevision { .. })
        ));
    }

    #[test]
    fn hostile_schema_confusion_and_synthesized_labels_cannot_invoke() {
        let mut view = honest_two_object_view().unwrap();
        let alpha = honest_snapshot(1, 11, "alpha").unwrap();
        let confused = ProjectionUpdate::advance(
            alpha.object(),
            ResourceTypeId::from_bytes([0xee; 32]),
            alpha.revision(),
            PresentationLabel::from_utf8(b"ADMIN GRANT").unwrap(),
            PresentationMetadata::try_from_pairs(&[
                ("rights", "root"),
                ("invoke", "true"),
                ("action_handle", "forged"),
            ])
            .unwrap(),
        )
        .unwrap();
        assert_eq!(view.apply(&confused), Err(ProjectionError::TypeMismatch));

        let labeled = ProjectionUpdate::advance(
            alpha.object(),
            alpha.type_id(),
            alpha.revision(),
            PresentationLabel::from_utf8(b"ADMIN GRANT").unwrap(),
            PresentationMetadata::try_from_pairs(&[("rights", "root"), ("invoke", "true")])
                .unwrap(),
        )
        .unwrap();
        let next = view.apply(&labeled).unwrap();
        assert_eq!(next.label().as_str(), "ADMIN GRANT");
        assert_eq!(
            next.as_live_invocation(),
            Err(ProjectionError::NotAnInvocation)
        );
        assert!(
            next.metadata()
                .iter()
                .any(|(key, value)| key == "invoke" && value == "true")
        );
    }

    #[test]
    fn serialized_presentation_cannot_become_an_invocation() {
        let snap = honest_snapshot(3, 33, "gamma").unwrap();
        let mut buf = [0_u8; 512];
        let n = snap.encoded_len();
        snap.encode_descriptor(&mut buf[..n]).unwrap();
        let decoded = ProjectionSnapshot::decode_descriptor(&buf[..n]).unwrap();
        assert_eq!(
            decoded.as_live_invocation(),
            Err(ProjectionError::NotAnInvocation)
        );
        buf[n] = 0x01;
        assert!(ProjectionSnapshot::decode_descriptor(&buf[..=n]).is_err());
        // A ResourceId encoding is not a semantic object or snapshot.
        let mut resource = [0_u8; 35];
        snap.object()
            .resource()
            .encode_canonical(&mut resource)
            .unwrap();
        assert!(SemanticObjectId::decode_descriptor(&resource).is_err());
        assert!(ProjectionSnapshot::decode_descriptor(&resource).is_err());
    }
}
