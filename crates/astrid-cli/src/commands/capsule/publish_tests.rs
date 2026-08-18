use super::publish::classification_label;
use astrid_capsule_index::PublicationClassification;

#[test]
fn publish_classification_labels_are_stable() {
    assert_eq!(classification_label(PublicationClassification::New), "new");
    assert_eq!(
        classification_label(PublicationClassification::Idempotent),
        "idempotent"
    );
    assert_eq!(
        classification_label(PublicationClassification::Equivocation),
        "equivocation"
    );
}
