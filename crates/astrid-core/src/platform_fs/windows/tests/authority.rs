//! Retained-authority behavior while an ancestor namespace entry changes.

use super::*;

#[test]
fn handle_relative_mutation_fails_closed_or_stays_bound_during_ancestor_move() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let ancestor = root.path().join("ancestor");
    let guarded = ancestor.join("guarded");
    std::fs::create_dir(&ancestor).unwrap();
    std::fs::create_dir(&guarded).unwrap();
    apply_private_acl(&ancestor, true).unwrap();
    apply_private_acl(&guarded, true).unwrap();
    let source = guarded.join("source");
    let destination = guarded.join("destination");
    std::fs::write(&source, b"authority-bound-content").unwrap();
    apply_private_acl(&source, false).unwrap();
    let guard = TrustedPathGuard::capture(&guarded).unwrap();
    let moved_ancestor = root.path().join("moved-ancestor");

    let result = guard.with_verified_mutation(
        "ancestor-move handle-relative test",
        BoundaryContract::ExactPrivateDirectory,
        || {
            std::fs::rename(&ancestor, &moved_ancestor)?;
            move_guarded_file(&guard, &source, &destination)
        },
    );

    assert!(result.is_err());
    assert!(!destination.exists());
    let moved_guarded = moved_ancestor.join("guarded");
    let outcomes = [
        std::fs::read(&source),
        std::fs::read(moved_guarded.join("source")),
        std::fs::read(moved_guarded.join("destination")),
    ];
    let valid = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, Ok(bytes) if bytes == b"authority-bound-content"))
        .count()
        == 1
        && outcomes.iter().all(|outcome| {
            outcome
                .as_ref()
                .is_ok_and(|bytes| bytes == b"authority-bound-content")
                || outcome
                    .as_ref()
                    .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        });
    assert!(
        valid,
        "ancestor move must preserve exactly one authority-bound copy: {outcomes:?}"
    );
}
