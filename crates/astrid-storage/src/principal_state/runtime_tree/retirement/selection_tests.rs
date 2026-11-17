use super::*;

#[test]
fn source_selection_preserves_component_prefix_authority() {
    let paths = [
        Path::new("log").join("principals").join("a"),
        Path::new("log").join("principals").join("b").join("nested"),
    ];
    let scopes = paths.iter().map(std::path::PathBuf::as_path).collect();
    for (name, selected) in [
        ("log/principals/a", true),
        ("log/principals/a/capsule/day.log", true),
        ("log/principals/ab/capsule/day.log", false),
        ("log/principals/b", false),
        ("log/principals/b/nested/day.log", true),
        ("log/principals/b/nested-peer/day.log", false),
        ("log/principals", false),
        ("etc/profiles/a.toml", false),
    ] {
        assert_eq!(
            is_selected_source(Some(&scopes), Path::new(name)),
            selected,
            "{name}"
        );
    }
}

#[test]
fn absent_selection_and_empty_selection_keep_distinct_authority() {
    let empty = BTreeSet::new();
    for path in [
        Path::new("etc/profile"),
        Path::new("log/principals/a/day.log"),
    ] {
        assert!(is_selected_source(None, path));
        assert!(!is_selected_source(Some(&empty), path));
    }
}
