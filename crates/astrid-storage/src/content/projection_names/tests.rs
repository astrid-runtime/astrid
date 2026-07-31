use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU16;
use std::sync::Mutex;

use caseless::default_case_fold_str;
use unicode_normalization::UnicodeNormalization;

use super::*;

fn name(value: &str) -> ContentName {
    ContentName::new(value).unwrap()
}

fn path_for<'a>(plan: &'a ProjectionNamePlan, source: &str) -> &'a ProjectedContentPath {
    plan.projected_path(&name(source)).unwrap()
}

#[test]
fn byte_exact_safe_names_keep_their_natural_hierarchy() {
    let names = vec![
        name("projects/game/Cargo.toml"),
        name("projects/game/src/main.rs"),
        name("README.md"),
    ];
    let plan = plan_projection_names(ProjectionNamePolicy::posix_exact_v1(), &names).unwrap();

    assert_eq!(
        path_for(&plan, "projects/game/src/main.rs").display_path(),
        "projects/game/src/main.rs"
    );
    assert!(plan.collisions().is_empty());
    assert!(plan.escaped().is_empty());
}

#[test]
fn ascii_case_collisions_disambiguate_every_member() {
    let names = vec![name("Readme"), name("README"), name("readme")];
    let plan = plan_projection_names(
        ProjectionNamePolicy::unicode_canonical_caseless_v1(),
        &names,
    )
    .unwrap();

    assert_eq!(plan.collisions().len(), 1);
    assert_eq!(
        plan.collisions()[0].sources(),
        &[name("README"), name("Readme"), name("readme")]
    );
    let paths = names
        .iter()
        .map(|source| plan.projected_path(source).unwrap().display_path())
        .collect::<BTreeSet<_>>();
    assert_eq!(paths.len(), names.len());
    assert!(paths.iter().all(|path| path.contains("~astrid-f-")));
}

#[test]
fn canonical_unicode_variants_collide_without_changing_authority() {
    let composed = name("caf\u{e9}/menu");
    let decomposed = name("cafe\u{301}/menu");
    let plan = plan_projection_names(
        ProjectionNamePolicy::unicode_canonical_v1(),
        &[composed.clone(), decomposed.clone()],
    )
    .unwrap();

    assert_eq!(plan.collisions().len(), 1);
    assert_eq!(
        plan.collisions()[0].sources(),
        &[decomposed.clone(), composed.clone()]
    );
    assert_eq!(plan.mappings()[0].source(), &decomposed);
    assert_eq!(plan.mappings()[1].source(), &composed);
}

#[test]
fn full_case_fold_handles_multi_character_equivalence() {
    let names = vec![name("Stra\u{df}e"), name("STRASSE")];
    let plan = plan_projection_names(ProjectionNamePolicy::windows_caseless_v1(), &names).unwrap();

    assert_eq!(plan.collisions().len(), 1);
    assert_ne!(path_for(&plan, "Stra\u{df}e"), path_for(&plan, "STRASSE"));
}

#[test]
fn file_directory_conflict_gets_distinct_roles() {
    let names = vec![name("a"), name("a/b"), name("a/c")];
    let plan = plan_projection_names(ProjectionNamePolicy::posix_exact_v1(), &names).unwrap();

    assert_eq!(plan.collisions().len(), 1);
    assert_eq!(
        plan.collisions()[0].kind(),
        ProjectionCollisionKind::FileDirectoryConflict
    );
    assert!(
        path_for(&plan, "a")
            .segments()
            .first()
            .unwrap()
            .as_str()
            .contains("~astrid-f-")
    );
    assert!(
        path_for(&plan, "a/b")
            .segments()
            .first()
            .unwrap()
            .as_str()
            .contains("~astrid-d-")
    );
}

#[test]
fn structural_and_repeated_separators_are_reversible() {
    let names = vec![
        name("./file"),
        name("../file"),
        name("/file"),
        name("a//file"),
        name("a/./file"),
    ];
    let plan = plan_projection_names(ProjectionNamePolicy::posix_exact_v1(), &names).unwrap();

    assert_eq!(plan.mappings().len(), names.len());
    assert_eq!(
        plan.mappings()
            .iter()
            .map(super::ProjectionNameMapping::projected)
            .collect::<BTreeSet<_>>()
            .len(),
        names.len()
    );
    assert!(plan.escaped().len() >= names.len());
}

#[test]
fn windows_special_names_and_characters_are_escaped() {
    let names = vec![
        name("CON"),
        name("CONIN$"),
        name("conout$.txt"),
        name("nul.txt"),
        name("COM\u{b9}"),
        name("trail."),
        name("trail "),
        name("bad:name"),
        name("bad\\name"),
    ];
    let plan = plan_projection_names(ProjectionNamePolicy::windows_caseless_v1(), &names).unwrap();

    assert_eq!(plan.escaped().len(), names.len());
    for mapping in plan.mappings() {
        let segment = mapping.projected().segments().last().unwrap().as_str();
        assert!(segment.contains("~astrid-f-"));
        assert!(!segment.ends_with(' ') && !segment.ends_with('.'));
    }
}

#[test]
fn projection_suffix_has_a_stable_golden_vector() {
    let source = name("CON");
    let plan = plan_projection_names(
        ProjectionNamePolicy::windows_caseless_v1(),
        std::slice::from_ref(&source),
    )
    .unwrap();

    assert_eq!(
        plan.projected_path(&source).unwrap().display_path(),
        "CON~astrid-f-6631de41d49775f1790fd042e3d3a94fde8a8c8420252ae2823546a321f5e149"
    );
}

#[test]
fn long_segments_preserve_a_full_collision_checked_suffix() {
    let long = "x".repeat(1024);
    let source = ContentName::new(long).unwrap();
    let policy = ProjectionNamePolicy::posix_exact_v1();
    let plan = plan_projection_names(policy, std::slice::from_ref(&source)).unwrap();
    let projected = plan.projected_path(&source).unwrap().segments()[0].as_str();

    assert_eq!(
        projected.len(),
        usize::from(policy.max_segment_units().get())
    );
    assert!(projected.contains("~astrid-f-"));
    assert_eq!(
        plan.escaped()[0].reason(),
        ProjectionEscapeReason::SegmentTooLong
    );
}

#[test]
fn reserved_marker_cannot_alias_a_generated_name() {
    let names = vec![
        name("foo"),
        name("FOO"),
        name("foo~astrid-f-deadbeef"),
        name("bar~ASTRID-f-deadbeef"),
    ];
    let plan = plan_projection_names(
        ProjectionNamePolicy::unicode_canonical_caseless_v1(),
        &names,
    )
    .unwrap();

    let paths = plan
        .mappings()
        .iter()
        .map(|mapping| mapping.projected().display_path())
        .collect::<BTreeSet<_>>();
    assert_eq!(paths.len(), names.len());
    assert!(plan.escaped().iter().any(|entry| {
        entry.source() == &name("foo~astrid-f-deadbeef")
            && entry.reason() == ProjectionEscapeReason::ReservedProjectionMarker
    }));
    assert!(plan.escaped().iter().any(|entry| {
        entry.source() == &name("bar~ASTRID-f-deadbeef")
            && entry.reason() == ProjectionEscapeReason::ReservedProjectionMarker
    }));
}

#[test]
fn plan_is_independent_of_input_iteration_order() {
    let original = vec![
        name("Readme"),
        name("README"),
        name("caf\u{e9}/menu"),
        name("cafe\u{301}/menu"),
        name("a"),
        name("a/b"),
        name("CON"),
        name("a//b"),
    ];
    let expected = plan_projection_names(
        ProjectionNamePolicy::unicode_canonical_caseless_v1(),
        &original,
    )
    .unwrap();

    for shift in 0..original.len() {
        let mut reordered = original.clone();
        reordered.rotate_left(shift);
        if shift % 2 == 1 {
            reordered.reverse();
        }
        let actual = plan_projection_names(
            ProjectionNamePolicy::unicode_canonical_caseless_v1(),
            &reordered,
        )
        .unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn too_small_segment_limit_fails_before_mapping() {
    let policy = ProjectionNamePolicy::new(
        ProjectionNameComparison::ByteExactV1,
        ProjectionNameSyntax::PosixUtf8V1,
        NonZeroU16::new(16).unwrap(),
    );
    assert!(matches!(
        plan_projection_names(policy, &[name("file")]),
        Err(ProjectionNameError::SegmentLimitTooSmall { .. })
    ));
}

#[test]
fn exact_duplicate_catalog_input_is_idempotent() {
    let source = name("same");
    let plan = plan_projection_names(
        ProjectionNamePolicy::posix_exact_v1(),
        &[source.clone(), source],
    )
    .unwrap();

    assert_eq!(plan.mappings().len(), 1);
    assert!(plan.collisions().is_empty());
}

#[test]
fn content_name_deserialization_preserves_validation() {
    assert!(serde_json::from_str::<ContentName>("\"valid\"").is_ok());
    assert!(serde_json::from_str::<ContentName>("\"\"").is_err());
    assert!(serde_json::from_str::<ContentName>("\"bad\\u0000name\"").is_err());
}

#[test]
fn comparison_tables_match_the_frozen_policy_versions() {
    assert_eq!(unicode_normalization::UNICODE_VERSION, (17, 0, 0));
    assert_eq!(caseless::UNICODE_VERSION, (16, 0, 0));
}

#[test]
fn adversarial_catalog_is_total_and_unique_under_every_policy() {
    let long = "x".repeat(512);
    let segments = [
        "a",
        "A",
        "caf\u{e9}",
        "cafe\u{301}",
        "Stra\u{df}e",
        "STRASSE",
        ".",
        "..",
        "",
        "CON",
        "nul.txt",
        "COM\u{b9}",
        "trail.",
        "trail ",
        "bad:name",
        "bad\\name",
        "name~astrid-f-deadbeef",
        &long,
    ];
    let mut names = BTreeSet::new();
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            names.insert(name(&format!("/leaf-{index}")));
            names.insert(name(&format!("parent//leaf-{index}")));
        } else {
            names.insert(name(segment));
            names.insert(name(&format!("{segment}/child")));
            names.insert(name(&format!("prefix/{segment}")));
        }
    }
    let names = names.into_iter().collect::<Vec<_>>();
    let policies = [
        ProjectionNamePolicy::posix_exact_v1(),
        ProjectionNamePolicy::unicode_canonical_v1(),
        ProjectionNamePolicy::unicode_canonical_caseless_v1(),
        ProjectionNamePolicy::windows_caseless_v1(),
    ];

    for policy in policies {
        let expected = plan_projection_names(policy, &names).unwrap();
        assert_eq!(expected.mappings().len(), names.len());
        let keys = expected
            .mappings()
            .iter()
            .map(|mapping| projected_comparison_key(policy, mapping.projected()))
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), names.len(), "policy {}", policy.identifier());
        assert!(expected.mappings().iter().all(|mapping| {
            mapping.projected().segments().iter().all(|segment| {
                segment_units_for_test(policy, segment.as_str())
                    <= usize::from(policy.max_segment_units().get())
            })
        }));

        let mut reversed = names.clone();
        reversed.reverse();
        assert_eq!(plan_projection_names(policy, &reversed).unwrap(), expected);
    }
}

fn projected_comparison_key(
    policy: ProjectionNamePolicy,
    path: &ProjectedContentPath,
) -> Vec<Vec<u8>> {
    path.segments()
        .iter()
        .map(|segment| match policy.comparison() {
            ProjectionNameComparison::ByteExactV1 => segment.as_str().as_bytes().to_vec(),
            ProjectionNameComparison::UnicodeCanonicalV1 => {
                segment.as_str().nfd().collect::<String>().into_bytes()
            },
            ProjectionNameComparison::UnicodeCaselessV1 => {
                default_case_fold_str(segment.as_str()).into_bytes()
            },
            ProjectionNameComparison::UnicodeCanonicalCaselessV1 => {
                default_case_fold_str(&segment.as_str().nfd().collect::<String>())
                    .nfd()
                    .collect::<String>()
                    .into_bytes()
            },
        })
        .collect()
}

fn segment_units_for_test(policy: ProjectionNamePolicy, value: &str) -> usize {
    match policy.syntax() {
        ProjectionNameSyntax::PosixUtf8V1 => value.len(),
        ProjectionNameSyntax::WindowsUtf16V1 => value.encode_utf16().count(),
    }
}

#[derive(Default)]
struct MockAtomicReservations {
    owners: Mutex<BTreeMap<ProjectedContentPath, ContentName>>,
}

#[derive(Debug, PartialEq, Eq)]
struct Occupied;

impl AtomicProjectionNameReservation for MockAtomicReservations {
    type Error = Occupied;

    fn reserve_atomically(
        &self,
        mapping: &ProjectionNameMapping,
    ) -> Result<ProjectionReservationOutcome, Self::Error> {
        let mut owners = self.owners.lock().unwrap();
        match owners.get(mapping.projected()) {
            Some(owner) if owner == mapping.source() => {
                Ok(ProjectionReservationOutcome::AlreadyReservedForSource)
            },
            Some(_) => Err(Occupied),
            None => {
                owners.insert(mapping.projected().clone(), mapping.source().clone());
                Ok(ProjectionReservationOutcome::Reserved)
            },
        }
    }
}

#[test]
fn publication_reservation_never_overwrites_a_late_conflict() {
    let source = name("file");
    let plan = plan_projection_names(
        ProjectionNamePolicy::posix_exact_v1(),
        std::slice::from_ref(&source),
    )
    .unwrap();
    let mapping = &plan.mappings()[0];
    let reservations = MockAtomicReservations::default();

    assert_eq!(
        reservations.reserve_atomically(mapping),
        Ok(ProjectionReservationOutcome::Reserved)
    );
    assert_eq!(
        reservations.reserve_atomically(mapping),
        Ok(ProjectionReservationOutcome::AlreadyReservedForSource)
    );

    let intruder = ProjectionNameMapping::new(name("other"), mapping.projected().clone());
    assert_eq!(reservations.reserve_atomically(&intruder), Err(Occupied));
    assert_eq!(
        reservations.owners.lock().unwrap().get(mapping.projected()),
        Some(&source)
    );
}
