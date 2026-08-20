use crate::content_dag::{ChunkingProfile, build_content};
use crate::storage_model::ObjectIdentity;

use super::*;

#[derive(Clone, Copy)]
struct TestIdentity;

impl ObjectIdentity for TestIdentity {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher = blake3::Hasher::new_derive_key("astrid catalog tree test identity");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        for reference in record.references() {
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[reference.kind().code()]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

fn value(seed: u8, logical_bytes: u64) -> CatalogValue {
    CatalogValue {
        file: ObjectId::new([seed; 32]),
        logical_bytes,
    }
}

fn content_value(
    seed: u8,
    logical_bytes: usize,
) -> (CatalogValue, BTreeMap<ObjectId, ObjectRecord>) {
    let built = build_content(
        &TestIdentity,
        ChunkingProfile::ASTRID_V1,
        &vec![seed; logical_bytes],
    )
    .unwrap();
    (
        CatalogValue {
            file: built.descriptor().file(),
            logical_bytes: built.descriptor().logical_bytes(),
        },
        built.records().iter().cloned().collect(),
    )
}

fn apply_order(names: &[&str]) -> (CatalogRoot, BTreeMap<ObjectId, ObjectRecord>) {
    let identity = TestIdentity;
    let mut root = None;
    let mut objects = BTreeMap::new();
    for (index, name) in names.iter().enumerate() {
        let ordinal = index.checked_add(1).unwrap();
        let (value, content) = content_value(u8::try_from(ordinal).unwrap(), ordinal);
        objects.extend(content);
        let mutation = insert(
            root,
            &ContentName::new(*name).unwrap(),
            value,
            &mut |object| {
                objects
                    .get(&object)
                    .cloned()
                    .ok_or_else(|| invalid(object, "test object is missing"))
            },
            &|record| identity.identify(record),
        )
        .unwrap();
        root = mutation.root;
        objects.extend(mutation.records);
    }
    (root.unwrap(), objects)
}

#[test]
fn format_two_catalog_discriminants_are_stable() {
    assert_eq!(CATALOG_VERSION.get(), 2);
    assert_eq!(LEAF_TAG, 0);
    assert_eq!(BRANCH_TAG, 1);
    assert_eq!(LEAF_FIXED_BYTES, 17);
    assert_eq!(BRANCH_BYTES, 57);
}

#[test]
fn insertion_order_does_not_change_the_canonical_root() {
    let (alpha, alpha_objects) = content_value(1, 1);
    let (alphabet, alphabet_objects) = content_value(2, 2);
    let (model_a, first_model_objects) = content_value(3, 3);
    let (model_z, last_model_objects) = content_value(4, 4);
    let (world, world_objects) = content_value(5, 5);
    let entries = [
        ("alpha", alpha),
        ("alphabet", alphabet),
        ("models/a", model_a),
        ("models/z", model_z),
        ("世界", world),
    ];
    let content_objects: BTreeMap<_, _> = alpha_objects
        .into_iter()
        .chain(alphabet_objects)
        .chain(first_model_objects)
        .chain(last_model_objects)
        .chain(world_objects)
        .collect();
    let permutations = [
        [0, 1, 2, 3, 4],
        [4, 3, 2, 1, 0],
        [2, 0, 4, 1, 3],
        [1, 3, 0, 4, 2],
    ];
    let mut expected = None;
    for permutation in permutations {
        let identity = TestIdentity;
        let mut root = None;
        let mut objects = content_objects.clone();
        for index in permutation {
            let (name, value) = &entries[index];
            let mutation = insert(
                root,
                &ContentName::new(*name).unwrap(),
                *value,
                &mut |object| {
                    objects
                        .get(&object)
                        .cloned()
                        .ok_or_else(|| invalid(object, "test object is missing"))
                },
                &|record| identity.identify(record),
            )
            .unwrap();
            root = mutation.root;
            objects.extend(mutation.records);
        }
        let root = root.unwrap();
        assert_eq!(expected.get_or_insert(root.object), &root.object);
        assert_eq!(
            validate_catalog(Some(root), &mut |object| {
                objects
                    .get(&object)
                    .cloned()
                    .ok_or_else(|| invalid(object, "test object is missing"))
            })
            .unwrap()
            .summary,
            root.summary
        );
    }
}

#[test]
fn lookup_and_mutation_are_bounded_by_the_key_bits() {
    let identity = TestIdentity;
    let mut entries = BTreeMap::new();
    for index in 0..4096_u64 {
        entries.insert(
            ContentName::new(format!("workspace/{index:08x}")).unwrap(),
            value((index % 251) as u8, index),
        );
    }
    let (root, mut objects) = build_catalog(&entries, &|record| identity.identify(record)).unwrap();
    let root = root.unwrap();
    let target = ContentName::new("workspace/00000800").unwrap();
    let mut loads = 0_usize;
    assert_eq!(
        lookup(root.into(), &target, &mut |object| {
            loads = loads.saturating_add(1);
            objects
                .get(&object)
                .cloned()
                .ok_or_else(|| invalid(object, "test object is missing"))
        })
        .unwrap(),
        entries.get(&target).copied()
    );
    assert!(loads <= target.as_str().len().saturating_add(1).saturating_mul(8));

    let mutation = insert(
        Some(root),
        &target,
        value(252, 99),
        &mut |object| {
            objects
                .get(&object)
                .cloned()
                .ok_or_else(|| invalid(object, "test object is missing"))
        },
        &|record| identity.identify(record),
    )
    .unwrap();
    assert!(mutation.records.len() <= target.as_str().len().saturating_add(1).saturating_mul(8));
    objects.extend(mutation.records);
    assert_eq!(
        lookup(mutation.root, &target, &mut |object| {
            objects
                .get(&object)
                .cloned()
                .ok_or_else(|| invalid(object, "test object is missing"))
        })
        .unwrap(),
        Some(value(252, 99))
    );
}

#[test]
fn prefix_exists_does_not_load_every_prefixed_leaf() {
    let identity = TestIdentity;
    let mut entries = BTreeMap::new();
    for index in 0..4096_u64 {
        entries.insert(
            ContentName::new(format!("workspace/{index:08x}")).unwrap(),
            value((index % 251) as u8, index),
        );
    }
    entries.insert(ContentName::new("other/file").unwrap(), value(7, 1));
    let (root, objects) = build_catalog(&entries, &|record| identity.identify(record)).unwrap();
    let root = root.unwrap();
    let prefix = ContentName::new("workspace/").unwrap();
    let load = |counter: &mut usize, object: ObjectId| {
        *counter = counter.saturating_add(1);
        objects
            .get(&object)
            .cloned()
            .ok_or_else(|| invalid(object, "test object is missing"))
    };

    let mut list_loads = 0_usize;
    let listed = list(Some(root), &mut |object| load(&mut list_loads, object)).unwrap();
    assert_eq!(listed.len(), 4097);

    let mut prefix_list_loads = 0_usize;
    let prefixed = list_prefix(Some(root), &prefix, &mut |object| {
        load(&mut prefix_list_loads, object)
    })
    .unwrap();
    assert_eq!(prefixed.len(), 4096);

    let mut exists_loads = 0_usize;
    assert!(
        prefix_exists(Some(root), &prefix, &mut |object| load(
            &mut exists_loads,
            object
        ))
        .unwrap()
    );
    let bound = prefix.as_str().len().saturating_add(1).saturating_mul(8);
    assert!(
        exists_loads <= bound,
        "prefix_exists loaded {exists_loads} nodes, bound {bound}"
    );
    assert!(
        exists_loads < list_loads,
        "prefix_exists loaded {exists_loads}, list loaded {list_loads}"
    );
    assert!(
        exists_loads < prefix_list_loads,
        "prefix_exists loaded {exists_loads}, list_prefix loaded {prefix_list_loads}"
    );

    let missing = ContentName::new("missing/").unwrap();
    let mut missing_loads = 0_usize;
    assert!(
        !prefix_exists(Some(root), &missing, &mut |object| load(
            &mut missing_loads,
            object
        ))
        .unwrap()
    );
    assert!(missing_loads <= bound);
}

#[test]
fn deletion_matches_a_fresh_canonical_build() {
    let identity = TestIdentity;
    let mut entries = BTreeMap::from([
        (ContentName::new("a").unwrap(), value(1, 10)),
        (ContentName::new("ab").unwrap(), value(2, 20)),
        (ContentName::new("b").unwrap(), value(3, 30)),
        (ContentName::new("世界").unwrap(), value(4, 40)),
    ]);
    let (root, mut objects) = build_catalog(&entries, &|record| identity.identify(record)).unwrap();
    let removed = ContentName::new("ab").unwrap();
    let mutation = delete(
        root,
        &removed,
        &mut |object| {
            objects
                .get(&object)
                .cloned()
                .ok_or_else(|| invalid(object, "test object is missing"))
        },
        &|record| identity.identify(record),
    )
    .unwrap();
    objects.extend(mutation.records);
    entries.remove(&removed);
    let (rebuilt, _) = build_catalog(&entries, &|record| identity.identify(record)).unwrap();
    assert_eq!(mutation.root, rebuilt);
}

#[test]
fn validation_rejects_shared_children_and_false_accounting() {
    let identity = TestIdentity;
    let (root, mut objects) = apply_order(&["alpha", "omega"]);
    let root_record = objects.get(&root.object).unwrap().clone();
    let Node::Branch {
        bit, left, right, ..
    } = decode_node(root.object, &root_record).unwrap()
    else {
        panic!("two names must produce a branch");
    };
    let shared = intern_branch(
        bit,
        left,
        CatalogRoot {
            object: left.object,
            summary: right.summary,
        },
        &|record| identity.identify(record),
        &mut objects,
    )
    .unwrap();
    assert!(
        validate_catalog(Some(shared), &mut |object| {
            objects
                .get(&object)
                .cloned()
                .ok_or_else(|| invalid(object, "test object is missing"))
        })
        .is_err()
    );

    let mut bytes = root_record.canonical_bytes().to_vec();
    bytes[17] ^= 1;
    let corrupt = ObjectRecord::new(
        root_record.kind(),
        root_record.format_version(),
        bytes,
        root_record.references().to_vec(),
        root_record.logical_bytes(),
        root_record.class(),
    )
    .unwrap();
    let corrupt_id = identity.identify(&corrupt);
    objects.insert(corrupt_id, corrupt.clone());
    let corrupt_root = root_from_record(corrupt_id, &corrupt).unwrap();
    assert!(
        validate_catalog(Some(corrupt_root), &mut |object| {
            objects
                .get(&object)
                .cloned()
                .ok_or_else(|| invalid(object, "test object is missing"))
        })
        .is_err()
    );
}

#[test]
fn thousand_path_copy_insertions_have_bounded_catalog_node_metadata() {
    const PUBLICATIONS: u64 = 1_000;
    const LOGICAL_BYTES: u64 = 4 * 1024;
    const TOTAL_METADATA_BUDGET: u64 = 4 * 1024 * 1024;

    let identity = TestIdentity;
    let (shared_value, mut objects) = content_value(7, usize::try_from(LOGICAL_BYTES).unwrap());
    let mut root = None;
    let mut total_metadata = 0_u64;
    let mut largest_publication = 0_u64;

    for index in 0..PUBLICATIONS {
        let name = ContentName::new(format!("workspace/fixture/{index:04}")).unwrap();
        let mutation = insert(
            root,
            &name,
            shared_value,
            &mut |object| {
                objects
                    .get(&object)
                    .cloned()
                    .ok_or_else(|| invalid(object, "fixture object is missing"))
            },
            &|record| identity.identify(record),
        )
        .unwrap();
        assert_eq!(mutation.previous, None);

        let retained = mutation
            .records
            .values()
            .map(|record| record.retained_bytes().unwrap())
            .sum::<u64>();
        total_metadata = total_metadata.checked_add(retained).unwrap();
        largest_publication = largest_publication.max(retained);
        root = mutation.root;
        objects.extend(mutation.records);
    }

    let validation = validate_catalog(root, &mut |object| {
        objects
            .get(&object)
            .cloned()
            .ok_or_else(|| invalid(object, "fixture object is missing"))
    })
    .unwrap();
    assert_eq!(validation.summary.entries, PUBLICATIONS);
    assert_eq!(
        validation.summary.logical_bytes,
        PUBLICATIONS.checked_mul(LOGICAL_BYTES).unwrap()
    );
    assert!(
        largest_publication < LOGICAL_BYTES,
        "one deduplicated publication retained {largest_publication} bytes of catalog metadata"
    );
    assert!(
        total_metadata < TOTAL_METADATA_BUDGET,
        "1,000 deduplicated publications retained {total_metadata} catalog metadata bytes"
    );
}

#[test]
#[ignore = "explicit catalog cardinality and amplification probe"]
fn catalog_scale_probe() {
    use std::time::Instant;

    use crate::content::{LegacyCatalog, encode_legacy_catalog};

    let identity = TestIdentity;
    for cardinality in [2_000_u64, 230_000] {
        let entries: BTreeMap<_, _> = (0..cardinality)
            .map(|index| {
                (
                    ContentName::new(format!("workspace/{index:016x}")).unwrap(),
                    value((index % 251) as u8, 4096),
                )
            })
            .collect();
        let build_started = Instant::now();
        let (root, mut objects) =
            build_catalog(&entries, &|record| identity.identify(record)).unwrap();
        let build_elapsed = build_started.elapsed();
        let root = root.unwrap();
        let legacy_logical = cardinality.checked_mul(4096).unwrap();
        let legacy_name_bytes = entries
            .keys()
            .try_fold(0_u64, |total, name| {
                total.checked_add(u64::try_from(name.as_str().len()).ok()?)
            })
            .unwrap();
        let legacy_quota = legacy_logical.checked_add(legacy_name_bytes).unwrap();
        let legacy = LegacyCatalog {
            entries: entries.clone(),
            logical_bytes: legacy_logical,
            quota_bytes: legacy_quota,
        };
        let legacy_retained_bytes = encode_legacy_catalog(&legacy)
            .unwrap()
            .retained_bytes()
            .unwrap();
        let target = ContentName::new(format!("workspace/{:016x}", cardinality / 2)).unwrap();

        let samples = 10_000_u32;
        let read_started = Instant::now();
        for _ in 0..samples {
            assert!(
                lookup(Some(root), &target, &mut |object| {
                    objects
                        .get(&object)
                        .cloned()
                        .ok_or_else(|| invalid(object, "probe object is missing"))
                })
                .unwrap()
                .is_some()
            );
        }
        let read_elapsed = read_started.elapsed();
        let mutation = insert(
            Some(root),
            &target,
            value(252, 4096),
            &mut |object| {
                objects
                    .get(&object)
                    .cloned()
                    .ok_or_else(|| invalid(object, "probe object is missing"))
            },
            &|record| identity.identify(record),
        )
        .unwrap();
        let mutation_objects = mutation.records.len();
        let retained_bytes = mutation
            .records
            .values()
            .map(|record| record.retained_bytes().unwrap())
            .sum::<u64>();
        objects.extend(mutation.records);
        println!(
            "catalog_probe entries={cardinality} build_ms={} read_ns={} mutation_objects={} mutation_retained_bytes={retained_bytes} legacy_rewrite_retained_bytes={legacy_retained_bytes}",
            build_elapsed.as_millis(),
            read_elapsed.as_nanos() / u128::from(samples),
            mutation_objects,
        );
    }
}
