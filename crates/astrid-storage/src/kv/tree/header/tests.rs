use super::*;
use crate::engine::InMemoryEngine;
use crate::kv::tree_tests::TestIdentity;

#[test]
fn validated_mutations_compare_payloads_and_preserve_same_length_changes() {
    let engine = InMemoryEngine::new(TestIdentity);
    let principal = "alice".to_owned();
    let mut context = TreeContext::new(&engine, &principal);
    let key = b"alice:capsule:ownership\0graph".to_vec();
    let before = vec![1; 512 * 1024];
    let after = vec![2; before.len()];
    let tree = context
        .build_sorted(vec![(key.clone(), before.clone())])
        .unwrap();
    let validated = context.validate_tree(tree).unwrap();
    let mut totals = NodeTotals {
        entries: validated.entries,
        logical_bytes: validated.logical_bytes,
        quota_bytes: validated.quota_bytes,
    };
    let mut overlay = OverlayMap::default();
    let replacement_tree = context
        .build_sorted(vec![(key.clone(), after.clone())])
        .unwrap()
        .unwrap();
    let crate::kv::tree::node::Node::Leaf(leaf) = context.node(replacement_tree).unwrap().node
    else {
        panic!("single value must use a leaf");
    };
    let replacement = leaf.entries[0].value.clone();
    let mutations = [Mutation {
        key: key.clone(),
        value: Some(replacement),
    }];
    let (result, output) = crate::content_dag::output_measurement::measure(|| {
        apply_validated_mutations(
            tree.unwrap(),
            &mut context,
            tree,
            &mut overlay,
            &mut totals,
            &mutations,
        )
    });
    result.unwrap();
    assert_eq!(overlay.get(&key), Some(&Some(after)));
    assert_eq!(totals.logical_bytes, validated.logical_bytes);
    assert_eq!(
        output.reserved,
        before.len() * 2,
        "old and new bytes are both needed for equality"
    );
    assert!(
        apply_validated_mutations(
            tree.unwrap(),
            &mut context,
            tree,
            &mut overlay,
            &mut totals,
            &mutations
        )
        .unwrap_err()
        .to_string()
        .contains("no-op mutation")
    );
}
