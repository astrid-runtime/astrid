use super::*;

fn fixture() -> (File, CanonicalPhysicalMap, ColdNodes) {
    let map = CanonicalPhysicalMap::build_dense(
        &Blake3PhysicalIdentity,
        PhysicalMapDomain::Representation,
        (0_u16..1024)
            .map(|ordinal| {
                (
                    PhysicalMapKey::new(*blake3::hash(&ordinal.to_le_bytes()).as_bytes()),
                    vec![7; 16],
                )
            })
            .collect(),
    )
    .unwrap();
    let file = File::native(tempfile::tempfile().unwrap());
    for node in map.nodes().values() {
        let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, node)
            .unwrap()
            .encode()
            .unwrap();
        append_frame(&mut file.try_clone().unwrap(), METADATA_MAGIC, &payload).unwrap();
    }
    let budget = LocationIndexMemoryBudget::new(
        std::num::NonZeroU64::new(LocationIndexMemoryBudget::MIN_BYTES).unwrap(),
    )
    .unwrap();
    let nodes = ColdNodes::from_validated_maps(
        &file,
        RecoveryLimits::process_addressable(),
        budget,
        &[&map],
    )
    .unwrap();
    (file, map, nodes)
}

#[test]
fn checkpoint_memo_reuses_page_proofs_without_retaining_nodes() {
    let (_file, map, nodes) = fixture();
    assert!(nodes.0.lock().locations.test_spilled_run_count() > 0);
    let provider = nodes.memoized_nodes();
    let cold_view = map.with_node_provider(nodes.clone());
    let view = cold_view.with_node_provider(&provider);
    let mut visited = 0;
    super::super::super::node_view::visit_nodes(&view, |_| {
        visited += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(visited, map.nodes().len());
    let (hits, misses) = provider.memo.borrow().test_hit_miss();
    assert!(
        hits > 0,
        "adjacent reads must reuse authenticated ancestors"
    );
    assert!(misses > 0, "first reads must authenticate real run pages");
    let root = map.root().unwrap();
    let before = provider.memo.borrow().test_hit_miss();
    assert_eq!(
        view.node(&Blake3PhysicalIdentity, root).unwrap(),
        map.nodes()[&root]
    );
    assert_eq!(
        view.node(&Blake3PhysicalIdentity, root).unwrap(),
        map.nodes()[&root]
    );
    let after = provider.memo.borrow().test_hit_miss();
    assert!(after.0 > before.0);
    assert!(
        after.1 <= before.1 + 1,
        "repeated root reads reuse locator pages"
    );
}

#[test]
fn checkpoint_memo_does_not_hide_reachable_frame_truncation() {
    let (file, map, nodes) = fixture();
    let provider = nodes.memoized_nodes();
    let cold_view = map.with_node_provider(nodes.clone());
    let view = cold_view.with_node_provider(&provider);
    let root = map.root().unwrap();
    view.node(&Blake3PhysicalIdentity, root).unwrap();
    file.set_len(0).unwrap();
    assert!(view.node(&Blake3PhysicalIdentity, root).is_err());
    assert!(
        nodes.failed(),
        "fresh body validation must fence corruption"
    );
}

#[test]
fn checkpoint_memo_rebinds_after_authenticated_run_damage() {
    let (_file, map, nodes) = fixture();
    let provider = nodes.memoized_nodes();
    let cold_view = map.with_node_provider(nodes.clone());
    let view = cold_view.with_node_provider(&provider);
    for id in map.nodes().keys() {
        view.node(&Blake3PhysicalIdentity, *id).unwrap();
    }
    nodes.0.lock().locations.truncate_test_run();
    assert!(
        map.nodes()
            .keys()
            .any(|id| view.node(&Blake3PhysicalIdentity, *id).is_err())
    );
    assert!(
        nodes.failed(),
        "damaged locator cannot become absence or cached success"
    );
}

#[test]
fn checkpoint_preparation_consolidates_historical_locators_and_keeps_fresh_body_checks() {
    use super::super::super::activation::CompleteNodes;
    let (file, map, nodes) = fixture();
    let provider = nodes.memoized_nodes();
    let root = map.root().unwrap();
    provider.node(root).unwrap();
    let mut historical = Vec::new();
    for ordinal in 0_u16..63 {
        let node = PhysicalMapNode::leaf(
            PhysicalMapDomain::Representation,
            PhysicalMapKey::new(*blake3::hash(&ordinal.to_be_bytes()).as_bytes()),
            vec![9; 16],
        );
        let id = node.identify(&Blake3PhysicalIdentity).unwrap();
        let payload = MetadataFrame::map_node(&Blake3PhysicalIdentity, &node)
            .unwrap()
            .encode()
            .unwrap();
        let location =
            append_frame(&mut file.try_clone().unwrap(), METADATA_MAGIC, &payload).unwrap();
        nodes.promote(id, location).unwrap();
        historical.push((id, node));
    }
    assert!(nodes.0.lock().locations.test_spilled_run_count() > 1);
    let count = nodes.len();
    nodes.prepare_checkpoint_walk().unwrap();
    assert_eq!(nodes.0.lock().locations.test_spilled_run_count(), 1);
    assert_eq!(nodes.len(), count);
    for (id, node) in map.nodes() {
        assert!(nodes.complete(id).unwrap());
        assert_eq!(provider.node(*id).unwrap().unwrap().as_ref(), node);
    }
    for (id, node) in historical {
        assert!(!nodes.complete(&id).unwrap());
        assert_eq!(provider.node(id).unwrap().unwrap().as_ref(), &node);
    }
    file.set_len(0).unwrap();
    assert!(provider.node(root).is_err());
    assert!(nodes.failed());
    assert!(nodes.prepare_checkpoint_walk().is_err());
}
