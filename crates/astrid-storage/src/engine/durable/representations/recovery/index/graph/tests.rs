use super::*;

fn id(value: u8) -> PhysicalMapNodeId {
    PhysicalMapNodeId::new([value; 32])
}

fn insert(graph: &mut HistoricalMapGraph, value: u8, children: &[u8]) {
    let children: Vec<_> = children.iter().map(|value| id(*value)).collect();
    graph
        .insert(
            id(value),
            FrameLocation::for_test(u64::from(value), 0),
            &children,
        )
        .unwrap();
}

#[test]
fn forward_references_resolve_without_duplicate_ids_or_per_node_edge_allocations() {
    let mut graph = HistoricalMapGraph::default();
    insert(&mut graph, 1, &[2, 3]);
    assert_eq!(graph.len(), 1);
    assert_eq!(graph.nodes.len(), 3);
    assert_eq!(graph.indices.len(), 3);
    assert_eq!(graph.edge_count(), 2);
    assert!(graph.location(&id(2)).is_none());
    assert!(!graph.closure_checker().complete(Some(id(1))));
    insert(&mut graph, 3, &[]);
    insert(&mut graph, 2, &[3]);
    assert_eq!(graph.len(), 3);
    assert_eq!(graph.nodes.len(), 3);
    assert_eq!(graph.indices.len(), 3);
    assert_eq!(graph.edge_count(), 3);
    let mut closure = graph.closure_checker();
    assert!(closure.complete(Some(id(1))));
    assert_eq!(closure.len(), 3);
    let visits = closure.visits();
    assert_eq!(visits, 3);
    assert!(closure.complete(Some(id(1))));
    assert!(closure.complete(Some(id(2))));
    assert_eq!(closure.visits(), visits);
}

#[test]
fn duplicate_resolution_cannot_replace_body_or_grow_edges() {
    let mut graph = HistoricalMapGraph::default();
    insert(&mut graph, 1, &[2]);
    let edges = graph.edge_count();
    for children in [vec![id(2)], vec![id(3), id(4)]] {
        assert!(
            graph
                .insert(id(1), FrameLocation::for_test(99, 0), &children)
                .is_err()
        );
        assert_eq!(graph.edge_count(), edges);
        assert_eq!(graph.nodes.len(), 2);
        assert_eq!(graph.len(), 1);
        assert_eq!(graph.location(&id(1)).unwrap().offset(), 1);
    }
}

#[test]
fn failed_closures_reset_only_touched_nodes_and_preserve_earlier_success() {
    let mut graph = HistoricalMapGraph::default();
    insert(&mut graph, 1, &[2]);
    insert(&mut graph, 2, &[]);
    insert(&mut graph, 3, &[1, 4]);
    insert(&mut graph, 5, &[]);
    let mut closure = graph.closure_checker();
    assert!(closure.complete(Some(id(1))));
    assert_eq!(closure.len(), 2);
    let statuses = closure.status.clone();
    for _ in 0..3 {
        assert!(!closure.complete(Some(id(3))));
        assert_eq!(closure.len(), 2);
        assert!(closure.pending.is_empty());
        assert!(closure.touched.is_empty());
        assert!(closure.status == statuses);
    }
    assert!(!closure.complete(Some(id(99))));
    assert_eq!(closure.len(), 2);
    assert!(closure.complete(Some(id(1))));
    assert_eq!(closure.len(), 2);
    assert!(closure.complete(Some(id(5))));
    assert_eq!(closure.len(), 3);
    assert!(closure.complete(None));
    assert_eq!(closure.len(), 3);
}

#[test]
fn missing_forward_body_can_succeed_only_with_a_new_snapshot_checker() {
    let mut graph = HistoricalMapGraph::default();
    insert(&mut graph, 1, &[2]);
    {
        let mut closure = graph.closure_checker();
        assert!(!closure.complete(Some(id(1))));
        assert!(!closure.complete(Some(id(1))));
        assert_eq!(closure.len(), 0);
    }
    insert(&mut graph, 2, &[]);
    let mut closure = graph.closure_checker();
    assert!(closure.complete(Some(id(1))));
    assert_eq!(closure.len(), 2);
    assert!(closure.complete(Some(id(1))));
    assert_eq!(closure.len(), 2);
}

#[test]
fn historical_cycle_walk_keeps_the_existing_visited_set_semantics() {
    let mut graph = HistoricalMapGraph::default();
    insert(&mut graph, 1, &[2]);
    insert(&mut graph, 2, &[1]);
    insert(&mut graph, 3, &[3]);
    let mut closure = graph.closure_checker();
    assert!(closure.complete(Some(id(1))));
    assert_eq!(closure.len(), 2);
    assert!(closure.complete(Some(id(2))));
    assert_eq!(closure.len(), 2);
    assert!(closure.complete(Some(id(3))));
    assert_eq!(closure.len(), 3);
}

#[test]
fn consuming_offsets_preserves_ordered_child_inventory_and_interned_slots() {
    let mut graph = HistoricalMapGraph::default();
    insert(&mut graph, 1, &[2, 3]);
    insert(&mut graph, 2, &[]);
    insert(&mut graph, 3, &[]);
    let node = graph.take(&id(1)).unwrap();
    assert_eq!(node.location.offset(), 1);
    assert_eq!(graph.len(), 2);
    assert_eq!(graph.nodes.len(), 3);
    assert_eq!(graph.edge_count(), 2);
    assert!(graph.location(&id(1)).is_none());
    assert!(graph.take(&id(1)).is_none());
    assert!(graph.take(&id(99)).is_none());
    assert!(!graph.closure_checker().complete(Some(id(1))));
    assert!(graph.matches_children(&node, &[id(2), id(3)]));
    for children in [
        vec![id(3), id(2)],
        vec![id(2)],
        vec![id(2), id(3), id(4)],
        vec![id(2), id(99)],
    ] {
        assert!(!graph.matches_children(&node, &children));
    }
    assert!(graph.take(&id(2)).is_some());
    assert!(graph.matches_children(&node, &[id(2), id(3)]));
    assert_eq!(graph.len(), 1);
    let leaf = graph.take(&id(3)).unwrap();
    assert!(graph.matches_children(&leaf, &[]));
    assert_eq!(graph.len(), 0);
}

#[test]
fn a_cycle_does_not_hide_an_unresolved_descendant() {
    let mut graph = HistoricalMapGraph::default();
    insert(&mut graph, 1, &[1, 2]);
    {
        let mut closure = graph.closure_checker();
        for _ in 0..3 {
            assert!(!closure.complete(Some(id(1))));
            assert_eq!(closure.len(), 0);
        }
    }
    insert(&mut graph, 2, &[]);
    let mut closure = graph.closure_checker();
    assert!(closure.complete(Some(id(1))));
    assert_eq!(closure.len(), 2);
}

#[test]
fn consumed_bodies_cannot_be_resolved_again_or_orphan_their_edges() {
    let mut graph = HistoricalMapGraph::default();
    insert(&mut graph, 1, &[2]);
    insert(&mut graph, 2, &[]);
    for value in [1, 2] {
        let node = graph.take(&id(value)).unwrap();
        let counts = (graph.len(), graph.nodes.len(), graph.edge_count());
        assert!(
            graph
                .insert(id(value), FrameLocation::for_test(99, 0), &[id(3)])
                .is_err()
        );
        assert_eq!((graph.len(), graph.nodes.len(), graph.edge_count()), counts);
        assert!(graph.location(&id(value)).is_none());
        assert!(graph.take(&id(value)).is_none());
        let children: &[PhysicalMapNodeId] = if value == 1 { &[id(2)] } else { &[] };
        assert!(graph.matches_children(&node, children));
    }
    assert_eq!(graph.len(), 0);
    // A failed take of a forward reference must not consume its future body.
    insert(&mut graph, 4, &[5]);
    assert!(graph.take(&id(5)).is_none());
    insert(&mut graph, 5, &[]);
    assert!(graph.closure_checker().complete(Some(id(4))));
}

#[test]
#[cfg(target_pointer_width = "64")]
fn historical_node_descriptor_extent_budget() {
    eprintln!(
        "historical NodeBody={} NodeDescriptor={} FrameLocation={}",
        std::mem::size_of::<NodeBody>(),
        std::mem::size_of::<NodeDescriptor>(),
        std::mem::size_of::<FrameLocation>()
    );
    // Every historical node pays this transient descriptor cost. Guard the
    // measured eight-byte increase over the previous 32-byte descriptor.
    assert!(std::mem::size_of::<NodeBody>() <= 24);
    assert!(std::mem::size_of::<NodeDescriptor>() <= 40);
}
