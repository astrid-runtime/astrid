//! Previous traversal retained solely as a partial-closure and wire-byte oracle.
use super::*;

pub(super) fn append(
    metadata: &mut Vec<MetadataFrame>,
    map: &(impl MapView + ?Sized),
    durable: &impl NodePresence,
    appended: &mut BTreeSet<PhysicalMapNodeId>,
    complete: &mut impl CompleteNodes,
) -> Result<usize, DurableError> {
    let Some(root) = map.view_root() else {
        return Ok(0);
    };
    let mut pending = vec![(root, false)];
    let mut visited = BTreeSet::new();
    while let Some((id, expanded)) = pending.pop() {
        if expanded {
            let node = map.view_node(id)?;
            // A persisted parent alone does not establish durable descendants.
            // Cache only closures checked against the append-only persisted set.
            let children_complete = match &node {
                PhysicalMapNode::Branch { zero, one, .. } => {
                    complete.complete(zero)? && complete.complete(one)?
                },
                PhysicalMapNode::Radix { children, .. } => children_complete(complete, children)?,
                PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => true,
            };
            if durable.has_node(&id)? && children_complete {
                complete.remember(id)?;
            }
            if !durable.has_node(&id)? && !appended.contains(&id) {
                metadata.push(MetadataFrame::map_node(&Blake3PhysicalIdentity, &node)?);
                appended.insert(id);
            }
            continue;
        }
        if complete.complete(&id)? || !visited.insert(id) {
            continue;
        }
        let node = map.view_node(id)?;
        pending.push((id, true));
        match &node {
            PhysicalMapNode::Branch { zero, one, .. } => {
                pending.push((*one, false));
                pending.push((*zero, false));
            },
            PhysicalMapNode::Radix { children, .. } => {
                pending.extend(children.iter().rev().map(|child| (*child, false)));
            },
            PhysicalMapNode::Leaf { .. } | PhysicalMapNode::Page { .. } => {},
        }
    }
    Ok(visited.len())
}

fn children_complete(
    complete: &impl CompleteNodes,
    children: &[PhysicalMapNodeId],
) -> Result<bool, DurableError> {
    for child in children {
        if !complete.complete(child)? {
            return Ok(false);
        }
    }
    Ok(true)
}
