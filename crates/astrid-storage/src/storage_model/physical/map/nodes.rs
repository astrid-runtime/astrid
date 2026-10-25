//! Fallible physical-node access independent of resident catalogue layout.
//!
//! A missing node is legitimate when probing a new immutable identity, but a
//! missing reachable node is corruption. Cold providers must propagate I/O.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;

use super::{
    PhysicalIdentity, PhysicalMapDomain, PhysicalMapNode, PhysicalMapNodeId, PhysicalModelError,
};

pub(crate) trait PhysicalMapNodes {
    type Error: From<PhysicalModelError>;

    /// Disposable providers can fence later admission after a reachable-path failure.
    fn note_read_failure(&self) {}

    fn node(&self, id: PhysicalMapNodeId) -> Result<Option<Cow<'_, PhysicalMapNode>>, Self::Error>;
}

pub(crate) trait PhysicalMapMutNodes: PhysicalMapNodes {
    fn put(&mut self, id: PhysicalMapNodeId, node: PhysicalMapNode) -> Result<(), Self::Error>;
}

impl PhysicalMapNodes for BTreeMap<PhysicalMapNodeId, PhysicalMapNode> {
    type Error = PhysicalModelError;

    fn node(&self, id: PhysicalMapNodeId) -> Result<Option<Cow<'_, PhysicalMapNode>>, Self::Error> {
        Ok(self.get(&id).map(Cow::Borrowed))
    }
}

impl PhysicalMapMutNodes for BTreeMap<PhysicalMapNodeId, PhysicalMapNode> {
    fn put(&mut self, id: PhysicalMapNodeId, node: PhysicalMapNode) -> Result<(), Self::Error> {
        self.insert(id, node);
        Ok(())
    }
}

pub(super) fn read<I: PhysicalIdentity, N: PhysicalMapNodes>(
    identity: &I,
    nodes: &N,
    domain: PhysicalMapDomain,
    id: PhysicalMapNodeId,
) -> Result<PhysicalMapNode, N::Error> {
    let node = nodes.node(id)?.ok_or(PhysicalModelError::InvalidMap(
        "missing reachable physical map node",
    ))?;
    if node.domain() != domain || node.identify(identity)? != id {
        return Err(PhysicalModelError::InvalidMap(
            "physical map node domain or identity mismatch",
        )
        .into());
    }
    Ok(node.into_owned())
}

pub(super) fn store<I: PhysicalIdentity, N: PhysicalMapMutNodes>(
    identity: &I,
    nodes: &mut N,
    node: PhysicalMapNode,
) -> Result<PhysicalMapNodeId, N::Error> {
    let id = node.identify(identity)?;
    if let Some(existing) = nodes.node(id)? {
        if *existing != node {
            return Err(
                PhysicalModelError::InvalidMap("physical map-node identity collision").into(),
            );
        }
        return Ok(id);
    }
    nodes.put(id, node)?;
    Ok(id)
}

impl<N: PhysicalMapNodes + ?Sized> PhysicalMapNodes for &N {
    type Error = N::Error;
    fn note_read_failure(&self) {
        (**self).note_read_failure();
    }
    fn node(&self, id: PhysicalMapNodeId) -> Result<Option<Cow<'_, PhysicalMapNode>>, Self::Error> {
        (**self).node(id)
    }
}

impl<N: PhysicalMapNodes + ?Sized> PhysicalMapNodes for &mut N {
    type Error = N::Error;
    fn note_read_failure(&self) {
        (**self).note_read_failure();
    }
    fn node(&self, id: PhysicalMapNodeId) -> Result<Option<Cow<'_, PhysicalMapNode>>, Self::Error> {
        (**self).node(id)
    }
}

impl<N: PhysicalMapMutNodes + ?Sized> PhysicalMapMutNodes for &mut N {
    fn put(&mut self, id: PhysicalMapNodeId, node: PhysicalMapNode) -> Result<(), Self::Error> {
        (**self).put(id, node)
    }
}
