//! An immutable overlay snapshot shares its exact root with every reader.
use super::traversal::Node;
use std::sync::Arc;
use vstd::prelude::*;

verus! {
#[derive(Debug,Default)]
pub(crate) struct OverlayMap {
    pub(super) root:Option<Arc<Node>>,
}

impl OverlayMap {
    pub(crate) fn snapshot(&self) -> (out:Self)
        ensures out == *self,
    {
        let root = match &self.root {Some(n) => Some(Arc::clone(n)),None => None};
        Self {root}
    }
}

impl Clone for OverlayMap {
    fn clone(&self) -> Self {self.snapshot()}
}
}
