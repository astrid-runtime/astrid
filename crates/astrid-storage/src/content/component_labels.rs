//! Owner-state component labels in the persisted content schema.
use vstd::prelude::*;

verus! {
pub(crate) const CONTENT: &[u8;7] = b"content";
pub(crate) const KV: &[u8;2] = b"kv";
pub(crate) const WORKSPACE: &[u8;10] = b"workspace/";
}
