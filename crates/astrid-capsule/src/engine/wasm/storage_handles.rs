//! Handle bindings within one storage-backed VFS. Directory and file tables are distinct.

use std::collections::{HashMap, hash_map::Entry};
use vstd::prelude::*;

verus! {

broadcast use vstd::std_specs::hash::group_hash_axioms;

pub(super) struct HandleTable<V> {
    entries: HashMap<String, V>,
}

impl<V> HandleTable<V> {
    pub(super) closed spec fn valid(&self) -> bool { vstd::std_specs::hash::hash_map_inv(&self.entries) }

    pub(super) closed spec fn contents(&self) -> Map<String, V> { self.entries@ }

    pub(super) closed spec fn has(&self, text: Seq<char>) -> bool {
        exists|k: String| #[trigger] self.entries@.contains_key(k) && k@ == text
    }

    pub(super) fn new() -> (table: Self)
        ensures table.valid(), table.contents() == Map::<String, V>::empty(),
    {
        Self { entries: HashMap::new() }
    }

    pub(super) fn with_root(key: String, root: V) -> (table: Self)
        ensures table.valid(), table.contents() == Map::<String, V>::empty().insert(key, root),
    {
        let mut table = Self::new();
        table.register(key, root);
        table
    }

    /// Bind the caller-supplied directory handle, preserving the VFS rebinding semantics.
    pub(super) fn bind_directory(&mut self, key: String, directory: V)
        requires old(self).valid(),
        ensures final(self).valid(), final(self).binds(key@, directory),
            if old(self).has(key@) {
                old(self).updated(key@, directory, final(self))
            } else { final(self).contents() == old(self).contents().insert(key, directory) },
    {
        let ghost before = self.contents();
        self.entries.insert(key, directory);
        proof {
            if old(self).has(key@) {
                assert(old(self).updated(key@, directory, self));
                let k = choose|k: String| #[trigger] before.contains_key(k)
                    && k@ == key@ && self.contents() == before.insert(k, directory);
                assert(self.entries@.contains_key(k));
            } else {
                assert(self.entries@.contains_key(key));
            }
        }
    }

    pub(super) closed spec fn updated(&self, text: Seq<char>, value: V, next: &Self) -> bool {
        exists|k: String| #[trigger] self.entries@.contains_key(k)
            && k@ == text && next.contents() == self.contents().insert(k, value)
    }

    pub(super) fn register(&mut self, key: String, value: V) -> (fresh: bool)
        requires old(self).valid(),
        ensures final(self).valid(),
            fresh == !old(self).has(key@),
            final(self).contents() == if fresh {
                old(self).contents().insert(key, value)
            } else { old(self).contents() },
    {
        match self.entries.entry(key) {
            Entry::Occupied(_) => false,
            Entry::Vacant(entry) => {
                entry.insert(value);
                true
            },
        }
    }

    pub(super) closed spec fn binds(&self, text: Seq<char>, value: V) -> bool {
        exists|k: String| #[trigger] self.entries@.contains_key(k)
            && k@ == text && self.entries@[k] == value
    }

    /// Any two lookups of the same handle text in one table select the same entry.
    pub(super) proof fn unique_binding(&self, name: Seq<char>, first: V, second: V)
        requires self.valid(), self.binds(name, first), self.binds(name, second),
        ensures first == second,
    {
        let a = choose|k: String| #[trigger] self.entries@.contains_key(k)
            && k@ == name && self.entries@[k] == first;
        let b = choose|k: String| #[trigger] self.entries@.contains_key(k)
            && k@ == name && self.entries@[k] == second;
        assert(a == b);
    }

    pub(super) fn lookup(&self, key: &str) -> (value: Option<&V>)
        requires self.valid(),
        ensures match value {
            Some(v) => self.binds(key@, *v),
            None => !self.has(key@),
        },
    {
        self.entries.get(key)
    }

    pub(super) closed spec fn removed(&self, text: Seq<char>, value: V, next: &Self) -> bool {
        exists|k: String| #[trigger] self.entries@.contains_key(k)
            && k@ == text && self.entries@[k] == value
            && next.contents() == self.contents().remove(k)
    }

    pub(super) fn retire(&mut self, key: &str) -> (value: Option<V>)
        requires old(self).valid(),
        ensures final(self).valid(), !final(self).has(key@),
            match value {
                Some(v) => old(self).removed(key@, v, final(self)),
                None => !old(self).has(key@) && final(self).contents() == old(self).contents(),
            },
    {
        self.entries.remove(key)
    }
}

}
