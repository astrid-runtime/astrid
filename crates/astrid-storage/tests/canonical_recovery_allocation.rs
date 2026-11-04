//! Canonical validation, rebuild and proven reads avoid redundant allocations.
#![cfg(not(target_family = "wasm"))]

use astrid_storage::storage_model::{
    CanonicalPhysicalMap, ObjectId, ObjectRecord, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::Arc;

thread_local! {
    // Account only allocations inside the invoking validation/rebuild call.
    // Input ownership outlives that call; the harness and other threads are
    // excluded. Additions measured under rebuild must be allocated inside the
    // window so their later drop cannot underflow a zero live counter.
    static ACCOUNTING: Cell<Option<(usize, usize, usize)>> = const { Cell::new(None) };
    static INVALID_ACCOUNTING: Cell<bool> = const { Cell::new(false) };
}

struct Allocator;

fn account(size: usize, allocated: bool) {
    let _ = ACCOUNTING.try_with(|state| {
        if let Some((live, peak, allocations)) = state.get() {
            let next = if allocated {
                live.checked_add(size)
            } else {
                live.checked_sub(size)
            };
            let Some(live) = next else {
                // Allocators cannot unwind. Mark an invalid measurement and
                // reject it outside the allocator after validation returns.
                state.set(None);
                INVALID_ACCOUNTING.set(true);
                return;
            };
            let Some(allocations) = allocations.checked_add(usize::from(allocated)) else {
                state.set(None);
                INVALID_ACCOUNTING.set(true);
                return;
            };
            state.set(Some((live, peak.max(live), allocations)));
        }
    });
}

// SAFETY: every allocation and deallocation forwards the unchanged layout to
// System. Accounting uses allocation-free thread-local cells only.
#[allow(
    unsafe_code,
    reason = "Test-only peak allocation accounting forwards System unchanged."
)]
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forward the allocator contract and original layout.
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            account(layout.size(), true);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        account(layout.size(), false);
        // SAFETY: all allocations originate from System with this layout.
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: Allocator = Allocator;

struct Identity;
impl PhysicalIdentity for Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key(context);
        hash.update(material);
        *hash.finalize().as_bytes()
    }
}

struct ResetAccounting;
impl Drop for ResetAccounting {
    fn drop(&mut self) {
        ACCOUNTING.set(None);
    }
}

const LARGE_COUNT: usize = 128;
const LARGE_VALUE_BYTES: usize = 64 * 1024;

fn large_entries() -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (0..LARGE_COUNT)
        .map(|index| {
            (
                PhysicalMapKey::new(*blake3::hash(&index.to_le_bytes()).as_bytes()),
                vec![0x5a; LARGE_VALUE_BYTES],
            )
        })
        .collect()
}

fn measure_peak<R>(body: impl FnOnce() -> R) -> (R, usize) {
    INVALID_ACCOUNTING.set(false);
    ACCOUNTING.set(Some((0, 0, 0)));
    let reset = ResetAccounting;
    let result = body();
    let accounting = ACCOUNTING.get();
    let invalid = INVALID_ACCOUNTING.get();
    drop(reset);
    assert!(
        !invalid,
        "temporary allocation accounting overflowed or underflowed"
    );
    let (_, peak, _) = accounting.expect("accounting active");
    (result, peak)
}

fn validate_without_retaining_input_payloads(dense: bool) {
    let entries = large_entries();
    let map = if dense {
        CanonicalPhysicalMap::build_dense(&Identity, PhysicalMapDomain::Placement, entries)
    } else {
        CanonicalPhysicalMap::build(&Identity, PhysicalMapDomain::Placement, entries)
    }
    .unwrap();
    let (result, peak) = measure_peak(|| {
        CanonicalPhysicalMap::validate_root(
            &Identity,
            PhysicalMapDomain::Placement,
            map.root(),
            map.nodes(),
        )
    });
    assert_eq!(result.unwrap(), u64::try_from(LARGE_COUNT).unwrap());
    // Room for transient node encoding, traversal sets and allocator rounding;
    // a second full input payload set alone exceeds this bound eightfold.
    assert!(
        peak < LARGE_COUNT * LARGE_VALUE_BYTES / 8,
        "validation retained {peak} temporary bytes"
    );
}

fn rebuild_without_cloning_existing_payloads(dense: bool) {
    // Existing map + its large payloads are allocated before accounting so the
    // measured window only sees rebuild scratch and the single new addition.
    let mut map = if dense {
        CanonicalPhysicalMap::build_dense(&Identity, PhysicalMapDomain::Placement, large_entries())
    } else {
        CanonicalPhysicalMap::build(&Identity, PhysicalMapDomain::Placement, large_entries())
    }
    .unwrap();
    let before_root = map.root();
    let before_count = map.entry_count();
    let before_nodes = map.nodes().len();

    let (inserted, peak) = measure_peak(|| {
        // Allocate the addition inside the window. Creating it beforehand and
        // dropping/moving it here would underflow the live counter.
        let addition_key =
            PhysicalMapKey::new(*blake3::hash(&LARGE_COUNT.to_le_bytes()).as_bytes());
        let additions = vec![(addition_key, vec![0xa5; LARGE_VALUE_BYTES])];
        map.rebuild_with_entries(&Identity, additions)
    });
    assert_eq!(inserted.unwrap(), 1);
    assert_ne!(map.root(), before_root);
    assert_eq!(map.entry_count(), before_count.strict_add(1));
    assert!(map.nodes().len() > before_nodes);
    // Leaf encode scratch + a small new-path node set stay well under one
    // eighth of the pre-existing payload mass. The old rebuild cloned every
    // existing 64 KiB leaf into an owned entries map and clearly exceeds it.
    assert!(
        peak < LARGE_COUNT * LARGE_VALUE_BYTES / 8,
        "rebuild retained {peak} temporary bytes"
    );
}

#[test]
fn legacy_canonical_validation_borrows_the_complete_input_payload_set() {
    validate_without_retaining_input_payloads(false);
}

#[test]
fn dense_canonical_validation_borrows_the_complete_input_payload_set() {
    validate_without_retaining_input_payloads(true);
}

#[test]
fn legacy_canonical_rebuild_borrows_existing_payloads() {
    rebuild_without_cloning_existing_payloads(false);
}

#[test]
fn dense_canonical_rebuild_borrows_existing_payloads() {
    rebuild_without_cloning_existing_payloads(true);
}

struct ResidentContent(BTreeMap<ObjectId, Arc<ObjectRecord>>);

impl astrid_storage::content_dag::ContentSource for ResidentContent {
    type Error = std::convert::Infallible;

    fn load_content_object(&self, id: ObjectId) -> Result<Option<ObjectRecord>, Self::Error> {
        Ok(self.0.get(&id).map(|record| record.as_ref().clone()))
    }

    fn load_shared_content_object(
        &self,
        id: ObjectId,
    ) -> Result<Option<Arc<ObjectRecord>>, Self::Error> {
        Ok(self.0.get(&id).cloned())
    }

    fn load_shared_content_objects(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<Option<Arc<ObjectRecord>>>, Self::Error> {
        Ok(ids.iter().map(|id| self.0.get(id).cloned()).collect())
    }
}

#[test]
fn verified_content_reads_allocate_per_tree_node_instead_of_per_chunk() {
    use astrid_storage::content_dag::{
        CHUNK_TREE_FANOUT, ChunkingProfile, build_content, read_verified_content,
    };
    use astrid_storage::principal_state::Blake3ObjectIdentityV1;
    use astrid_storage::storage_model::ObjectKind;

    let mut random = 0x12ab_56cd_90ef_3412_u64;
    let bytes: Vec<_> = (0..16 * 1024 * 1024)
        .map(|_| {
            random ^= random << 13;
            random ^= random >> 7;
            random ^= random << 17;
            random.to_le_bytes()[0]
        })
        .collect();
    let built = build_content(&Blake3ObjectIdentityV1, ChunkingProfile::ASTRID_V1, &bytes).unwrap();
    assert!(built.descriptor().chunk_count() > u64::try_from(CHUNK_TREE_FANOUT).unwrap());
    let verified = built.verified_content();
    let tree_nodes = built
        .records()
        .iter()
        .filter(|(_, record)| record.kind() == ObjectKind::ChunkTree)
        .count();
    let source = ResidentContent(
        built
            .into_records()
            .into_iter()
            .map(|(id, record)| (id, Arc::new(record)))
            .collect(),
    );

    INVALID_ACCOUNTING.set(false);
    ACCOUNTING.set(Some((0, 0, 0)));
    let reset = ResetAccounting;
    let result = read_verified_content(&source, verified);
    let accounting = ACCOUNTING.get();
    let invalid = INVALID_ACCOUNTING.get();
    drop(reset);
    assert!(!invalid, "verified-read allocation accounting was invalid");
    assert_eq!(result.unwrap(), bytes);
    let (_, _, allocations) = accounting.unwrap();
    // One output allocation plus decoding and batch vectors per tree node.
    // Geometric selection growth is bounded by log2(fanout); spare slots cover
    // fixed traversal bookkeeping, not a path allocation for every chunk.
    let per_node = usize::try_from(CHUNK_TREE_FANOUT.ilog2()).unwrap() + 6;
    let budget = 8 + per_node * tree_nodes;
    assert!(
        allocations <= budget,
        "verified read allocated {allocations} times for {tree_nodes} tree nodes (budget {budget})"
    );
}
