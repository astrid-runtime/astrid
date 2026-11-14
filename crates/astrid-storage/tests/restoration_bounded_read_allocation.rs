//! Public pack/reopen restoration must not retain a full asset-sized `Vec`.
//!
//! Separate integration binary: owns its `#[global_allocator]` and must not be
//! folded into the shared unit-test harness.
//!
#![cfg(not(target_family = "wasm"))]

use astrid_core::dirs::AstridHome;
use astrid_storage::{ContentName, KvQuotaResolver, StateOwner, open_runtime_principal_store};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

thread_local! {
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

struct ResetAccounting;
impl Drop for ResetAccounting {
    fn drop(&mut self) {
        ACCOUNTING.set(None);
    }
}

const FILE_BYTES: u64 = 64 * 1024 * 1024;
/// Full-file restore `Vec` alone is 64 mebibytes. Bounded profile windows + `DAG`
/// scratch must stay under a quarter of the asset; a retained body fails.
const PEAK_BUDGET_BYTES: usize = 16 * 1024 * 1024;

fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
    Arc::new(|_: &StateOwner| Ok(None))
}

fn fixture_home() -> (tempfile::TempDir, AstridHome) {
    // Match runtime_tree lifecycle fixtures: TempDir owns the parent only so
    // production can birth a private home root.
    #[cfg(windows)]
    let root = tempfile::Builder::new()
        .prefix("astrid-bounded-restore-")
        .tempdir_in(directories::BaseDirs::new().unwrap().data_local_dir())
        .unwrap();
    #[cfg(not(windows))]
    let root = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(root.path().join("home"));
    home.ensure().unwrap();
    (root, home)
}

fn write_repeating_file(path: &Path, length: u64) {
    let mut file = File::create(path).unwrap();
    let pattern = [0x5a_u8; 8192];
    let mut remaining = length;
    while remaining > 0 {
        let count = usize::try_from(remaining.min(pattern.len() as u64)).unwrap();
        file.write_all(&pattern[..count]).unwrap();
        remaining = remaining.strict_sub(count as u64);
    }
    file.sync_all().unwrap();
}

fn file_digest(path: &Path) -> blake3::Hash {
    let mut file = File::open(path).unwrap();
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            return hasher.finalize();
        }
        hasher.update(&buffer[..count]);
    }
}

#[tokio::test]
async fn public_pack_reopen_keeps_large_restore_peak_under_asset_budget() {
    let (_root, home) = fixture_home();

    // Fixture construction stays outside the measured window. Stream the asset
    // through put_streaming so a process-wide 64 MiB Vec never dominates setup,
    // then publish+pack to the volume-only stopped shape used by restore.
    let scratch = tempfile::NamedTempFile::new().unwrap();
    write_repeating_file(scratch.path(), FILE_BYTES);
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    store
        .content()
        .put_streaming(
            &StateOwner::System,
            &ContentName::new("large-asset.bin").unwrap(),
            File::open(scratch.path()).unwrap(),
        )
        .unwrap();
    store
        .content()
        .put(
            &StateOwner::System,
            &ContentName::new("config.toml").unwrap(),
            b"# bounded-restore fixture\n",
        )
        .unwrap();
    store.publish_runtime_projection(&home).unwrap();
    store.pack_and_retire_runtime_projection(&home).unwrap();
    assert_eq!(fs::read_dir(home.root()).unwrap().count(), 1);
    drop(store);

    let expected_digest = file_digest(scratch.path());
    for phase in ["volume-only restore", "unchanged projection reopen"] {
        INVALID_ACCOUNTING.set(false);
        ACCOUNTING.set(Some((0, 0, 0)));
        let reset = ResetAccounting;
        let restored = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .expect("reopen must restore packed projection");
        let accounting = ACCOUNTING.get();
        let invalid = INVALID_ACCOUNTING.get();
        drop(reset);
        assert!(
            !invalid,
            "{phase}: allocation accounting overflowed or underflowed"
        );
        let (_, peak, _) = accounting.expect("accounting active");
        eprintln!("{phase}: peak_allocated_bytes={peak}, budget={PEAK_BUDGET_BYTES}");
        assert!(
            peak < PEAK_BUDGET_BYTES,
            "{phase}: peak {peak} retained an asset-sized body; budget {PEAK_BUDGET_BYTES}"
        );
        let restored_path = home.root().join("large-asset.bin");
        assert_eq!(fs::metadata(&restored_path).unwrap().len(), FILE_BYTES);
        assert_eq!(file_digest(&restored_path), expected_digest);
        assert_eq!(
            restored
                .content()
                .read_range(
                    &StateOwner::System,
                    &ContentName::new("large-asset.bin").unwrap(),
                    FILE_BYTES.strict_sub(32),
                    32,
                )
                .unwrap()
                .unwrap(),
            vec![0x5a_u8; 32]
        );
        drop(restored);
    }
}
