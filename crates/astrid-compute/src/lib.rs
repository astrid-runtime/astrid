//! Principal-scoped parallel execution of capsule-authored core-Wasm workers.
//!
//! This crate is the native mechanism behind the proposed
//! `astrid:compute@1.0.0` control-plane contract. It deliberately knows no
//! Linux, tensor, rendering, compiler, inference, or game semantics. A caller
//! supplies a validated worker module; Astrid supplies shared memory, worker
//! ownership, scheduling, fuel, cancellation, and aggregate admission.
//!
//! The only `unsafe` code in this crate converts Wasmtime's
//! `SharedMemory::data()` `UnsafeCell<u8>` elements into aligned atomic views,
//! exactly as required by Wasmtime's API. It is isolated in small helper
//! functions. The other unsafe operation creates a read-only file mapping in
//! one documented helper. All public shared-region and asset access is safe.

#![deny(unreachable_pub)]
#![deny(clippy::all)]

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use astrid_capsule_types::{FuelLedger, FuelRateLimiter};
use astrid_core::principal::PrincipalId;
use thiserror::Error;
use wasmtime::{
    Caller, Config, Engine, ExternType, Linker, MemoryType, Module, SharedMemory, Store,
    UpdateDeadline, ValType,
};

/// ABI version returned by `astrid_compute_abi_version`.
pub const COMPUTE_ABI_VERSION: i32 = 1;
/// Bytes at the start of shared memory reserved for Astrid Compute ABI 1.
pub const ABI_HEADER_BYTES: u64 = 64;
const ABI_HEADER_LEN: usize = 64;
/// Magic stored at byte zero (`ASC1`).
pub const ABI_MAGIC: u32 = 0x4153_4331;
/// WebAssembly's default linear-memory page size.
pub const WASM_PAGE_BYTES: u64 = 65_536;
/// Wasmtime allowance used when policy deliberately leaves jobs uncapped.
/// Epoch interruption still provides forced cancellation and shutdown.
pub const UNBOUNDED_JOB_FUEL: u64 = u64::MAX;
/// Bounded queue per worker. This is backpressure, not a thread ceiling.
const WORKER_QUEUE_CAPACITY: usize = 64;
/// Epoch cadence bounds forced cancellation latency for non-cooperative code.
const EPOCH_INTERVAL: Duration = Duration::from_millis(25);
/// Signed workers may initialize large passive data segments (for example a
/// kernel image) before their first job. Startup has no hidden fuel ceiling,
/// but must still be interruptible if a malformed start function never exits.
const WORKER_START_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum immutable files attached to one signed worker.
pub const MAX_WORKER_ASSETS: usize = 16;
/// Maximum bytes copied from an immutable asset by one host call.
pub const MAX_ASSET_READ_BYTES: u64 = 64 * 1024;
const ASSET_READ_BASE_FUEL: u64 = 64;
const ASSET_READ_FUEL_PER_BYTE: u64 = 1;
/// `asset_read` completed successfully.
pub const ASSET_OK: i32 = 0;
/// `asset_size` or `asset_read` received an unknown asset index.
pub const ASSET_ERR_INDEX: i32 = -1;
/// `asset_read` received a negative, overflowing, or out-of-bounds range.
pub const ASSET_ERR_RANGE: i32 = -2;
/// `asset_read` exceeded [`MAX_ASSET_READ_BYTES`].
pub const ASSET_ERR_LENGTH: i32 = -3;
/// `asset_read` could not charge its fuel cost.
pub const ASSET_ERR_FUEL: i32 = -4;
/// `asset_read` was invoked outside an admitted worker job.
pub const ASSET_ERR_PHASE: i32 = -5;

/// Typed failure returned by the engine-agnostic compute mechanism.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum ComputeError {
    /// The request contains an invalid count, range, or memory shape.
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Worker bytes, hash, imports, exports, or ABI do not conform.
    #[error("invalid worker: {0}")]
    WorkerInvalid(String),
    /// Aggregate principal admission policy denied the request.
    #[error("compute quota exceeded")]
    Quota,
    /// A specifically addressed worker or bounded queue is busy.
    #[error("compute worker is busy")]
    Busy,
    /// Work was cancelled before successful completion.
    #[error("compute work was cancelled")]
    Cancelled,
    /// Worker compilation, instantiation, execution, fuel, or interrupt failed.
    #[error("compute worker failed: {0}")]
    WorkerFailed(String),
    /// The group is closed and accepts no more work.
    #[error("compute group is closed")]
    Closed,
}

/// Requested execution behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    /// One worker, FIFO queue. Useful for replay and differential testing.
    Deterministic,
    /// Resolve and schedule multiple workers when admitted.
    Parallel,
}

/// Requested worker-count policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parallelism {
    /// Host useful parallelism, subject to effective aggregate policy.
    Auto,
    /// Exactly this many workers or fail.
    Exact(u32),
    /// At least one and no more than this many workers.
    AtMost(u32),
}

/// Operator/runtime policy passed to the compute mechanism.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComputeLimits {
    /// Aggregate workers per principal. `None` means no Astrid policy cap.
    pub max_workers_per_principal: Option<u32>,
    /// Aggregate shared bytes per principal. `None` means no compute-specific cap.
    pub max_memory_bytes_per_principal: Option<u64>,
    /// Maximum fuel for one job. `None` means no Astrid policy cap.
    pub max_job_fuel: Option<u64>,
}

/// Process-wide compute capacity contributed by the host/operator.
///
/// This is distinct from [`ComputeLimits`]: one principal cannot consume more
/// than its own intersected policy, and all principals together cannot reserve
/// more than this host pool. `None` preserves the legacy uncapped constructor
/// behaviour for embedders; the Astrid daemon always supplies detected limits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ComputeHostLimits {
    /// Workers reserved across every principal and compute group.
    pub max_workers: Option<u32>,
    /// Shared-memory bytes reserved across every principal and compute group.
    pub max_memory_bytes: Option<u64>,
}

/// Effective policy contributed by the verified invoking principal.
///
/// The runtime intersects this with its operator/host limits. `None` delegates
/// that dimension to the outer runtime; it never widens an operator ceiling.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrincipalComputeLimits {
    /// Aggregate workers this principal may reserve across compute groups.
    pub max_workers: Option<u32>,
    /// Aggregate shared memory this principal may reserve across compute groups.
    pub max_memory_bytes: Option<u64>,
    /// Per-job fuel ceiling contributed by the principal policy.
    pub max_job_fuel: Option<u64>,
    /// Rolling CPU-rate ceiling. `None` means the principal is policy-exempt.
    pub max_fuel_per_sec: Option<u64>,
}

impl ComputeLimits {
    fn intersect(self, principal: PrincipalComputeLimits) -> Self {
        Self {
            max_workers_per_principal: min_option(
                self.max_workers_per_principal,
                principal.max_workers,
            ),
            max_memory_bytes_per_principal: min_option(
                self.max_memory_bytes_per_principal,
                principal.max_memory_bytes,
            ),
            max_job_fuel: min_option(self.max_job_fuel, principal.max_job_fuel),
        }
    }
}

fn min_option<T: Ord + Copy>(left: Option<T>, right: Option<T>) -> Option<T> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

/// Group creation request after WIT/SDK conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupRequest {
    /// Deterministic or parallel scheduling.
    pub mode: ExecutionMode,
    /// Requested worker count.
    pub parallelism: Parallelism,
    /// Initial 64-KiB shared-memory pages.
    pub initial_memory_pages: u32,
    /// Maximum shared-memory pages. Zero asks the host to admit the largest
    /// value allowed by the signed worker and currently available policy.
    pub maximum_memory_pages: u32,
}

/// Capsule-defined range and tag passed to one worker invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkDescriptor {
    /// Byte offset in the shared region. Must not overlap the ABI header.
    pub offset: u64,
    /// Byte length in the shared region.
    pub length: u64,
    /// Opaque capsule-defined tag.
    pub tag: u64,
    /// Optional stable worker affinity.
    pub worker_index: Option<u32>,
    /// Optional fuel override.
    pub fuel: Option<u64>,
}

/// Lifecycle state of one submitted job.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    /// Accepted but not yet executing.
    Queued,
    /// Executing in a worker Store.
    Running,
    /// Worker returned an application status.
    Completed,
    /// Cancelled by the job, group, principal, capsule, or runtime.
    Cancelled,
    /// Worker trapped, exhausted fuel, or failed.
    Failed,
}

/// Terminal worker result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobResult {
    /// Terminal state (`Completed` on the successful result path).
    pub state: JobState,
    /// Worker index that ran the descriptor.
    pub worker_index: u32,
    /// Opaque status returned by `astrid_compute_run`.
    pub worker_status: i32,
    /// Fuel removed from the Store allowance.
    pub fuel_consumed: u64,
    /// Host-monotonic elapsed time.
    pub elapsed: Duration,
}

/// Current and cumulative counters for one group.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct GroupAccounting {
    /// Workers reserved for the principal.
    pub workers_reserved: u32,
    /// Current shared bytes.
    pub memory_bytes_current: u64,
    /// Peak shared bytes.
    pub memory_bytes_peak: u64,
    /// Jobs accepted.
    pub jobs_submitted: u64,
    /// Jobs returning an application status.
    pub jobs_completed: u64,
    /// Jobs cancelled.
    pub jobs_cancelled: u64,
    /// Jobs failing in the worker runtime.
    pub jobs_failed: u64,
    /// Cumulative consumed fuel.
    pub fuel_consumed: u64,
}

/// Current aggregate reservation for one principal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PrincipalComputeUsage {
    /// Workers held by all groups/capsules sharing this ledger.
    pub workers: u64,
    /// Maximum shared bytes reserved by all groups/capsules sharing this ledger.
    pub memory_bytes: u64,
}

/// Kernel-owned aggregate reservation ledger.
///
/// One instance must be shared across every capsule runtime in a kernel. A
/// group holds an RAII reservation, so every failure and drop path rolls back.
#[derive(Debug, Clone, Default)]
pub struct ComputeLedger {
    inner: Arc<Mutex<ComputeLedgerState>>,
}

#[derive(Debug, Default)]
struct ComputeLedgerState {
    principals: HashMap<PrincipalId, PrincipalComputeUsage>,
    total: PrincipalComputeUsage,
}

impl ComputeLedger {
    /// Return a principal's live reservation snapshot.
    #[must_use]
    pub fn usage(&self, principal: &PrincipalId) -> PrincipalComputeUsage {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .principals
            .get(principal)
            .copied()
            .unwrap_or_default()
    }

    /// Return aggregate process-wide reservations.
    #[must_use]
    pub fn total_usage(&self) -> PrincipalComputeUsage {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .total
    }

    fn remaining_workers(
        &self,
        principal: &PrincipalId,
        principal_limit: Option<u32>,
        host_limit: Option<u32>,
    ) -> Option<u64> {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let principal_used = state
            .principals
            .get(principal)
            .copied()
            .unwrap_or_default()
            .workers;
        min_option(
            principal_limit.map(|max| u64::from(max).saturating_sub(principal_used)),
            host_limit.map(|max| u64::from(max).saturating_sub(state.total.workers)),
        )
    }

    fn remaining_memory(
        &self,
        principal: &PrincipalId,
        principal_limit: Option<u64>,
        host_limit: Option<u64>,
    ) -> Option<u64> {
        let state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let principal_used = state
            .principals
            .get(principal)
            .copied()
            .unwrap_or_default()
            .memory_bytes;
        min_option(
            principal_limit.map(|max| max.saturating_sub(principal_used)),
            host_limit.map(|max| max.saturating_sub(state.total.memory_bytes)),
        )
    }

    fn reserve(
        &self,
        principal: PrincipalId,
        workers: u32,
        memory_bytes: u64,
        limits: ComputeLimits,
        host_limits: ComputeHostLimits,
    ) -> Result<ComputeReservation, ComputeError> {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let usage = state
            .principals
            .get(&principal)
            .copied()
            .unwrap_or_default();
        let next_workers = usage.workers.saturating_add(u64::from(workers));
        let next_memory = usage.memory_bytes.saturating_add(memory_bytes);
        let next_total_workers = state.total.workers.saturating_add(u64::from(workers));
        let next_total_memory = state.total.memory_bytes.saturating_add(memory_bytes);
        if limits
            .max_workers_per_principal
            .is_some_and(|limit| next_workers > u64::from(limit))
            || limits
                .max_memory_bytes_per_principal
                .is_some_and(|limit| next_memory > limit)
            || host_limits
                .max_workers
                .is_some_and(|limit| next_total_workers > u64::from(limit))
            || host_limits
                .max_memory_bytes
                .is_some_and(|limit| next_total_memory > limit)
        {
            return Err(ComputeError::Quota);
        }
        let usage = state.principals.entry(principal.clone()).or_default();
        usage.workers = next_workers;
        usage.memory_bytes = next_memory;
        state.total.workers = next_total_workers;
        state.total.memory_bytes = next_total_memory;
        drop(state);
        Ok(ComputeReservation {
            ledger: self.clone(),
            principal,
            workers: u64::from(workers),
            memory_bytes,
            released: AtomicBool::new(false),
        })
    }

    fn release(&self, principal: &PrincipalId, workers: u64, memory_bytes: u64) {
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(usage) = state.principals.get_mut(principal) {
            usage.workers = usage.workers.saturating_sub(workers);
            usage.memory_bytes = usage.memory_bytes.saturating_sub(memory_bytes);
            if usage.workers == 0 && usage.memory_bytes == 0 {
                state.principals.remove(principal);
            }
        }
        state.total.workers = state.total.workers.saturating_sub(workers);
        state.total.memory_bytes = state.total.memory_bytes.saturating_sub(memory_bytes);
    }
}

#[derive(Debug)]
struct ComputeReservation {
    ledger: ComputeLedger,
    principal: PrincipalId,
    workers: u64,
    memory_bytes: u64,
    released: AtomicBool,
}

impl Drop for ComputeReservation {
    fn drop(&mut self) {
        if !self.released.swap(true, Ordering::AcqRel) {
            self.ledger
                .release(&self.principal, self.workers, self.memory_bytes);
        }
    }
}

/// Signed capsule worker artifact before compilation.
#[derive(Debug, Clone)]
pub struct WorkerArtifact {
    id: String,
    bytes: Arc<[u8]>,
    digest: String,
    assets: Arc<[WorkerAsset]>,
}

/// Hash-pinned immutable file attached to one compute worker declaration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerAssetSpec {
    /// Stable worker-local identifier.
    pub id: String,
    /// Traversal-free path beneath the installed capsule root.
    pub relative_path: PathBuf,
    /// Exact BLAKE3 identity.
    pub expected_hash: String,
}

#[derive(Debug, Clone)]
struct WorkerAsset {
    id: String,
    bytes: Arc<memmap2::Mmap>,
    digest: String,
}

impl WorkerArtifact {
    /// Validate and read a worker beneath the installed capsule root.
    ///
    /// `expected_hash` must use `blake3:<lowercase hex>` form. Every path
    /// component is rejected if it is a symlink; lexical traversal, absolute
    /// paths, and canonical escape are rejected before bytes are accepted.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::WorkerInvalid`] for an unsafe path, unreadable
    /// file, missing component, or hash mismatch.
    pub fn from_capsule_path(
        id: impl Into<String>,
        capsule_root: &Path,
        relative_path: &Path,
        expected_hash: &str,
    ) -> Result<Self, ComputeError> {
        Self::from_capsule_path_with_assets(id, capsule_root, relative_path, expected_hash, &[])
    }

    /// Validate a worker and its private immutable assets beneath one capsule.
    ///
    /// Asset files are hash-verified from read-only mappings. Their pages are
    /// shared by every principal using this loaded artifact and remain outside
    /// worker linear memory until a bounded compute-ABI read copies bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::WorkerInvalid`] for an unsafe path, duplicate or
    /// malformed asset identity, non-regular file, empty asset, or hash drift.
    pub fn from_capsule_path_with_assets(
        id: impl Into<String>,
        capsule_root: &Path,
        relative_path: &Path,
        expected_hash: &str,
        assets: &[WorkerAssetSpec],
    ) -> Result<Self, ComputeError> {
        if relative_path.is_absolute()
            || relative_path.components().any(|part| {
                matches!(
                    part,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(ComputeError::WorkerInvalid(
                "worker path must be relative and traversal-free".to_owned(),
            ));
        }
        reject_symlink_components(capsule_root, relative_path)?;
        let root = capsule_root.canonicalize().map_err(|error| {
            ComputeError::WorkerInvalid(format!("canonicalize capsule root: {error}"))
        })?;
        let path = capsule_root.join(relative_path);
        let canonical = path.canonicalize().map_err(|error| {
            ComputeError::WorkerInvalid(format!("canonicalize worker path: {error}"))
        })?;
        if !canonical.starts_with(&root) {
            return Err(ComputeError::WorkerInvalid(
                "worker path escaped the capsule root".to_owned(),
            ));
        }
        let bytes = std::fs::read(&canonical)
            .map_err(|error| ComputeError::WorkerInvalid(format!("read worker: {error}")))?;
        let mut artifact = Self::from_bytes(id, bytes, expected_hash)?;
        if assets.len() > MAX_WORKER_ASSETS {
            return Err(ComputeError::WorkerInvalid(format!(
                "worker declares more than {MAX_WORKER_ASSETS} immutable assets"
            )));
        }
        let mut loaded = Vec::with_capacity(assets.len());
        let mut ids = std::collections::HashSet::with_capacity(assets.len());
        for asset in assets {
            if !valid_asset_id(&asset.id) {
                return Err(ComputeError::WorkerInvalid(format!(
                    "invalid worker asset id {:?}",
                    asset.id
                )));
            }
            if !ids.insert(asset.id.as_str()) {
                return Err(ComputeError::WorkerInvalid(format!(
                    "duplicate worker asset id {:?}",
                    asset.id
                )));
            }
            loaded.push(load_worker_asset(capsule_root, asset)?);
        }
        artifact.assets = loaded.into();
        Ok(artifact)
    }

    /// Build from bytes while enforcing the manifest hash.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::WorkerInvalid`] when `expected_hash` does not
    /// exactly match the BLAKE3 digest of `bytes`.
    pub fn from_bytes(
        id: impl Into<String>,
        bytes: impl Into<Vec<u8>>,
        expected_hash: &str,
    ) -> Result<Self, ComputeError> {
        let bytes = bytes.into();
        let actual = format!("blake3:{}", blake3::hash(&bytes).to_hex());
        if expected_hash != actual {
            return Err(ComputeError::WorkerInvalid(format!(
                "worker hash mismatch: expected {expected_hash}, got {actual}"
            )));
        }
        Ok(Self {
            id: id.into(),
            bytes: bytes.into(),
            digest: actual,
            assets: Arc::new([]),
        })
    }

    /// Artifact identifier declared in the capsule manifest.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Verified BLAKE3 digest.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Number of verified immutable assets attached to this worker.
    #[must_use]
    pub fn asset_count(&self) -> usize {
        self.assets.len()
    }

    /// Sum of the declared immutable asset byte lengths.
    #[must_use]
    pub fn asset_bytes(&self) -> u64 {
        self.assets.iter().fold(0_u64, |total, asset| {
            total.saturating_add(u64::try_from(asset.bytes.len()).unwrap_or(u64::MAX))
        })
    }

    /// Worker-local id of one immutable asset by manifest order.
    #[must_use]
    pub fn asset_id(&self, index: usize) -> Option<&str> {
        self.assets.get(index).map(|asset| asset.id.as_str())
    }

    /// Verified digest of one immutable asset by manifest order.
    #[must_use]
    pub fn asset_digest(&self, index: usize) -> Option<&str> {
        self.assets.get(index).map(|asset| asset.digest.as_str())
    }
}

fn valid_asset_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn load_worker_asset(root: &Path, spec: &WorkerAssetSpec) -> Result<WorkerAsset, ComputeError> {
    let relative = &spec.relative_path;
    if relative.is_absolute()
        || !relative.starts_with("assets")
        || relative.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(ComputeError::WorkerInvalid(format!(
            "worker asset {:?} must be a traversal-free path under assets/",
            spec.id
        )));
    }
    reject_symlink_components(root, relative)?;
    let canonical_root = root.canonicalize().map_err(|error| {
        ComputeError::WorkerInvalid(format!("canonicalize capsule root: {error}"))
    })?;
    let canonical = root.join(relative).canonicalize().map_err(|error| {
        ComputeError::WorkerInvalid(format!("canonicalize worker asset {:?}: {error}", spec.id))
    })?;
    if !canonical.starts_with(canonical_root) {
        return Err(ComputeError::WorkerInvalid(format!(
            "worker asset {:?} escaped the capsule root",
            spec.id
        )));
    }
    let file = std::fs::File::open(&canonical).map_err(|error| {
        ComputeError::WorkerInvalid(format!("open worker asset {:?}: {error}", spec.id))
    })?;
    let metadata = file.metadata().map_err(|error| {
        ComputeError::WorkerInvalid(format!("inspect worker asset {:?}: {error}", spec.id))
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > i64::MAX.unsigned_abs() {
        return Err(ComputeError::WorkerInvalid(format!(
            "worker asset {:?} must be a non-empty addressable regular file",
            spec.id
        )));
    }
    let bytes = map_read_only_asset(&file).map_err(|error| {
        ComputeError::WorkerInvalid(format!("map worker asset {:?}: {error}", spec.id))
    })?;
    let actual = format!("blake3:{}", blake3::hash(&bytes).to_hex());
    if spec.expected_hash != actual {
        return Err(ComputeError::WorkerInvalid(format!(
            "worker asset {:?} hash mismatch: expected {}, got {actual}",
            spec.id, spec.expected_hash
        )));
    }
    Ok(WorkerAsset {
        id: spec.id.clone(),
        bytes: Arc::new(bytes),
        digest: actual,
    })
}

#[allow(
    unsafe_code,
    reason = "immutable assets use an owned read-only mmap and are never exposed mutably"
)]
fn map_read_only_asset(file: &std::fs::File) -> std::io::Result<memmap2::Mmap> {
    // SAFETY: the mapping is read-only and remains owned for its entire use.
    // The installed capsule tree is outside capsule write authority; the
    // exact bytes are verified from this same mapping before it is accepted.
    unsafe { memmap2::MmapOptions::new().map(file) }
}

fn reject_symlink_components(root: &Path, relative: &Path) -> Result<(), ComputeError> {
    let mut current = PathBuf::from(root);
    for component in relative.components() {
        let Component::Normal(part) = component else {
            continue;
        };
        current.push(part);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            ComputeError::WorkerInvalid(format!("inspect worker path component: {error}"))
        })?;
        if metadata.file_type().is_symlink() {
            return Err(ComputeError::WorkerInvalid(
                "worker path may not contain symlinks".to_owned(),
            ));
        }
    }
    Ok(())
}

/// Native compute runtime. Cloneable and safe to share across capsule engines.
#[derive(Clone)]
pub struct ComputeRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    engine: Engine,
    ledger: ComputeLedger,
    fuel_ledger: FuelLedger,
    fuel_rate: FuelRateLimiter,
    limits: ComputeLimits,
    host_limits: ComputeHostLimits,
    worker_start_timeout: Duration,
    ticker_stop: Arc<AtomicBool>,
    ticker: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for ComputeRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputeRuntime")
            .field("limits", &self.inner.limits)
            .finish_non_exhaustive()
    }
}

impl ComputeRuntime {
    /// Construct a runtime over the kernel's shared principal ledger.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::WorkerFailed`] if Wasmtime cannot enable the
    /// required proposals or the epoch ticker thread cannot start.
    pub fn new(ledger: ComputeLedger, limits: ComputeLimits) -> Result<Self, ComputeError> {
        Self::new_accounted(
            ledger,
            limits,
            FuelLedger::default(),
            FuelRateLimiter::default(),
        )
    }

    /// Construct a runtime whose worker fuel is charged into the kernel's
    /// ordinary cross-capsule principal CPU account.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::WorkerFailed`] if Wasmtime cannot enable the
    /// required proposals or the epoch ticker thread cannot start.
    pub fn new_accounted(
        ledger: ComputeLedger,
        limits: ComputeLimits,
        fuel_ledger: FuelLedger,
        fuel_rate: FuelRateLimiter,
    ) -> Result<Self, ComputeError> {
        Self::new_accounted_with_host_limits(
            ledger,
            limits,
            ComputeHostLimits::default(),
            fuel_ledger,
            fuel_rate,
        )
    }

    /// Construct an accounted runtime with a process-wide admission pool.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::WorkerFailed`] if Wasmtime cannot enable the
    /// required proposals or the epoch ticker thread cannot start.
    pub fn new_accounted_with_host_limits(
        ledger: ComputeLedger,
        limits: ComputeLimits,
        host_limits: ComputeHostLimits,
        fuel_ledger: FuelLedger,
        fuel_rate: FuelRateLimiter,
    ) -> Result<Self, ComputeError> {
        Self::new_with_worker_start_timeout_and_accounting(
            ledger,
            limits,
            host_limits,
            fuel_ledger,
            fuel_rate,
            WORKER_START_TIMEOUT,
        )
    }

    #[cfg(test)]
    fn new_with_worker_start_timeout(
        ledger: ComputeLedger,
        limits: ComputeLimits,
        worker_start_timeout: Duration,
    ) -> Result<Self, ComputeError> {
        Self::new_with_worker_start_timeout_and_accounting(
            ledger,
            limits,
            ComputeHostLimits::default(),
            FuelLedger::default(),
            FuelRateLimiter::default(),
            worker_start_timeout,
        )
    }

    fn new_with_worker_start_timeout_and_accounting(
        ledger: ComputeLedger,
        limits: ComputeLimits,
        host_limits: ComputeHostLimits,
        fuel_ledger: FuelLedger,
        fuel_rate: FuelRateLimiter,
        worker_start_timeout: Duration,
    ) -> Result<Self, ComputeError> {
        let mut config = Config::new();
        config
            .wasm_threads(true)
            .shared_memory(true)
            .consume_fuel(true)
            .epoch_interruption(true);
        let engine = Engine::new(&config)
            .map_err(|error| ComputeError::WorkerFailed(format!("create engine: {error}")))?;
        let stop = Arc::new(AtomicBool::new(false));
        let ticker_engine = engine.clone();
        let ticker_stop = Arc::clone(&stop);
        let ticker = std::thread::Builder::new()
            .name("astrid-compute-epoch".to_owned())
            .spawn(move || {
                while !ticker_stop.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_INTERVAL);
                    ticker_engine.increment_epoch();
                }
            })
            .map_err(|error| ComputeError::WorkerFailed(format!("start epoch ticker: {error}")))?;
        Ok(Self {
            inner: Arc::new(RuntimeInner {
                engine,
                ledger,
                fuel_ledger,
                fuel_rate,
                limits,
                host_limits,
                worker_start_timeout,
                ticker_stop: stop,
                ticker: Mutex::new(Some(ticker)),
            }),
        })
    }

    /// Open and atomically admit a compute group.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the request is malformed, principal policy
    /// denies admission, the worker is invalid, memory allocation fails, or a
    /// worker thread cannot compile/instantiate the artifact.
    pub fn open_group(
        &self,
        principal: &PrincipalId,
        artifact: &WorkerArtifact,
        request: GroupRequest,
    ) -> Result<ComputeGroup, ComputeError> {
        self.open_group_with_limits(
            principal,
            artifact,
            request,
            PrincipalComputeLimits::default(),
        )
    }

    /// Open a group under the intersection of operator and principal policy.
    ///
    /// # Errors
    ///
    /// Returns a typed error when either policy denies admission or the worker
    /// cannot be compiled, instantiated, or started.
    pub fn open_group_with_limits(
        &self,
        principal: &PrincipalId,
        artifact: &WorkerArtifact,
        request: GroupRequest,
        principal_limits: PrincipalComputeLimits,
    ) -> Result<ComputeGroup, ComputeError> {
        validate_group_request(request)?;
        let effective_limits = self.inner.limits.intersect(principal_limits);
        let workers = self.resolve_workers(principal, request, effective_limits)?;
        let module = Module::from_binary(&self.inner.engine, &artifact.bytes)
            .map_err(|error| ComputeError::WorkerInvalid(format!("compile module: {error}")))?;
        let request = self.resolve_memory_request(principal, &module, request, effective_limits)?;
        let initial_bytes = u64::from(request.initial_memory_pages)
            .checked_mul(WASM_PAGE_BYTES)
            .ok_or_else(|| ComputeError::InvalidInput("initial memory overflow".to_owned()))?;
        // A worker can execute `memory.grow` directly. Reserve its declared
        // maximum up front so no guest instruction can bypass aggregate
        // principal admission between host calls.
        let maximum_bytes = u64::from(request.maximum_memory_pages)
            .checked_mul(WASM_PAGE_BYTES)
            .ok_or_else(|| ComputeError::InvalidInput("maximum memory overflow".to_owned()))?;
        let reservation = self.inner.ledger.reserve(
            principal.clone(),
            workers,
            maximum_bytes,
            effective_limits,
            self.inner.host_limits,
        )?;
        validate_worker_module(&module, request)?;
        let memory = SharedMemory::new(
            &self.inner.engine,
            MemoryType::shared(request.initial_memory_pages, request.maximum_memory_pages),
        )
        .map_err(|error| ComputeError::WorkerFailed(format!("allocate shared memory: {error}")))?;
        initialize_header(&memory, workers)?;

        let accounting = Arc::new(AccountingState::new(workers, initial_bytes));
        let closed = Arc::new(AtomicBool::new(false));
        let jobs = Arc::new(Mutex::new(Vec::<Weak<JobInner>>::new()));
        let mut slots = Vec::with_capacity(workers as usize);
        for index in 0..workers {
            match WorkerSlot::start(
                index,
                &self.inner.engine,
                &module,
                &memory,
                WorkerExecutionContext {
                    accounting: Arc::clone(&accounting),
                    closed: Arc::clone(&closed),
                    fuel_ledger: self.inner.fuel_ledger.clone(),
                    fuel_rate: self.inner.fuel_rate.clone(),
                    assets: Arc::clone(&artifact.assets),
                },
                self.inner.worker_start_timeout,
            ) {
                Ok(slot) => slots.push(slot),
                Err(error) => {
                    closed.store(true, Ordering::Release);
                    for slot in &slots {
                        slot.shutdown();
                    }
                    for slot in &slots {
                        slot.join();
                    }
                    return Err(error);
                },
            }
        }

        Ok(ComputeGroup {
            inner: Arc::new(GroupInner {
                principal: principal.clone(),
                artifact_id: artifact.id.clone(),
                artifact_digest: artifact.digest.clone(),
                mode: request.mode,
                maximum_memory_pages: request.maximum_memory_pages,
                memory,
                slots,
                next_worker: AtomicUsize::new(0),
                closed,
                jobs,
                accounting,
                _reservation: reservation,
                max_job_fuel: effective_limits.max_job_fuel,
                max_fuel_per_sec: principal_limits.max_fuel_per_sec,
                fuel_rate: self.inner.fuel_rate.clone(),
            }),
        })
    }

    fn resolve_workers(
        &self,
        principal: &PrincipalId,
        request: GroupRequest,
        limits: ComputeLimits,
    ) -> Result<u32, ComputeError> {
        if request.mode == ExecutionMode::Deterministic {
            if matches!(
                request.parallelism,
                Parallelism::Exact(0) | Parallelism::AtMost(0)
            ) {
                return Err(ComputeError::InvalidInput(
                    "parallelism must be greater than zero".to_owned(),
                ));
            }
            return self
                .inner
                .ledger
                .remaining_workers(
                    principal,
                    limits.max_workers_per_principal,
                    self.inner.host_limits.max_workers,
                )
                .is_none_or(|remaining| remaining >= 1)
                .then_some(1)
                .ok_or(ComputeError::Quota);
        }
        let useful = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
        let desired = match request.parallelism {
            Parallelism::Auto => u32::try_from(useful).unwrap_or(u32::MAX),
            Parallelism::Exact(0) | Parallelism::AtMost(0) => {
                return Err(ComputeError::InvalidInput(
                    "parallelism must be greater than zero".to_owned(),
                ));
            },
            Parallelism::Exact(value) | Parallelism::AtMost(value) => value,
        };
        let remaining = self.inner.ledger.remaining_workers(
            principal,
            limits.max_workers_per_principal,
            self.inner.host_limits.max_workers,
        );
        match request.parallelism {
            Parallelism::Exact(_) => {
                if remaining.is_some_and(|left| u64::from(desired) > left) {
                    Err(ComputeError::Quota)
                } else {
                    Ok(desired)
                }
            },
            Parallelism::Auto | Parallelism::AtMost(_) => {
                let admitted =
                    remaining.map_or(u64::from(desired), |left| u64::from(desired).min(left));
                u32::try_from(admitted)
                    .ok()
                    .filter(|count| *count > 0)
                    .ok_or(ComputeError::Quota)
            },
        }
    }

    fn resolve_memory_request(
        &self,
        principal: &PrincipalId,
        module: &Module,
        mut request: GroupRequest,
        limits: ComputeLimits,
    ) -> Result<GroupRequest, ComputeError> {
        if request.maximum_memory_pages != 0 {
            return Ok(request);
        }
        let (_, worker_maximum) = worker_memory_limits(module)?;
        let available_bytes = self.inner.ledger.remaining_memory(
            principal,
            limits.max_memory_bytes_per_principal,
            self.inner.host_limits.max_memory_bytes,
        );
        let available_pages = available_bytes.map_or(u64::MAX, |bytes| bytes / WASM_PAGE_BYTES);
        let admitted = worker_maximum.min(available_pages).min(u64::from(u32::MAX));
        request.maximum_memory_pages = u32::try_from(admitted)
            .ok()
            .filter(|maximum| *maximum >= request.initial_memory_pages)
            .ok_or(ComputeError::Quota)?;
        Ok(request)
    }

    /// Shared aggregate ledger.
    #[must_use]
    pub fn ledger(&self) -> &ComputeLedger {
        &self.inner.ledger
    }
}

impl Drop for RuntimeInner {
    fn drop(&mut self) {
        self.ticker_stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self
            .ticker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }
}

fn validate_group_request(request: GroupRequest) -> Result<(), ComputeError> {
    if request.initial_memory_pages == 0 {
        return Err(ComputeError::InvalidInput(
            "initial memory pages must be greater than zero".to_owned(),
        ));
    }
    if request.maximum_memory_pages != 0
        && request.maximum_memory_pages < request.initial_memory_pages
    {
        return Err(ComputeError::InvalidInput(
            "maximum memory pages must be zero (auto) or at least initial pages".to_owned(),
        ));
    }
    Ok(())
}

fn worker_memory_limits(module: &Module) -> Result<(u64, u64), ComputeError> {
    let mut memory = None;
    let mut asset_count = false;
    let mut asset_size = false;
    let mut asset_read = false;
    for import in module.imports() {
        if import.module() != "astrid_compute" {
            return Err(ComputeError::WorkerInvalid(format!(
                "worker imports unsupported module {:?}",
                import.module()
            )));
        }
        match import.name() {
            "memory" if memory.is_none() => {
                let ExternType::Memory(imported) = import.ty() else {
                    return Err(ComputeError::WorkerInvalid(
                        "astrid_compute.memory import is not a memory".to_owned(),
                    ));
                };
                memory = Some(imported);
            },
            "asset_count"
                if !asset_count && import_signature(&import.ty(), &[], &[ValType::I32]) =>
            {
                asset_count = true;
            },
            "asset_size"
                if !asset_size
                    && import_signature(&import.ty(), &[ValType::I32], &[ValType::I64]) =>
            {
                asset_size = true;
            },
            "asset_read"
                if !asset_read
                    && import_signature(
                        &import.ty(),
                        &[ValType::I32, ValType::I64, ValType::I64, ValType::I64],
                        &[ValType::I32],
                    ) =>
            {
                asset_read = true;
            },
            name => {
                return Err(ComputeError::WorkerInvalid(format!(
                    "worker has unsupported or malformed astrid_compute.{name} import"
                )));
            },
        }
    }
    let Some(memory) = memory else {
        return Err(ComputeError::WorkerInvalid(
            "worker must import astrid_compute.memory".to_owned(),
        ));
    };
    if !memory.is_shared() || memory.maximum().is_none() {
        return Err(ComputeError::WorkerInvalid(
            "worker memory import must be shared and declare a maximum".to_owned(),
        ));
    }
    Ok((
        memory.minimum(),
        memory.maximum().expect("checked shared-memory maximum"),
    ))
}

fn import_signature(import: &ExternType, params: &[ValType], results: &[ValType]) -> bool {
    let ExternType::Func(function) = import else {
        return false;
    };
    val_types_match(function.params(), params) && val_types_match(function.results(), results)
}

fn val_types_match(actual: impl Iterator<Item = ValType>, expected: &[ValType]) -> bool {
    let actual = actual.collect::<Vec<_>>();
    actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.matches(expected))
}

fn validate_worker_module(module: &Module, request: GroupRequest) -> Result<(), ComputeError> {
    let (minimum, maximum) = worker_memory_limits(module)?;
    if minimum > u64::from(request.initial_memory_pages)
        || maximum < u64::from(request.maximum_memory_pages)
    {
        return Err(ComputeError::WorkerInvalid(
            "worker memory limits are incompatible with the group request".to_owned(),
        ));
    }
    Ok(())
}

/// Safe handle to one admitted group.
#[derive(Clone)]
pub struct ComputeGroup {
    inner: Arc<GroupInner>,
}

impl std::fmt::Debug for ComputeGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputeGroup")
            .field("artifact_id", &self.inner.artifact_id)
            .field("parallelism", &self.inner.slots.len())
            .field("closed", &self.inner.closed.load(Ordering::Acquire))
            .finish()
    }
}

struct GroupInner {
    principal: PrincipalId,
    artifact_id: String,
    artifact_digest: String,
    mode: ExecutionMode,
    maximum_memory_pages: u32,
    memory: SharedMemory,
    slots: Vec<WorkerSlot>,
    next_worker: AtomicUsize,
    closed: Arc<AtomicBool>,
    jobs: Arc<Mutex<Vec<Weak<JobInner>>>>,
    accounting: Arc<AccountingState>,
    _reservation: ComputeReservation,
    max_job_fuel: Option<u64>,
    max_fuel_per_sec: Option<u64>,
    fuel_rate: FuelRateLimiter,
}

impl ComputeGroup {
    /// Principal that opened and owns this group.
    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.inner.principal
    }

    /// Verified worker id.
    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.inner.artifact_id
    }

    /// Verified worker digest.
    #[must_use]
    pub fn worker_digest(&self) -> &str {
        &self.inner.artifact_digest
    }

    /// Effective worker count.
    #[must_use]
    pub fn parallelism(&self) -> u32 {
        u32::try_from(self.inner.slots.len()).unwrap_or(u32::MAX)
    }

    /// Execution mode.
    #[must_use]
    pub fn mode(&self) -> ExecutionMode {
        self.inner.mode
    }

    /// Current shared-memory pages.
    #[must_use]
    pub fn memory_pages(&self) -> u32 {
        u32::try_from(self.inner.memory.size()).unwrap_or(u32::MAX)
    }

    /// Maximum shared-memory pages.
    #[must_use]
    pub fn maximum_memory_pages(&self) -> u32 {
        self.inner.maximum_memory_pages
    }

    /// Atomically copy bytes out of shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::InvalidInput`] when the checked range is not
    /// addressable or exceeds current shared memory.
    pub fn read(&self, offset: u64, length: u32) -> Result<Vec<u8>, ComputeError> {
        atomic_read_bytes(&self.inner.memory, offset, u64::from(length))
    }

    /// Atomically copy bytes into shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::InvalidInput`] when the checked range is not
    /// addressable or exceeds current shared memory.
    pub fn write(&self, offset: u64, bytes: &[u8]) -> Result<(), ComputeError> {
        atomic_write_bytes(&self.inner.memory, offset, bytes)
    }

    /// Grow shared memory within the maximum reserved when the group opened.
    ///
    /// # Errors
    ///
    /// Returns [`ComputeError::Closed`] after cancellation,
    /// [`ComputeError::WorkerFailed`] if Wasmtime cannot grow the memory.
    pub fn grow(&self, delta_pages: u32) -> Result<u32, ComputeError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(ComputeError::Closed);
        }
        match self.inner.memory.grow(u64::from(delta_pages)) {
            Ok(previous) => {
                let current = self.inner.memory.data_size() as u64;
                self.inner.accounting.set_memory(current);
                let _ = atomic_store_u64(&self.inner.memory, 24, current);
                u32::try_from(previous).map_err(|_| {
                    ComputeError::WorkerFailed("previous page count exceeded u32".to_owned())
                })
            },
            Err(error) => Err(ComputeError::WorkerFailed(format!(
                "grow shared memory: {error}"
            ))),
        }
    }

    /// Queue one worker invocation.
    ///
    /// # Errors
    ///
    /// Returns a typed error for a closed group, invalid descriptor, invalid
    /// fuel, invalid affinity, bounded-queue backpressure, or failed worker.
    pub fn submit(&self, descriptor: WorkDescriptor) -> Result<ComputeJob, ComputeError> {
        if self.inner.closed.load(Ordering::Acquire) {
            return Err(ComputeError::Closed);
        }
        if self.inner.max_fuel_per_sec.is_some_and(|budget| {
            self.inner
                .fuel_rate
                .over_budget(&self.inner.principal, budget, Instant::now())
        }) {
            return Err(ComputeError::Quota);
        }
        validate_descriptor(&self.inner.memory, descriptor)?;
        let job = Arc::new(JobInner::new(
            self.inner.principal.clone(),
            self.inner.artifact_id.clone(),
        ));
        self.inner
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(Arc::downgrade(&job));

        let index = if let Some(index) = descriptor.worker_index {
            let index = usize::try_from(index).map_err(|_| {
                ComputeError::InvalidInput("worker index is not addressable".to_owned())
            })?;
            let Some(slot) = self.inner.slots.get(index) else {
                return Err(ComputeError::InvalidInput(
                    "worker index is outside the group".to_owned(),
                ));
            };
            slot.reserve_targeted()?;
            index
        } else {
            self.select_worker()
        };

        let fuel = descriptor
            .fuel
            .or(self.inner.max_job_fuel)
            .unwrap_or(UNBOUNDED_JOB_FUEL);
        if fuel == 0 {
            self.inner.slots[index].release_pending();
            return Err(ComputeError::InvalidInput(
                "job fuel must be greater than zero".to_owned(),
            ));
        }
        if self
            .inner
            .max_job_fuel
            .is_some_and(|maximum| fuel > maximum)
        {
            self.inner.slots[index].release_pending();
            return Err(ComputeError::Quota);
        }
        let command = WorkerCommand::Run {
            descriptor,
            fuel,
            job: Arc::clone(&job),
        };
        self.inner
            .accounting
            .queued_jobs
            .fetch_add(1, Ordering::Relaxed);
        if let Err(error) = self.inner.slots[index].try_send(command) {
            self.inner
                .accounting
                .queued_jobs
                .fetch_sub(1, Ordering::Relaxed);
            self.inner.slots[index].release_pending();
            return Err(error);
        }
        self.inner
            .accounting
            .jobs_submitted
            .fetch_add(1, Ordering::Relaxed);
        Ok(ComputeJob { inner: job })
    }

    fn select_worker(&self) -> usize {
        let len = self.inner.slots.len();
        let start = self
            .inner
            .next_worker
            .fetch_add(1, Ordering::Relaxed)
            .checked_rem(len)
            .unwrap_or(0);
        let index = (0..len)
            .map(|offset| start.wrapping_add(offset).checked_rem(len).unwrap_or(0))
            .min_by_key(|index| self.inner.slots[*index].pending())
            .unwrap_or(start);
        self.inner.slots[index].add_pending();
        index
    }

    /// Idempotently cancel every queued/running job and reject new work.
    pub fn cancel(&self) {
        self.inner.cancel_all();
    }

    /// Snapshot group counters.
    #[must_use]
    pub fn accounting(&self) -> GroupAccounting {
        self.inner.accounting.snapshot()
    }

    /// Whether cancellation/close has begun.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::Acquire)
    }

    /// Jobs accepted but not yet executing.
    #[must_use]
    pub fn queued_jobs(&self) -> u32 {
        u32::try_from(self.inner.accounting.queued_jobs.load(Ordering::Relaxed)).unwrap_or(u32::MAX)
    }

    /// Jobs currently executing in worker Stores.
    #[must_use]
    pub fn running_jobs(&self) -> u32 {
        u32::try_from(self.inner.accounting.running_jobs.load(Ordering::Relaxed))
            .unwrap_or(u32::MAX)
    }
}

impl GroupInner {
    fn cancel_all(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            let _ = atomic_fetch_add_u32(&self.memory, 8, 1);
            let _ = self.memory.atomic_notify(8, u32::MAX);
        }
        let mut jobs = self
            .jobs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        jobs.retain(|weak| {
            if let Some(job) = weak.upgrade() {
                job.cancel.store(true, Ordering::Release);
                true
            } else {
                false
            }
        });
    }
}

impl Drop for GroupInner {
    fn drop(&mut self) {
        self.cancel_all();
        for slot in &self.slots {
            slot.shutdown();
        }
        for slot in &self.slots {
            slot.join();
        }
    }
}

fn validate_descriptor(
    memory: &SharedMemory,
    descriptor: WorkDescriptor,
) -> Result<(), ComputeError> {
    if descriptor.offset < ABI_HEADER_BYTES {
        return Err(ComputeError::InvalidInput(
            "descriptor overlaps the reserved ABI header".to_owned(),
        ));
    }
    checked_range(memory, descriptor.offset, descriptor.length).map(|_| ())
}

/// Cloneable job observer.
#[derive(Clone)]
pub struct ComputeJob {
    inner: Arc<JobInner>,
}

impl std::fmt::Debug for ComputeJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputeJob")
            .field("state", &self.state())
            .finish_non_exhaustive()
    }
}

impl ComputeJob {
    /// Principal that owns the group which submitted this job.
    #[must_use]
    pub fn principal(&self) -> &PrincipalId {
        &self.inner.principal
    }

    /// Verified worker id of the group which submitted this job.
    #[must_use]
    pub fn worker_id(&self) -> &str {
        &self.inner.worker_id
    }

    /// Current non-blocking state.
    #[must_use]
    pub fn state(&self) -> JobState {
        self.inner
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .state
    }

    /// Worker index once assigned/running.
    #[must_use]
    pub fn worker_index(&self) -> Option<u32> {
        self.inner
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .worker_index
    }

    /// Request cancellation. Idempotent.
    pub fn cancel(&self) {
        self.inner.cancel.store(true, Ordering::Release);
    }

    /// Block until terminal and clone the result.
    ///
    /// # Errors
    ///
    /// Returns the terminal cancellation or worker failure recorded by the
    /// worker thread.
    pub fn join(&self) -> Result<JobResult, ComputeError> {
        let mut record = self
            .inner
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while record.result.is_none() {
            record = self
                .inner
                .ready
                .wait(record)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        record.result.clone().unwrap_or_else(|| {
            Err(ComputeError::WorkerFailed(
                "job reached an impossible non-terminal state".to_owned(),
            ))
        })
    }

    /// Wait up to `timeout` for terminal state.
    pub fn join_timeout(&self, timeout: Duration) -> Option<Result<JobResult, ComputeError>> {
        let record = self
            .inner
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (record, _) = self
            .inner
            .ready
            .wait_timeout_while(record, timeout, |record| record.result.is_none())
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        record.result.clone()
    }
}

struct JobInner {
    principal: PrincipalId,
    worker_id: String,
    record: Mutex<JobRecord>,
    ready: Condvar,
    cancel: Arc<AtomicBool>,
}

impl JobInner {
    fn new(principal: PrincipalId, worker_id: String) -> Self {
        Self {
            principal,
            worker_id,
            record: Mutex::new(JobRecord {
                state: JobState::Queued,
                worker_index: None,
                result: None,
            }),
            ready: Condvar::new(),
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    fn running(&self, worker_index: u32) {
        let mut record = self
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        record.state = JobState::Running;
        record.worker_index = Some(worker_index);
    }

    fn finish(&self, result: Result<JobResult, ComputeError>, worker_index: u32) {
        let mut record = self
            .record
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        record.worker_index = Some(worker_index);
        record.state = match &result {
            Ok(value) => value.state,
            Err(ComputeError::Cancelled) => JobState::Cancelled,
            Err(_) => JobState::Failed,
        };
        record.result = Some(result);
        self.ready.notify_all();
    }
}

struct JobRecord {
    state: JobState,
    worker_index: Option<u32>,
    result: Option<Result<JobResult, ComputeError>>,
}

struct WorkerStoreState {
    cancel: Arc<AtomicBool>,
    group_closed: Arc<AtomicBool>,
    memory: SharedMemory,
    assets: Arc<[WorkerAsset]>,
    job_active: bool,
}

enum WorkerCommand {
    Run {
        descriptor: WorkDescriptor,
        fuel: u64,
        job: Arc<JobInner>,
    },
    Shutdown,
}

fn close_failed_group(closed: &AtomicBool, memory: &SharedMemory) {
    if !closed.swap(true, Ordering::AcqRel) {
        let _ = atomic_fetch_add_u32(memory, 8, 1);
        let _ = memory.atomic_notify(8, u32::MAX);
    }
}

struct WorkerSlot {
    sender: mpsc::SyncSender<WorkerCommand>,
    pending: Arc<AtomicUsize>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

struct WorkerExecutionContext {
    accounting: Arc<AccountingState>,
    closed: Arc<AtomicBool>,
    fuel_ledger: FuelLedger,
    fuel_rate: FuelRateLimiter,
    assets: Arc<[WorkerAsset]>,
}

fn link_asset_imports(linker: &mut Linker<WorkerStoreState>) -> Result<(), ComputeError> {
    linker
        .func_wrap(
            "astrid_compute",
            "asset_count",
            |caller: Caller<'_, WorkerStoreState>| -> i32 {
                i32::try_from(caller.data().assets.len()).unwrap_or(i32::MAX)
            },
        )
        .map_err(|error| {
            ComputeError::WorkerInvalid(format!("link asset_count import: {error}"))
        })?;
    linker
        .func_wrap(
            "astrid_compute",
            "asset_size",
            |caller: Caller<'_, WorkerStoreState>, index: i32| -> i64 {
                usize::try_from(index)
                    .ok()
                    .and_then(|index| caller.data().assets.get(index))
                    .and_then(|asset| i64::try_from(asset.bytes.len()).ok())
                    .unwrap_or(i64::from(ASSET_ERR_INDEX))
            },
        )
        .map_err(|error| ComputeError::WorkerInvalid(format!("link asset_size import: {error}")))?;
    linker
        .func_wrap(
            "astrid_compute",
            "asset_read",
            |mut caller: Caller<'_, WorkerStoreState>,
             index: i32,
             asset_offset: i64,
             destination: i64,
             length: i64|
             -> i32 {
                if !caller.data().job_active {
                    return ASSET_ERR_PHASE;
                }
                let Ok(index) = usize::try_from(index) else {
                    return ASSET_ERR_INDEX;
                };
                let (Ok(asset_offset), Ok(destination), Ok(length)) = (
                    usize::try_from(asset_offset),
                    u64::try_from(destination),
                    usize::try_from(length),
                ) else {
                    return ASSET_ERR_RANGE;
                };
                let length_u64 = u64::try_from(length).unwrap_or(u64::MAX);
                if length_u64 > MAX_ASSET_READ_BYTES {
                    return ASSET_ERR_LENGTH;
                }
                let Some(asset) = caller.data().assets.get(index) else {
                    return ASSET_ERR_INDEX;
                };
                let source = Arc::clone(&asset.bytes);
                let Some(end) = asset_offset.checked_add(length) else {
                    return ASSET_ERR_RANGE;
                };
                let Some(bytes) = source.get(asset_offset..end) else {
                    return ASSET_ERR_RANGE;
                };
                let charge = ASSET_READ_BASE_FUEL
                    .saturating_add(length_u64.saturating_mul(ASSET_READ_FUEL_PER_BYTE));
                let Ok(remaining) = caller.get_fuel() else {
                    return ASSET_ERR_FUEL;
                };
                if remaining < charge {
                    return ASSET_ERR_FUEL;
                }
                if caller.set_fuel(remaining.saturating_sub(charge)).is_err() {
                    return ASSET_ERR_FUEL;
                }
                let memory = caller.data().memory.clone();
                if atomic_write_bytes(&memory, destination, bytes).is_err() {
                    return ASSET_ERR_RANGE;
                }
                ASSET_OK
            },
        )
        .map_err(|error| ComputeError::WorkerInvalid(format!("link asset_read import: {error}")))?;
    Ok(())
}

impl WorkerSlot {
    #[allow(
        clippy::too_many_lines,
        reason = "single worker-thread lifecycle keeps Store ownership and teardown auditable"
    )]
    fn start(
        index: u32,
        engine: &Engine,
        module: &Module,
        memory: &SharedMemory,
        context: WorkerExecutionContext,
        worker_start_timeout: Duration,
    ) -> Result<Self, ComputeError> {
        let WorkerExecutionContext {
            accounting,
            closed,
            fuel_ledger,
            fuel_rate,
            assets,
        } = context;
        let (sender, receiver) = mpsc::sync_channel(WORKER_QUEUE_CAPACITY);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let pending = Arc::new(AtomicUsize::new(0));
        let pending_for_thread = Arc::clone(&pending);
        let engine = engine.clone();
        let interrupt_engine = engine.clone();
        let module = module.clone();
        let memory = memory.clone();
        let startup_cancel = Arc::new(AtomicBool::new(false));
        let startup_cancel_for_thread = Arc::clone(&startup_cancel);
        let handle = std::thread::Builder::new()
            .name(format!("astrid-compute-{index}"))
            .spawn(move || {
                let mut store = Store::new(
                    &engine,
                    WorkerStoreState {
                        cancel: startup_cancel_for_thread,
                        group_closed: Arc::clone(&closed),
                        memory: memory.clone(),
                        assets,
                        job_active: false,
                    },
                );
                // Initialization may materialize large signed data segments.
                // It is not a principal job and has no hidden fuel quota; the
                // epoch deadline plus startup timeout below remains a forced
                // interruption boundary for a non-terminating start function.
                if let Err(error) = store.set_fuel(UNBOUNDED_JOB_FUEL) {
                    let _ = ready_tx.send(Err(ComputeError::WorkerFailed(format!(
                        "seed validation fuel: {error}"
                    ))));
                    return;
                }
                store.set_epoch_deadline(1);
                store.epoch_deadline_callback(|context| {
                    if context.data().cancel.load(Ordering::Acquire)
                        || context.data().group_closed.load(Ordering::Acquire)
                    {
                        Ok(UpdateDeadline::Interrupt)
                    } else {
                        Ok(UpdateDeadline::Continue(1))
                    }
                });
                let startup = (|| {
                    let mut linker = Linker::new(&engine);
                    linker
                        .define(&mut store, "astrid_compute", "memory", memory.clone())
                        .map_err(|error| {
                            ComputeError::WorkerInvalid(format!(
                                "link worker shared memory: {error:#}"
                            ))
                        })?;
                    link_asset_imports(&mut linker)?;
                    let instance = linker.instantiate(&mut store, &module).map_err(|error| {
                        ComputeError::WorkerInvalid(format!("instantiate worker: {error:#}"))
                    })?;
                    let abi = instance
                        .get_typed_func::<(), i32>(&mut store, "astrid_compute_abi_version")
                        .map_err(|error| {
                            ComputeError::WorkerInvalid(format!("missing ABI export: {error}"))
                        })?;
                    let version = abi.call(&mut store, ()).map_err(|error| {
                        ComputeError::WorkerInvalid(format!("call ABI export: {error}"))
                    })?;
                    if version != COMPUTE_ABI_VERSION {
                        return Err(ComputeError::WorkerInvalid(format!(
                            "unsupported ABI version {version}"
                        )));
                    }
                    let run = instance
                        .get_typed_func::<(i32, i64, i64, i64), i32>(
                            &mut store,
                            "astrid_compute_run",
                        )
                        .map_err(|error| {
                            ComputeError::WorkerInvalid(format!("missing run export: {error}"))
                        })?;
                    Ok(run)
                })();
                let Ok(run) = startup else {
                    let _ = ready_tx.send(startup.map(|_| ()));
                    return;
                };
                let _ = ready_tx.send(Ok(()));
                while let Ok(command) = receiver.recv() {
                    let WorkerCommand::Run {
                        descriptor,
                        fuel,
                        job,
                    } = command
                    else {
                        break;
                    };
                    accounting.queued_jobs.fetch_sub(1, Ordering::Relaxed);
                    if closed.load(Ordering::Acquire) || job.cancel.load(Ordering::Acquire) {
                        job.finish(Err(ComputeError::Cancelled), index);
                        accounting.jobs_cancelled.fetch_add(1, Ordering::Relaxed);
                        pending_for_thread.fetch_sub(1, Ordering::Relaxed);
                        continue;
                    }
                    accounting.running_jobs.fetch_add(1, Ordering::Relaxed);
                    job.running(index);
                    store.data_mut().cancel = Arc::clone(&job.cancel);
                    if let Err(error) = store.set_fuel(fuel) {
                        job.finish(
                            Err(ComputeError::WorkerFailed(format!("set fuel: {error}"))),
                            index,
                        );
                        accounting.jobs_failed.fetch_add(1, Ordering::Relaxed);
                        accounting.running_jobs.fetch_sub(1, Ordering::Relaxed);
                        pending_for_thread.fetch_sub(1, Ordering::Relaxed);
                        close_failed_group(&closed, &memory);
                        break;
                    }
                    store.set_epoch_deadline(1);
                    let started = Instant::now();
                    let offset = i64::try_from(descriptor.offset);
                    let length = i64::try_from(descriptor.length);
                    let tag = i64::from_ne_bytes(descriptor.tag.to_ne_bytes());
                    store.data_mut().job_active = true;
                    let call = match (offset, length) {
                        (Ok(offset), Ok(length)) => {
                            run.call(&mut store, (index.cast_signed(), offset, length, tag))
                        },
                        _ => Err(wasmtime::Error::msg(
                            "descriptor does not fit ABI-1 memory32 arguments",
                        )),
                    };
                    store.data_mut().job_active = false;
                    let remaining = store.get_fuel().unwrap_or(0);
                    let consumed = fuel.saturating_sub(remaining);
                    fuel_ledger.charge(&job.principal, consumed);
                    fuel_rate.record(&job.principal, consumed, Instant::now());
                    let current_memory = memory.data_size() as u64;
                    accounting.set_memory(current_memory);
                    let _ = atomic_store_u64(&memory, 24, current_memory);
                    accounting
                        .fuel_consumed
                        .fetch_add(consumed, Ordering::Relaxed);
                    let worker_failed = match call {
                        Ok(status) => {
                            job.finish(
                                Ok(JobResult {
                                    state: JobState::Completed,
                                    worker_index: index,
                                    worker_status: status,
                                    fuel_consumed: consumed,
                                    elapsed: started.elapsed(),
                                }),
                                index,
                            );
                            accounting.jobs_completed.fetch_add(1, Ordering::Relaxed);
                            false
                        },
                        Err(_error)
                            if job.cancel.load(Ordering::Acquire)
                                || closed.load(Ordering::Acquire) =>
                        {
                            job.finish(Err(ComputeError::Cancelled), index);
                            accounting.jobs_cancelled.fetch_add(1, Ordering::Relaxed);
                            false
                        },
                        Err(error) => {
                            job.finish(Err(ComputeError::WorkerFailed(error.to_string())), index);
                            accounting.jobs_failed.fetch_add(1, Ordering::Relaxed);
                            true
                        },
                    };
                    accounting.running_jobs.fetch_sub(1, Ordering::Relaxed);
                    pending_for_thread.fetch_sub(1, Ordering::Relaxed);
                    if worker_failed {
                        close_failed_group(&closed, &memory);
                        break;
                    }
                }
                for command in receiver.try_iter() {
                    if let WorkerCommand::Run { job, .. } = command {
                        accounting.queued_jobs.fetch_sub(1, Ordering::Relaxed);
                        job.finish(Err(ComputeError::Cancelled), index);
                        accounting.jobs_cancelled.fetch_add(1, Ordering::Relaxed);
                        pending_for_thread.fetch_sub(1, Ordering::Relaxed);
                    }
                }
            })
            .map_err(|error| ComputeError::WorkerFailed(format!("start worker thread: {error}")))?;
        match ready_rx.recv_timeout(worker_start_timeout) {
            Ok(Ok(())) => Ok(Self {
                sender,
                pending,
                handle: Mutex::new(Some(handle)),
            }),
            Ok(Err(error)) => {
                let _ = handle.join();
                Err(error)
            },
            Err(mpsc::RecvTimeoutError::Timeout) => {
                startup_cancel.store(true, Ordering::Release);
                interrupt_engine.increment_epoch();
                let _ = handle.join();
                Err(ComputeError::WorkerInvalid(format!(
                    "worker startup exceeded {} seconds",
                    worker_start_timeout.as_secs_f64()
                )))
            },
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = handle.join();
                Err(ComputeError::WorkerFailed(
                    "worker startup channel closed".to_owned(),
                ))
            },
        }
    }

    fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    fn add_pending(&self) {
        self.pending.fetch_add(1, Ordering::AcqRel);
    }

    fn reserve_targeted(&self) -> Result<(), ComputeError> {
        self.pending
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| ComputeError::Busy)
    }

    fn release_pending(&self) {
        self.pending.fetch_sub(1, Ordering::AcqRel);
    }

    fn try_send(&self, command: WorkerCommand) -> Result<(), ComputeError> {
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::TrySendError::Full(_) => ComputeError::Busy,
            mpsc::TrySendError::Disconnected(_) => {
                ComputeError::WorkerFailed("worker thread is unavailable".to_owned())
            },
        })
    }

    fn shutdown(&self) {
        // A blocking send is intentional during teardown: a full queue must
        // drain its now-cancelled jobs and then receive the sentinel. A
        // best-effort `try_send` could lose the only shutdown message and make
        // the subsequent join wait forever on `recv`.
        let _ = self.sender.send(WorkerCommand::Shutdown);
    }

    fn join(&self) {
        if let Some(handle) = self
            .handle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = handle.join();
        }
    }
}

struct AccountingState {
    workers_reserved: u32,
    memory_bytes_current: AtomicU64,
    memory_bytes_peak: AtomicU64,
    jobs_submitted: AtomicU64,
    jobs_completed: AtomicU64,
    jobs_cancelled: AtomicU64,
    jobs_failed: AtomicU64,
    fuel_consumed: AtomicU64,
    queued_jobs: AtomicU64,
    running_jobs: AtomicU64,
}

impl AccountingState {
    fn new(workers_reserved: u32, memory_bytes: u64) -> Self {
        Self {
            workers_reserved,
            memory_bytes_current: AtomicU64::new(memory_bytes),
            memory_bytes_peak: AtomicU64::new(memory_bytes),
            jobs_submitted: AtomicU64::new(0),
            jobs_completed: AtomicU64::new(0),
            jobs_cancelled: AtomicU64::new(0),
            jobs_failed: AtomicU64::new(0),
            fuel_consumed: AtomicU64::new(0),
            queued_jobs: AtomicU64::new(0),
            running_jobs: AtomicU64::new(0),
        }
    }

    fn set_memory(&self, current: u64) {
        self.memory_bytes_current.store(current, Ordering::Relaxed);
        self.memory_bytes_peak.fetch_max(current, Ordering::Relaxed);
    }

    fn snapshot(&self) -> GroupAccounting {
        GroupAccounting {
            workers_reserved: self.workers_reserved,
            memory_bytes_current: self.memory_bytes_current.load(Ordering::Relaxed),
            memory_bytes_peak: self.memory_bytes_peak.load(Ordering::Relaxed),
            jobs_submitted: self.jobs_submitted.load(Ordering::Relaxed),
            jobs_completed: self.jobs_completed.load(Ordering::Relaxed),
            jobs_cancelled: self.jobs_cancelled.load(Ordering::Relaxed),
            jobs_failed: self.jobs_failed.load(Ordering::Relaxed),
            fuel_consumed: self.fuel_consumed.load(Ordering::Relaxed),
        }
    }
}

fn initialize_header(memory: &SharedMemory, workers: u32) -> Result<(), ComputeError> {
    atomic_write_bytes(memory, 0, &[0; ABI_HEADER_LEN])?;
    atomic_store_u32(memory, 0, ABI_MAGIC)?;
    atomic_store_u32(memory, 4, COMPUTE_ABI_VERSION as u32)?;
    atomic_store_u64(memory, 16, u64::from(workers))?;
    atomic_store_u64(memory, 24, memory.data_size() as u64)?;
    Ok(())
}

fn checked_range(
    memory: &SharedMemory,
    offset: u64,
    length: u64,
) -> Result<std::ops::Range<usize>, ComputeError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| ComputeError::InvalidInput("shared-memory range overflow".to_owned()))?;
    if end > memory.data_size() as u64 {
        return Err(ComputeError::InvalidInput(
            "shared-memory range is out of bounds".to_owned(),
        ));
    }
    let start = usize::try_from(offset)
        .map_err(|_| ComputeError::InvalidInput("offset is not addressable".to_owned()))?;
    let end = usize::try_from(end)
        .map_err(|_| ComputeError::InvalidInput("range end is not addressable".to_owned()))?;
    Ok(start..end)
}

#[allow(
    unsafe_code,
    reason = "Wasmtime SharedMemory requires host access through atomic pointer views"
)]
fn atomic_read_bytes(
    memory: &SharedMemory,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, ComputeError> {
    let range = checked_range(memory, offset, length)?;
    let data = memory.data();
    Ok(data[range]
        .iter()
        .map(|cell| {
            // SAFETY: `AtomicU8` has alignment 1 and the pointer remains valid
            // for the SharedMemory lifetime. Wasmtime explicitly requires
            // concurrent host access through atomic views of these cells.
            let atomic = unsafe { &*cell.get().cast::<std::sync::atomic::AtomicU8>() };
            atomic.load(Ordering::SeqCst)
        })
        .collect())
}

#[allow(
    unsafe_code,
    reason = "Wasmtime SharedMemory requires host access through atomic pointer views"
)]
fn atomic_write_bytes(
    memory: &SharedMemory,
    offset: u64,
    bytes: &[u8],
) -> Result<(), ComputeError> {
    let range = checked_range(memory, offset, bytes.len() as u64)?;
    let data = memory.data();
    for (cell, byte) in data[range].iter().zip(bytes) {
        // SAFETY: same argument as `atomic_read_bytes`; AtomicU8 alignment is 1.
        let atomic = unsafe { &*cell.get().cast::<std::sync::atomic::AtomicU8>() };
        atomic.store(*byte, Ordering::SeqCst);
    }
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Wasmtime SharedMemory requires host access through aligned atomic pointer views"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "alignment is checked and Wasmtime's shared-memory base is page-aligned"
)]
fn atomic_store_u32(memory: &SharedMemory, offset: usize, value: u32) -> Result<(), ComputeError> {
    if !offset.is_multiple_of(std::mem::align_of::<AtomicU32>())
        || offset
            .checked_add(std::mem::size_of::<AtomicU32>())
            .is_none_or(|end| end > memory.data_size())
    {
        return Err(ComputeError::WorkerFailed(
            "unaligned or out-of-bounds ABI u32".to_owned(),
        ));
    }
    let cell = &memory.data()[offset];
    // SAFETY: the ABI offsets are explicitly alignment-checked; Wasmtime's
    // shared-memory base is page-aligned and stable for the memory lifetime.
    let atomic = unsafe { &*cell.get().cast::<AtomicU32>() };
    atomic.store(value, Ordering::SeqCst);
    Ok(())
}

#[allow(
    unsafe_code,
    reason = "Wasmtime SharedMemory requires host access through aligned atomic pointer views"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "alignment is checked and Wasmtime's shared-memory base is page-aligned"
)]
fn atomic_fetch_add_u32(
    memory: &SharedMemory,
    offset: usize,
    value: u32,
) -> Result<u32, ComputeError> {
    if !offset.is_multiple_of(std::mem::align_of::<AtomicU32>())
        || offset
            .checked_add(std::mem::size_of::<AtomicU32>())
            .is_none_or(|end| end > memory.data_size())
    {
        return Err(ComputeError::WorkerFailed(
            "unaligned or out-of-bounds ABI u32".to_owned(),
        ));
    }
    let cell = &memory.data()[offset];
    // SAFETY: same alignment and lifetime argument as `atomic_store_u32`.
    let atomic = unsafe { &*cell.get().cast::<AtomicU32>() };
    Ok(atomic.fetch_add(value, Ordering::SeqCst))
}

#[allow(
    unsafe_code,
    reason = "Wasmtime SharedMemory requires host access through aligned atomic pointer views"
)]
#[allow(
    clippy::cast_ptr_alignment,
    reason = "alignment is checked and Wasmtime's shared-memory base is page-aligned"
)]
fn atomic_store_u64(memory: &SharedMemory, offset: usize, value: u64) -> Result<(), ComputeError> {
    if !offset.is_multiple_of(std::mem::align_of::<AtomicU64>())
        || offset
            .checked_add(std::mem::size_of::<AtomicU64>())
            .is_none_or(|end| end > memory.data_size())
    {
        return Err(ComputeError::WorkerFailed(
            "unaligned or out-of-bounds ABI u64".to_owned(),
        ));
    }
    let cell = &memory.data()[offset];
    // SAFETY: the ABI offsets are explicitly alignment-checked; Wasmtime's
    // shared-memory base is page-aligned and stable for the memory lifetime.
    let atomic = unsafe { &*cell.get().cast::<AtomicU64>() };
    atomic.store(value, Ordering::SeqCst);
    Ok(())
}

#[cfg(test)]
mod tests;
