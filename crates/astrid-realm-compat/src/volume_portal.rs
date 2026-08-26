//! Owner-scoped durable byte portal over an injected [`AstridVolume`].
//!
//! The portal deliberately does not accept a host path. Region names are
//! derived from the trusted [`HostPrincipal`] bytes and the fixed domain
//! separator below; guest paths, argv, and payloads never participate in
//! namespace selection. The volume remains the only byte store and the only
//! durability boundary.

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::sync::{
    Arc, Mutex, MutexGuard, OnceLock, Weak,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use astrid_provider::{HostPrincipal, ProviderError};
use astrid_resource_types::{CanonicalDecode, CanonicalEncode, ObjectGeneration};
use astrid_storage::volume::{AstridVolume, VolumeRegion};

/// Maximum logical payload extent in one owner portal.
///
/// The bound keeps malformed or hostile callers from turning a portal into an
/// unbounded namespace. It is a format policy, not a host filesystem quota.
pub const MAX_OWNER_VOLUME_BYTES: u64 = 64 * 1024 * 1024;

const REGION_PREFIX: &str = "astrid-realm-compat/v1/owner";
const METADATA_SUFFIX: &str = "metadata";
const PAYLOAD_SUFFIX: &str = "payload";
const METADATA_MAGIC: [u8; 8] = *b"ARCPORT1";
const GENERATION_ENCODED_LEN: usize = 11;
const METADATA_LEN: usize = METADATA_MAGIC.len() + 32 + GENERATION_ENCODED_LEN;
const OWNER_OFFSET: usize = 8;
const GENERATION_OFFSET: usize = 40;

static NEXT_PORTAL_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
struct VolumeCoordinator {
    state: Mutex<CoordinatorState>,
}

// A staged mutation is released only by the staging portal's successful
// commit. Drop must not clear it: that would let another portal flush the
// unsynced volume tail through AstridVolume::sync.

#[derive(Debug, Default)]
struct CoordinatorState {
    active: Option<ActiveMutation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ActiveMutation {
    owner: HostPrincipal,
    portal_id: u64,
}

#[derive(Debug)]
struct VolumeCoordinatorEntry {
    volume: Weak<dyn AstridVolume>,
    coordinator: Arc<VolumeCoordinator>,
}

static VOLUME_COORDINATORS: OnceLock<Mutex<HashMap<usize, VolumeCoordinatorEntry>>> =
    OnceLock::new();

struct OperationGuard<'a> {
    _operation: MutexGuard<'a, ()>,
    coordinator: MutexGuard<'a, CoordinatorState>,
}

/// Durable owner-bound byte portal.
///
/// The owner is immutable for the lifetime of this value. Every byte and
/// durability operation checks both the caller principal and the persisted
/// [`ObjectGeneration`]. This type stores an injected volume handle, never a
/// host path or a second byte store.
pub struct OwnerVolumePortal {
    volume: Arc<dyn AstridVolume>,
    owner: HostPrincipal,
    metadata_region: VolumeRegion,
    payload_region: VolumeRegion,
    operation_lock: Arc<Mutex<()>>,
    coordinator: Arc<VolumeCoordinator>,
    portal_id: u64,
    poisoned: Arc<AtomicBool>,
}

impl Clone for OwnerVolumePortal {
    fn clone(&self) -> Self {
        Self {
            volume: Arc::clone(&self.volume),
            owner: self.owner,
            metadata_region: self.metadata_region.clone(),
            payload_region: self.payload_region.clone(),
            operation_lock: Arc::clone(&self.operation_lock),
            coordinator: Arc::clone(&self.coordinator),
            portal_id: self.portal_id,
            poisoned: Arc::clone(&self.poisoned),
        }
    }
}

impl fmt::Debug for OwnerVolumePortal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnerVolumePortal")
            .field("owner", &self.owner)
            .finish_non_exhaustive()
    }
}

impl OwnerVolumePortal {
    /// Open an owner portal on an injected volume.
    ///
    /// A new owner receives one metadata region and one payload region. Both
    /// are created and the initial generation is synchronized before this
    /// method reports success. Existing regions must contain a valid,
    /// owner-matching metadata record and a bounded payload extent.
    ///
    /// # Errors
    ///
    /// Storage errors, malformed metadata, mixed initialization state, and
    /// capacity violations fail closed as [`ProviderError::NotSupported`].
    pub fn open(
        volume: Arc<dyn AstridVolume>,
        owner: HostPrincipal,
    ) -> Result<Self, ProviderError> {
        let (metadata_region, payload_region) = regions_for(owner)?;
        let coordinator = coordinator_for(&volume)?;
        let portal =
            Self::new_unchecked(volume, owner, metadata_region, payload_region, coordinator);
        let mut guard = portal.lock_operation()?;
        let metadata_exists = portal
            .volume
            .region_exists(&portal.metadata_region)
            .map_err(|_| ProviderError::NotSupported)?;
        let payload_exists = portal
            .volume
            .region_exists(&portal.payload_region)
            .map_err(|_| ProviderError::NotSupported)?;

        if metadata_exists != payload_exists {
            return Err(ProviderError::NotSupported);
        }

        if !metadata_exists {
            guard
                .coordinator
                .reserve_mutation(portal.owner, portal.portal_id)?;
            portal
                .volume
                .create_region(&portal.metadata_region, true)
                .map_err(|_| ProviderError::NotSupported)?;
            portal
                .volume
                .create_region(&portal.payload_region, true)
                .map_err(|_| ProviderError::NotSupported)?;
            portal.write_generation(ObjectGeneration::INITIAL)?;
            portal.sync_unchecked()?;
            guard
                .coordinator
                .clear_mutation(portal.owner, portal.portal_id)?;
            drop(guard);
            return Ok(portal);
        }

        let _ = portal.read_generation()?;
        let payload_len = portal
            .volume
            .region_len(&portal.payload_region)
            .map_err(|_| ProviderError::NotSupported)?;
        if payload_len > MAX_OWNER_VOLUME_BYTES {
            portal.poison();
            return Err(ProviderError::NotSupported);
        }
        drop(guard);
        Ok(portal)
    }

    /// Alias for [`Self::open`] that emphasizes construction from a volume.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::NotSupported`] when the volume cannot be
    /// opened or its owner metadata is invalid.
    pub fn new(volume: Arc<dyn AstridVolume>, owner: HostPrincipal) -> Result<Self, ProviderError> {
        Self::open(volume, owner)
    }

    /// Alias for [`Self::open`] using the owner-bound naming used by ramfs.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::NotSupported`] when the volume cannot be
    /// opened or its owner metadata is invalid.
    pub fn for_owner(
        volume: Arc<dyn AstridVolume>,
        owner: HostPrincipal,
    ) -> Result<Self, ProviderError> {
        Self::open(volume, owner)
    }

    fn new_unchecked(
        volume: Arc<dyn AstridVolume>,
        owner: HostPrincipal,
        metadata_region: VolumeRegion,
        payload_region: VolumeRegion,
        coordinator: Arc<VolumeCoordinator>,
    ) -> Self {
        Self {
            volume,
            owner,
            metadata_region,
            payload_region,
            operation_lock: Arc::new(Mutex::new(())),
            coordinator,
            portal_id: NEXT_PORTAL_ID.fetch_add(1, Ordering::Relaxed),
            poisoned: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Immutable trusted owner encoded by this portal.
    #[must_use]
    pub const fn owner(&self) -> HostPrincipal {
        self.owner
    }

    /// Stable owner identity for this portal. This is not a host path.
    #[must_use]
    pub const fn namespace_id(&self) -> HostPrincipal {
        self.owner
    }

    /// Host path probe. A durable portal never exposes a host path.
    #[must_use]
    pub const fn as_host_path(&self) -> Option<&'static str> {
        let _ = self;
        None
    }

    /// Require the caller to match this portal's immutable owner.
    ///
    /// This check is independent of provider/interpreter preflight.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`] for a different owner.
    pub fn require_owner(&self, caller: HostPrincipal) -> Result<(), ProviderError> {
        if caller.as_bytes() == self.owner.as_bytes() {
            Ok(())
        } else {
            Err(ProviderError::PrincipalMismatch)
        }
    }

    /// Return the currently persisted generation for `caller`.
    ///
    /// Callers that are about to perform an operation should pass the returned
    /// value back to that operation; the operation checks it again.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`] for a different owner,
    /// or [`ProviderError::NotSupported`] when metadata cannot be read or is
    /// malformed.
    pub fn generation(&self, caller: HostPrincipal) -> Result<ObjectGeneration, ProviderError> {
        self.require_owner(caller)?;
        let _guard = self.lock_operation()?;
        self.read_generation()
    }

    /// Return the persisted generation after checking the caller owner.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`] for a different owner,
    /// or [`ProviderError::NotSupported`] for invalid metadata.
    pub fn generation_for(&self, caller: HostPrincipal) -> Result<ObjectGeneration, ProviderError> {
        self.generation(caller)
    }

    /// Require a caller-supplied generation to match the persisted value.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`] for a different owner,
    /// [`ProviderError::StaleGeneration`] when `requested` is stale, or
    /// [`ProviderError::NotSupported`] for invalid metadata.
    pub fn require_generation(
        &self,
        caller: HostPrincipal,
        requested: ObjectGeneration,
    ) -> Result<(), ProviderError> {
        self.require_owner(caller)?;
        let _guard = self.lock_operation()?;
        self.check_generation(requested)
    }

    /// Require both owner and generation for one operation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`] for a different owner,
    /// [`ProviderError::StaleGeneration`] for a stale generation, or
    /// [`ProviderError::NotSupported`] when metadata cannot be read.
    pub fn require_owner_generation(
        &self,
        caller: HostPrincipal,
        requested: ObjectGeneration,
    ) -> Result<(), ProviderError> {
        self.require_owner(caller)?;
        let _guard = self.lock_operation()?;
        self.check_generation(requested)
    }

    /// Read bytes at an exact payload offset.
    ///
    /// A successful read is an observation of the live volume state. Call
    /// [`Self::sync`] separately when a preceding write must cross the durable
    /// barrier and advance the owner generation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`],
    /// [`ProviderError::StaleGeneration`], or [`ProviderError::NotSupported`]
    /// when the read fails or the request exceeds the extent bound.
    pub fn read_at(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ProviderError> {
        self.require_owner(caller)?;
        let _guard = self.lock_operation()?;
        self.check_generation(generation)?;
        Self::check_range(offset, buffer.len())?;
        self.volume
            .read_region_at(&self.payload_region, offset, buffer)
            .map_err(|_| {
                self.poison();
                ProviderError::NotSupported
            })
    }

    /// Read bytes using the portal's owner and generation checks.
    ///
    /// # Errors
    ///
    /// Returns the same authority, generation, storage, and capacity errors
    /// as [`Self::read_at`].
    pub fn read(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, ProviderError> {
        self.read_at(caller, generation, offset, buffer)
    }

    /// Return the current payload extent after owner and generation checks.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`],
    /// [`ProviderError::StaleGeneration`], or [`ProviderError::NotSupported`]
    /// when payload metadata is unavailable or out of bounds.
    pub fn len(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
    ) -> Result<u64, ProviderError> {
        self.require_owner(caller)?;
        let _guard = self.lock_operation()?;
        self.check_generation(generation)?;
        let length = self.volume.region_len(&self.payload_region).map_err(|_| {
            self.poison();
            ProviderError::NotSupported
        })?;
        if length > MAX_OWNER_VOLUME_BYTES {
            self.poison();
            return Err(ProviderError::NotSupported);
        }
        Ok(length)
    }

    /// Stream bytes into the payload region at an exact offset.
    ///
    /// This method stages one volume payload record and does not claim that
    /// the bytes are durable. Call [`Self::sync`] to append the next owner
    /// generation and cross the durability barrier in one volume commit.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`],
    /// [`ProviderError::StaleGeneration`], or [`ProviderError::NotSupported`]
    /// for a malformed volume, short source, or out-of-range write.
    pub fn write_from(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
        offset: u64,
        payload_len: u64,
        payload: &mut dyn Read,
    ) -> Result<(), ProviderError> {
        self.require_owner(caller)?;
        let mut guard = self.lock_operation()?;
        let owns_active_mutation = guard.coordinator.active_for(self.owner, self.portal_id)?;
        self.check_generation(generation)?;
        Self::check_range_u64(offset, payload_len)?;
        if payload_len == 0 {
            return Ok(());
        }
        if !owns_active_mutation {
            guard
                .coordinator
                .reserve_mutation(self.owner, self.portal_id)?;
        }
        self.write_payload_unchecked(offset, payload_len, payload)
    }

    /// Write a byte slice into the payload region without claiming durability.
    ///
    /// # Errors
    ///
    /// Returns the same authority, generation, storage, and capacity errors
    /// as [`Self::write_from`].
    pub fn write_at(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        let payload_len = u64::try_from(bytes.len()).map_err(|_| ProviderError::NotSupported)?;
        self.write_from(caller, generation, offset, payload_len, &mut &bytes[..])
    }

    /// Write a byte slice into the payload region without claiming durability.
    ///
    /// # Errors
    ///
    /// Returns the same authority, generation, storage, and capacity errors
    /// as [`Self::write_at`].
    pub fn write(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        self.write_at(caller, generation, offset, bytes)
    }

    /// Flush all preceding portal writes through [`AstridVolume::sync`].
    ///
    /// When a write is staged, this appends the next owner-generation record
    /// before issuing exactly one volume sync. The returned generation is the
    /// token for subsequent operations. With no staged write, the current
    /// generation is returned after a plain durability flush.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`],
    /// [`ProviderError::StaleGeneration`], or [`ProviderError::NotSupported`]
    /// when metadata or the volume durability barrier fails.
    pub fn sync(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
    ) -> Result<ObjectGeneration, ProviderError> {
        self.require_owner(caller)?;
        let mut guard = self.lock_operation()?;
        let owns_active_mutation = guard.coordinator.active_for(self.owner, self.portal_id)?;
        self.check_generation(generation)?;
        if owns_active_mutation {
            let next = generation.checked_next().map_err(|_| {
                self.poison();
                ProviderError::NotSupported
            })?;
            self.write_generation(next)?;
            self.sync_unchecked()?;
            guard
                .coordinator
                .clear_mutation(self.owner, self.portal_id)?;
            Ok(next)
        } else {
            self.sync_unchecked()?;
            Ok(generation)
        }
    }

    /// Stage a payload and commit it with the next owner generation.
    ///
    /// The payload record, generation metadata record, and one
    /// [`AstridVolume::sync`] call form the durable operation. On success the
    /// returned generation is required for later reads, writes, and syncs.
    ///
    /// # Errors
    ///
    /// Returns the same authority, generation, storage, and capacity errors
    /// as [`Self::write_at`] or [`Self::sync`].
    pub fn write_durable_at(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
        offset: u64,
        bytes: &[u8],
    ) -> Result<ObjectGeneration, ProviderError> {
        self.require_owner(caller)?;
        let mut guard = self.lock_operation()?;
        let owns_active_mutation = guard.coordinator.active_for(self.owner, self.portal_id)?;
        self.check_generation(generation)?;
        let payload_len = u64::try_from(bytes.len()).map_err(|_| ProviderError::NotSupported)?;
        Self::check_range_u64(offset, payload_len)?;
        let next = generation.checked_next().map_err(|_| {
            self.poison();
            ProviderError::NotSupported
        })?;
        if !owns_active_mutation {
            guard
                .coordinator
                .reserve_mutation(self.owner, self.portal_id)?;
        }
        self.write_payload_unchecked(offset, payload_len, &mut &bytes[..])?;
        self.write_generation(next)?;
        self.sync_unchecked()?;
        guard
            .coordinator
            .clear_mutation(self.owner, self.portal_id)?;
        Ok(next)
    }

    /// Alias for [`Self::write_durable_at`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::write_durable_at`].
    pub fn write_durable(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
        offset: u64,
        bytes: &[u8],
    ) -> Result<ObjectGeneration, ProviderError> {
        self.write_durable_at(caller, generation, offset, bytes)
    }

    /// Advance the owner generation and synchronize the new metadata.
    ///
    /// The returned generation is durable only when this method returns
    /// success. A failed synchronization poisons this portal; callers must
    /// reopen the volume before attempting another operation.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::PrincipalMismatch`],
    /// [`ProviderError::StaleGeneration`], or [`ProviderError::NotSupported`]
    /// when the volume cannot persist the next generation.
    pub fn advance_generation(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
    ) -> Result<ObjectGeneration, ProviderError> {
        self.require_owner(caller)?;
        let mut guard = self.lock_operation()?;
        let owns_active_mutation = guard.coordinator.active_for(self.owner, self.portal_id)?;
        self.check_generation(generation)?;
        let next = generation.checked_next().map_err(|_| {
            self.poison();
            ProviderError::NotSupported
        })?;
        if !owns_active_mutation {
            guard
                .coordinator
                .reserve_mutation(self.owner, self.portal_id)?;
        }
        self.write_generation(next)?;
        self.sync_unchecked()?;
        guard
            .coordinator
            .clear_mutation(self.owner, self.portal_id)?;
        Ok(next)
    }

    /// Alias for [`Self::advance_generation`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::advance_generation`].
    pub fn bump_generation(
        &self,
        caller: HostPrincipal,
        generation: ObjectGeneration,
    ) -> Result<ObjectGeneration, ProviderError> {
        self.advance_generation(caller, generation)
    }

    fn lock_operation(&self) -> Result<OperationGuard<'_>, ProviderError> {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(ProviderError::NotSupported);
        }
        let Ok(operation) = self.operation_lock.lock() else {
            self.poison();
            return Err(ProviderError::NotSupported);
        };
        let Ok(coordinator) = self.coordinator.state.lock() else {
            self.poison();
            return Err(ProviderError::NotSupported);
        };
        Ok(OperationGuard {
            _operation: operation,
            coordinator,
        })
    }

    fn check_generation(&self, requested: ObjectGeneration) -> Result<(), ProviderError> {
        let found = self.read_generation()?;
        if found != requested {
            return Err(ProviderError::StaleGeneration {
                found: found.get(),
                requested: requested.get(),
            });
        }
        Ok(())
    }

    fn read_generation(&self) -> Result<ObjectGeneration, ProviderError> {
        let length = self.volume.region_len(&self.metadata_region).map_err(|_| {
            self.poison();
            ProviderError::NotSupported
        })?;
        if length != METADATA_LEN as u64 {
            self.poison();
            return Err(ProviderError::NotSupported);
        }
        let mut bytes = [0_u8; METADATA_LEN];
        let read = self
            .volume
            .read_region_at(&self.metadata_region, 0, &mut bytes)
            .map_err(|_| {
                self.poison();
                ProviderError::NotSupported
            })?;
        if read != bytes.len()
            || bytes[..OWNER_OFFSET] != METADATA_MAGIC
            || bytes[OWNER_OFFSET..GENERATION_OFFSET] != self.owner.as_bytes()[..]
        {
            self.poison();
            return Err(ProviderError::NotSupported);
        }
        ObjectGeneration::decode_canonical(&bytes[GENERATION_OFFSET..]).map_err(|_| {
            self.poison();
            ProviderError::NotSupported
        })
    }

    fn write_generation(&self, generation: ObjectGeneration) -> Result<(), ProviderError> {
        let mut bytes = [0_u8; METADATA_LEN];
        bytes[..OWNER_OFFSET].copy_from_slice(&METADATA_MAGIC);
        bytes[OWNER_OFFSET..GENERATION_OFFSET].copy_from_slice(self.owner.as_bytes());
        generation
            .encode_canonical(&mut bytes[GENERATION_OFFSET..])
            .map_err(|_| {
                self.poison();
                ProviderError::NotSupported
            })?;
        self.volume
            .write_region_from(
                &self.metadata_region,
                0,
                METADATA_LEN as u64,
                &mut &bytes[..],
            )
            .map_err(|_| {
                self.poison();
                ProviderError::NotSupported
            })
    }

    fn write_payload_unchecked(
        &self,
        offset: u64,
        payload_len: u64,
        payload: &mut dyn Read,
    ) -> Result<(), ProviderError> {
        if payload_len == 0 {
            return Ok(());
        }
        self.volume
            .write_region_from(&self.payload_region, offset, payload_len, payload)
            .map_err(|_| {
                self.poison();
                ProviderError::NotSupported
            })?;
        Ok(())
    }

    fn sync_unchecked(&self) -> Result<(), ProviderError> {
        self.volume.sync().map_err(|_| {
            self.poison();
            ProviderError::NotSupported
        })
    }

    fn check_range(offset: u64, length: usize) -> Result<(), ProviderError> {
        let length = u64::try_from(length).map_err(|_| ProviderError::NotSupported)?;
        Self::check_range_u64(offset, length)
    }

    fn check_range_u64(offset: u64, length: u64) -> Result<(), ProviderError> {
        let end = offset
            .checked_add(length)
            .ok_or(ProviderError::NotSupported)?;
        if end > MAX_OWNER_VOLUME_BYTES {
            return Err(ProviderError::NotSupported);
        }
        Ok(())
    }

    fn poison(&self) {
        self.poisoned.store(true, Ordering::Release);
    }
}

impl CoordinatorState {
    fn active_for(&self, owner: HostPrincipal, portal_id: u64) -> Result<bool, ProviderError> {
        match self.active {
            None => Ok(false),
            Some(active) if active.owner == owner && active.portal_id == portal_id => Ok(true),
            Some(_) => Err(ProviderError::NotSupported),
        }
    }

    fn reserve_mutation(
        &mut self,
        owner: HostPrincipal,
        portal_id: u64,
    ) -> Result<(), ProviderError> {
        match self.active {
            None => {
                self.active = Some(ActiveMutation { owner, portal_id });
                Ok(())
            },
            Some(active) if active.owner == owner && active.portal_id == portal_id => Ok(()),
            Some(_) => Err(ProviderError::NotSupported),
        }
    }

    fn clear_mutation(
        &mut self,
        owner: HostPrincipal,
        portal_id: u64,
    ) -> Result<(), ProviderError> {
        match self.active {
            Some(active) if active.owner == owner && active.portal_id == portal_id => {
                self.active = None;
                Ok(())
            },
            _ => Err(ProviderError::NotSupported),
        }
    }
}

fn coordinator_for(
    volume: &Arc<dyn AstridVolume>,
) -> Result<Arc<VolumeCoordinator>, ProviderError> {
    let key = Arc::as_ptr(volume).cast::<()>() as usize;
    let registry = VOLUME_COORDINATORS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut entries = registry.lock().map_err(|_| ProviderError::NotSupported)?;
    entries.retain(|_, entry| entry.volume.upgrade().is_some());
    if let Some(entry) = entries.get(&key)
        && let Some(existing_volume) = entry.volume.upgrade()
        && Arc::ptr_eq(&existing_volume, volume)
    {
        return Ok(Arc::clone(&entry.coordinator));
    }
    let coordinator = Arc::new(VolumeCoordinator {
        state: Mutex::new(CoordinatorState::default()),
    });
    entries.insert(
        key,
        VolumeCoordinatorEntry {
            volume: Arc::downgrade(volume),
            coordinator: Arc::clone(&coordinator),
        },
    );
    Ok(coordinator)
}

fn regions_for(owner: HostPrincipal) -> Result<(VolumeRegion, VolumeRegion), ProviderError> {
    let encoded = owner.as_bytes();
    let mut base = String::new();
    base.push_str(REGION_PREFIX);
    base.push('/');
    for byte in encoded {
        use fmt::Write as _;
        write!(base, "{byte:02x}").map_err(|_| ProviderError::NotSupported)?;
    }
    let metadata = VolumeRegion::new(format!("{base}/{METADATA_SUFFIX}"))
        .map_err(|_| ProviderError::NotSupported)?;
    let payload = VolumeRegion::new(format!("{base}/{PAYLOAD_SUFFIX}"))
        .map_err(|_| ProviderError::NotSupported)?;
    Ok((metadata, payload))
}

#[cfg(test)]
#[path = "volume_portal_tests.rs"]
mod tests;
