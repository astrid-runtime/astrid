//! Serialized open and reclaim coordination for hosted volume containers.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock, Weak};

use fs2::FileExt as _;
use parking_lot::{Mutex, MutexGuard};

use super::{
    ContainerState, HostedFileVolume, ReadOnlyHostedVolume, VOLUME_MAGIC, reclaim, recover,
};

type SharedOpenReclaimLock = Mutex<()>;

static OPEN_LOCKS: OnceLock<RwLock<BTreeMap<PathBuf, Weak<SharedOpenReclaimLock>>>> =
    OnceLock::new();

#[cfg(test)]
type ProofHook = Box<dyn FnOnce() + Send + 'static>;

#[cfg(test)]
static PROOF_HOOK: OnceLock<std::sync::Mutex<Option<(PathBuf, ProofHook)>>> = OnceLock::new();

#[cfg(test)]
pub(super) fn set_test_proof_hook(path: PathBuf, hook: ProofHook) {
    *PROOF_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("hosted proof test hook lock") = Some((path, hook));
}

#[cfg(test)]
fn run_test_proof_hook(path: &Path) {
    let mut hook = PROOF_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .expect("hosted proof test hook lock");
    if hook.as_ref().is_some_and(|(target, _)| target == path)
        && let Some((_, hook)) = hook.take()
    {
        hook();
    }
}

/// Process-local serialization shared by open and physical reclaim for one
/// canonical parent plus final path component.
pub(super) struct OpenReclaimLock(Arc<SharedOpenReclaimLock>);

impl OpenReclaimLock {
    fn for_path(path: &Path) -> io::Result<Self> {
        let parent = path.parent().unwrap_or(Path::new("/"));
        let canonical_parent = std::fs::canonicalize(parent)?;
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Astrid volume path has no file name",
            )
        })?;
        let key = canonical_parent.join(file_name);
        let registry = OPEN_LOCKS.get_or_init(|| RwLock::new(BTreeMap::new()));
        if let Some(lock) = registry
            .read()
            .expect("Astrid volume open-lock registry")
            .get(&key)
            .and_then(Weak::upgrade)
        {
            return Ok(Self(lock));
        }
        let mut guards = registry.write().expect("Astrid volume open-lock registry");
        if let Some(lock) = guards.get(&key).and_then(Weak::upgrade) {
            return Ok(Self(lock));
        }
        guards.retain(|_, lock| lock.strong_count() > 0);
        let lock = Arc::new(Mutex::new(()));
        guards.insert(key, Arc::downgrade(&lock));
        Ok(Self(lock))
    }

    pub(super) fn lock(&self) -> MutexGuard<'_, ()> {
        self.0.lock()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HostedVolumeIdentity {
    volume: u64,
    file: u64,
}

impl HostedVolumeIdentity {
    #[cfg(windows)]
    fn windows_file_identity(handle: std::os::windows::io::RawHandle) -> io::Result<Self> {
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let mut info = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the caller owns a live Windows handle and `info` is writable.
        #[allow(unsafe_code)]
        if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            volume: u64::from(info.dwVolumeSerialNumber),
            file: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        })
    }

    fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Astrid volume is not a regular file",
            ));
        }
        cfg_select! {
            unix => Ok(Self {
                volume: metadata.dev(),
                file: metadata.ino(),
            }),
            windows => {
                Self::windows_file_identity(file.as_raw_handle())
            },
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Astrid volume identity is unsupported on this platform",
            )),
        }
    }

    fn from_path(path: &Path) -> io::Result<Self> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.is_symlink() || !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Astrid volume is redirected or not a regular file",
            ));
        }
        cfg_select! {
            unix => Ok(Self {
                volume: metadata.dev(),
                file: metadata.ino(),
            }),
            windows => {
                let file = open_file_without_following(path)?;
                let identity = Self::windows_file_identity(file.as_raw_handle())?;
                drop(file);
                Ok(identity)
            },
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Astrid volume identity is unsupported on this platform",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostedArtifactRole {
    Active,
    Temporary,
    Previous,
    Legacy,
}

pub(crate) struct HostedArtifactProof {
    #[cfg_attr(not(test), allow(dead_code))]
    role: HostedArtifactRole,
    #[cfg_attr(not(test), allow(dead_code))]
    identity: HostedVolumeIdentity,
    volume: Arc<ReadOnlyHostedVolume>,
}

impl HostedArtifactProof {
    #[cfg(test)]
    #[must_use]
    pub(crate) const fn role(&self) -> HostedArtifactRole {
        self.role
    }

    #[cfg(test)]
    #[must_use]
    pub(crate) const fn identity(&self) -> HostedVolumeIdentity {
        self.identity
    }

    #[must_use]
    pub(crate) fn volume(&self) -> Arc<ReadOnlyHostedVolume> {
        Arc::clone(&self.volume)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostedProofPhase {
    Artifacts,
    Selected,
}

pub(crate) enum HostedProofDecision<T> {
    Accept,
    Reject(T),
}

pub(crate) enum HostedProof<T> {
    Accepted(Arc<HostedFileVolume>),
    Rejected(T),
}

struct HostedArtifact {
    role: HostedArtifactRole,
    path: PathBuf,
    identity: HostedVolumeIdentity,
    file: File,
    volume: Arc<ReadOnlyHostedVolume>,
}

struct HostedArtifactPlan {
    destination: PathBuf,
    temporary: PathBuf,
    previous: PathBuf,
    legacy: Option<PathBuf>,
}

fn open_file_without_following(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        options.access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE);
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    options.open(path)
}

fn recover_locked_artifact(role: HostedArtifactRole, path: PathBuf) -> io::Result<HostedArtifact> {
    let path_identity = HostedVolumeIdentity::from_path(&path)?;
    let mut file = open_file_without_following(&path)?;
    file.try_lock_exclusive().map_err(|error| {
        if error.kind() == io::ErrorKind::WouldBlock {
            io::Error::new(io::ErrorKind::WouldBlock, "Astrid volume is already open")
        } else {
            error
        }
    })?;
    let identity = HostedVolumeIdentity::from_file(&file)?;
    if identity != path_identity {
        return Err(io::Error::new(
            io::ErrorKind::StaleNetworkFileHandle,
            "Astrid volume path changed while acquiring its proof lock",
        ));
    }
    if file.metadata()?.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid empty Astrid volume artifact",
        ));
    }
    let mut magic = [0_u8; VOLUME_MAGIC.len()];
    file.read_exact(&mut magic)?;
    if magic != VOLUME_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Astrid volume header",
        ));
    }
    let recovery = recover::recover_container(&mut file)?;
    let volume = Arc::new(ReadOnlyHostedVolume {
        file: file.try_clone()?,
        regions: recovery.regions,
    });
    Ok(HostedArtifact {
        role,
        path,
        identity,
        file,
        volume,
    })
}

fn artifact_paths(plan: &HostedArtifactPlan) -> [(HostedArtifactRole, &Path); 4] {
    [
        (HostedArtifactRole::Active, plan.destination.as_path()),
        (HostedArtifactRole::Temporary, plan.temporary.as_path()),
        (HostedArtifactRole::Previous, plan.previous.as_path()),
        (
            HostedArtifactRole::Legacy,
            plan.legacy.as_deref().unwrap_or(Path::new("")),
        ),
    ]
}

fn open_artifact_proof(plan: &HostedArtifactPlan) -> io::Result<(Vec<HostedArtifact>, usize)> {
    let mut existing = Vec::new();
    let mut pending: Vec<(HostedArtifactRole, PathBuf)> = Vec::new();
    for (role, path) in artifact_paths(plan) {
        if role == HostedArtifactRole::Legacy && plan.legacy.is_none() {
            continue;
        }
        if std::fs::symlink_metadata(path).is_ok() {
            pending.push((role, path.to_path_buf()));
        }
    }
    let legacy_identity = pending
        .iter()
        .find(|(role, _)| *role == HostedArtifactRole::Legacy)
        .map(|(_, path)| HostedVolumeIdentity::from_path(path))
        .transpose()?;
    if let Some(legacy_identity) = legacy_identity {
        pending.retain(|(role, path)| {
            *role == HostedArtifactRole::Legacy
                || HostedVolumeIdentity::from_path(path)
                    .is_ok_and(|identity| identity != legacy_identity)
        });
        if pending.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "Astrid storage has conflicting legacy and recoverable canonical artifacts",
            ));
        }
    }
    for (role, path) in pending {
        existing.push(recover_locked_artifact(role, path)?);
    }
    let selected = existing
        .iter()
        .position(|artifact| match artifact.role {
            HostedArtifactRole::Active => true,
            HostedArtifactRole::Temporary => !existing
                .iter()
                .any(|candidate| candidate.role == HostedArtifactRole::Active),
            HostedArtifactRole::Previous => !existing.iter().any(|candidate| {
                candidate.role == HostedArtifactRole::Active
                    || candidate.role == HostedArtifactRole::Temporary
            }),
            HostedArtifactRole::Legacy => existing.len() == 1,
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "no authoritative Astrid volume artifact",
            )
        })?;
    Ok((existing, selected))
}

fn install_selected_volume(source: &HostedArtifact, destination: &Path) -> io::Result<()> {
    if source.role == HostedArtifactRole::Active {
        return Ok(());
    }
    link_locked_source(source, destination)?;
    let promoted = HostedVolumeIdentity::from_path(destination)?;
    if promoted != source.identity {
        return Err(io::Error::new(
            io::ErrorKind::StaleNetworkFileHandle,
            "promoted Astrid volume has a different identity",
        ));
    }
    sync_parent(destination)?;
    Ok(())
}

#[cfg(all(unix, target_os = "macos"))]
fn link_locked_source(source: &HostedArtifact, destination: &Path) -> io::Result<()> {
    let current = HostedVolumeIdentity::from_path(&source.path)?;
    if current != source.identity {
        return Err(io::Error::new(
            io::ErrorKind::StaleNetworkFileHandle,
            "source volume changed before its path-based promotion fallback",
        ));
    }
    // macOS does not expose linkat AT_EMPTY_PATH. This compatibility fallback
    // revalidates immediately before linking and never unlinks a mismatch.
    std::fs::hard_link(&source.path, destination)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn link_locked_source(source: &HostedArtifact, destination: &Path) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd as _;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let parent = destination.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "volume destination has no parent",
        )
    })?;
    let file_name = destination.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "volume destination has no name",
        )
    })?;
    let parent_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(parent)?;
    let name = CString::new(file_name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid volume file name"))?;
    // SAFETY: all descriptors remain live and both name buffers outlive the call.
    #[allow(unsafe_code)]
    let result = unsafe {
        libc::linkat(
            source.file.as_raw_fd(),
            c"".as_ptr(),
            parent_file.as_raw_fd(),
            name.as_ptr(),
            libc::AT_EMPTY_PATH,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn link_locked_source(source: &HostedArtifact, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_RENAME_INFO, FileRenameInfo, SetFileInformationByHandle,
    };

    let destination_name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    let name_words = destination_name.len();
    let buffer_words = usize::checked_add(4, name_words.div_ceil(2))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "rename buffer is too large"))?;
    let mut buffer = vec![0_u64; buffer_words];
    let information = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    // SAFETY: `information` points to the zeroed aligned allocation and all
    // field writes remain inside its `4 + name_words.div_ceil(2)` u64 extent.
    #[allow(unsafe_code)]
    unsafe {
        std::ptr::addr_of_mut!((*information).Anonymous.ReplaceIfExists).write(false);
        std::ptr::addr_of_mut!((*information).RootDirectory).write(std::ptr::null_mut());
        std::ptr::addr_of_mut!((*information).FileNameLength).write(
            u32::try_from(name_words).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "volume destination path is too long",
                )
            })?,
        );
        let file_name = std::ptr::addr_of_mut!((*information).FileName).cast::<u16>();
        std::ptr::copy_nonoverlapping(destination_name.as_ptr(), file_name, name_words);
    }
    // SAFETY: `source.file` owns the live source-handle opened with DELETE
    // access, and `information` remains valid through the call.
    #[allow(unsafe_code)]
    if unsafe {
        SetFileInformationByHandle(
            source.file.as_raw_handle(),
            FileRenameInfo,
            information.cast(),
            u32::try_from(buffer.len().saturating_mul(size_of::<u64>())).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "rename buffer overflow")
            })?,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn link_locked_source(_source: &HostedArtifact, _destination: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "source-bound volume linking is unsupported",
    ))
}

fn sync_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "volume has no parent"))?;
    File::open(parent)?.sync_all()
}

impl HostedFileVolume {
    /// Refuse owner-proved reclaim if the namespace no longer names the locked
    /// inode or an uninspected recovery sibling exists.
    pub(super) fn verify_owner_proved_reclaim(&self) -> io::Result<()> {
        if !self.owner_proved {
            return Ok(());
        }
        let state = self.state.lock();
        let path_identity = HostedVolumeIdentity::from_path(&self.path)?;
        let handle_identity = HostedVolumeIdentity::from_file(&state.file)?;
        if path_identity != handle_identity {
            return Err(io::Error::new(
                io::ErrorKind::StaleNetworkFileHandle,
                "owner-proved Astrid volume path no longer names its locked inode",
            ));
        }
        if std::fs::symlink_metadata(reclaim::temp_path(&self.path)).is_ok()
            || std::fs::symlink_metadata(reclaim::previous_path(&self.path)).is_ok()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "owner-proved Astrid volume reclaim found uninspected recovery artifacts",
            ));
        }
        Ok(())
    }

    /// Open the authoritative artifact only after a caller-owned owner proof.
    ///
    /// # Errors
    ///
    /// Returns `Rejected` before renaming or deleting evidence when either
    /// scan observes a forbidden owner or cannot prove complete coverage.
    /// Accepted recovery consumes the already-locked selected inode directly;
    /// it never follows the proof with ordinary `HostedFileVolume::open`.
    pub(crate) fn open_with_owner_proof<T, E>(
        volume_path: impl AsRef<Path>,
        legacy: Option<&Path>,
        map_error: impl Fn(io::Error) -> E + Copy,
        classify: impl Fn(HostedProofPhase, &[HostedArtifactProof]) -> Result<HostedProofDecision<T>, E>,
    ) -> Result<HostedProof<T>, E> {
        let destination_path = volume_path.as_ref().to_path_buf();
        let canonical_lock = OpenReclaimLock::for_path(&destination_path).map_err(map_error)?;
        let canonical_guard = canonical_lock.lock();
        let legacy_lock = match legacy {
            Some(path) => Some(OpenReclaimLock::for_path(path).map_err(map_error)?),
            None => None,
        };
        let legacy_guard = legacy_lock.as_ref().map(|lock| lock.lock());
        let plan = HostedArtifactPlan {
            temporary: reclaim::temp_path(&destination_path),
            previous: reclaim::previous_path(&destination_path),
            destination: destination_path,
            legacy: legacy.map(Path::to_path_buf),
        };
        let (mut artifacts, selected_index) = open_artifact_proof(&plan).map_err(map_error)?;
        let proofs: Vec<HostedArtifactProof> = artifacts
            .iter()
            .map(|artifact| HostedArtifactProof {
                role: artifact.role,
                identity: artifact.identity,
                volume: Arc::clone(&artifact.volume),
            })
            .collect();
        if let HostedProofDecision::Reject(reason) = classify(HostedProofPhase::Artifacts, &proofs)?
        {
            return Ok(HostedProof::Rejected(reason));
        }
        #[cfg(test)]
        run_test_proof_hook(&plan.destination);
        let selected_proof = proofs
            .get(selected_index)
            .ok_or_else(|| map_error(io::Error::other("selected Astrid volume disappeared")))?;
        if let HostedProofDecision::Reject(reason) = classify(
            HostedProofPhase::Selected,
            std::slice::from_ref(selected_proof),
        )? {
            return Ok(HostedProof::Rejected(reason));
        }
        for artifact in &artifacts {
            let current = HostedVolumeIdentity::from_path(&artifact.path).map_err(map_error)?;
            if current != artifact.identity {
                return Err(map_error(io::Error::new(
                    io::ErrorKind::StaleNetworkFileHandle,
                    "Astrid volume artifact changed during its owner proof",
                )));
            }
        }
        let selected = artifacts.swap_remove(selected_index);
        drop(proofs);
        install_selected_volume(&selected, &plan.destination).map_err(map_error)?;
        let mut selected = selected;
        let recovery = recover::recover_container(&mut selected.file).map_err(map_error)?;
        if selected.file.metadata().map_err(map_error)?.len() != recovery.valid_len
            && !recovery.footer_present
        {
            selected
                .file
                .set_len(recovery.valid_len)
                .map_err(map_error)?;
            selected.file.sync_all().map_err(map_error)?;
        }
        let footer_pending = !recovery.footer_present;
        let selected_identity =
            HostedVolumeIdentity::from_file(&selected.file).map_err(map_error)?;
        let mut state = ContainerState {
            file: selected.file,
            sequence: recovery.sequence,
            valid_len: recovery.valid_len,
            durable_len: recovery.durable_len,
            last_commit_offset: recovery.last_commit_offset,
            last_commit_has_snapshot: recovery.last_commit_has_snapshot,
            boundary_pending: false,
            footer_pending,
            regions: recovery.regions,
        };
        if footer_pending {
            HostedFileVolume::make_durable(&mut state).map_err(map_error)?;
        }
        let returned_identity =
            HostedVolumeIdentity::from_path(&plan.destination).map_err(map_error)?;
        if returned_identity != selected_identity {
            return Err(map_error(io::Error::new(
                io::ErrorKind::StaleNetworkFileHandle,
                "Astrid volume path changed before owner-proved return",
            )));
        }
        drop(legacy_guard);
        drop(canonical_guard);
        Ok(HostedProof::Accepted(Arc::new(Self {
            path: plan.destination,
            open_lock: canonical_lock,
            owner_proved: true,
            state: Mutex::new(state),
        })))
    }

    /// Open or create one hosted Astrid volume container.
    ///
    /// This generic physical-container constructor intentionally retains its
    /// established recovery behavior. It rearranges opaque volume bytes only;
    /// runtime owner admission occurs through `open_with_owner_proof`, whose
    /// accepted instance refuses uninspected artifact changes before reclaim.
    ///
    /// # Errors
    ///
    /// Returns an error for a lock conflict, invalid header, interior corrupt
    /// framing, invalid region name, or host I/O failure. An incomplete final
    /// record is treated as an uncommitted tail and truncated. Once a footer
    /// exists, recovery reads only the footer, one commit, and its snapshot.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let open_lock = OpenReclaimLock::for_path(&path)?;
        let swap_guard = open_lock.lock();
        reclaim::recover_artifacts(&path)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut file = options.open(&path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Astrid volume is not a regular file",
            ));
        }
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == io::ErrorKind::WouldBlock {
                io::Error::new(io::ErrorKind::WouldBlock, "Astrid volume is already open")
            } else {
                error
            }
        })?;
        let length = file.metadata()?.len();
        if length == 0 {
            file.write_all(&VOLUME_MAGIC)?;
            file.sync_all()?;
        } else {
            let mut magic = [0_u8; VOLUME_MAGIC.len()];
            file.read_exact(&mut magic)?;
            if magic != VOLUME_MAGIC {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid Astrid volume header",
                ));
            }
        }
        let recovery = recover::recover_container(&mut file)?;
        if file.metadata()?.len() != recovery.valid_len && !recovery.footer_present {
            file.set_len(recovery.valid_len)?;
            file.sync_all()?;
        }
        let footer_pending = !recovery.footer_present;
        let mut state = ContainerState {
            file,
            sequence: recovery.sequence,
            valid_len: recovery.valid_len,
            durable_len: recovery.durable_len,
            last_commit_offset: recovery.last_commit_offset,
            last_commit_has_snapshot: recovery.last_commit_has_snapshot,
            boundary_pending: false,
            footer_pending,
            regions: recovery.regions,
        };
        if footer_pending {
            // A header-only recovery is immediately upgraded so the next boot
            // can use the footer even when no caller performs an explicit sync.
            HostedFileVolume::make_durable(&mut state)?;
        }
        drop(swap_guard);
        Ok(Arc::new(Self {
            path,
            open_lock,
            owner_proved: false,
            state: Mutex::new(state),
        }))
    }
}
