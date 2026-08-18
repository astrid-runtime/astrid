//! Persistent source storage and command-independent handlers.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::Serialize;

use super::IndexError;
use super::model::{
    BUILTIN_INDEX_ID, IndexConfig, IndexSource, MetadataSnapshot, PinnedRoot, validate_base_url,
    validate_index_id,
};

/// Default filename for source configuration beneath AstridHome/etc.
pub(crate) const CONFIG_FILE_NAME: &str = "indexes.toml";

/// Default filename for the cross-process update lock.
pub(crate) const LOCK_FILE_NAME: &str = "indexes.lock";

/// Injected config and lock paths. Tests can point these at a temporary tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IndexPaths {
    /// Source config path.
    pub(crate) config: PathBuf,
    /// Cross-process lock path.
    pub(crate) lock: PathBuf,
}

impl IndexPaths {
    /// Build paths from a config path using a sibling lock file.
    pub(crate) fn from_config(config: impl Into<PathBuf>) -> Self {
        let config = config.into();
        let lock = config.with_file_name(LOCK_FILE_NAME);
        Self { config, lock }
    }

    /// Build paths beneath an Astrid home root.
    pub(crate) fn from_home(home: &Path) -> Self {
        Self::from_config(home.join("etc").join(CONFIG_FILE_NAME))
    }
}

/// Compiled identity for the official Astrid Index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BuiltinSource {
    /// Immutable source record.
    pub(crate) source: IndexSource,
}

impl BuiltinSource {
    /// Validate and mark a source as the compiled built-in identity.
    pub(crate) fn new(mut source: IndexSource) -> Result<Self, IndexError> {
        validate_index_id(&source.id)?;
        if source.id != BUILTIN_INDEX_ID {
            return Err(IndexError::BuiltinRepointed);
        }
        source.built_in = true;
        source.validate()?;
        Ok(Self { source })
    }
}

/// Persistent source store. All mutating operations take an exclusive file
/// lock and commit a complete config via a same-directory rename.
#[derive(Debug, Clone)]
pub(crate) struct IndexStore {
    paths: IndexPaths,
    builtin: Option<BuiltinSource>,
}

impl IndexStore {
    /// Create a store without a compiled built-in source.
    ///
    /// Production dispatch should use `with_builtin` so deleting the config
    /// file cannot make the official source disappear.
    pub(crate) fn new(config_path: impl Into<PathBuf>) -> Self {
        Self {
            paths: IndexPaths::from_config(config_path),
            builtin: None,
        }
    }

    /// Create a store from injected paths and an optional built-in identity.
    pub(crate) fn with_paths(paths: IndexPaths, builtin: Option<BuiltinSource>) -> Self {
        Self { paths, builtin }
    }

    /// Create a store beneath an Astrid home root.
    pub(crate) fn from_home(home: &Path, builtin: Option<BuiltinSource>) -> Self {
        Self::with_paths(IndexPaths::from_home(home), builtin)
    }

    /// Config and lock paths used by this store.
    pub(crate) fn paths(&self) -> &IndexPaths {
        &self.paths
    }

    /// Return the compiled official source, or a typed error when this build
    /// has not completed the official root-key ceremony.
    pub(crate) fn require_builtin(&self) -> Result<&IndexSource, IndexError> {
        self.builtin
            .as_ref()
            .map(|builtin| &builtin.source)
            .ok_or(IndexError::BuiltinRootUnavailable)
    }

    /// Load and validate configured sources.
    pub(crate) fn load(&self) -> Result<Vec<IndexSource>, IndexError> {
        let _lock = self.acquire_lock(false)?;
        let mut config = self.read_unlocked()?;
        self.apply_builtin(&mut config)?;
        Ok(sorted_sources(config.sources))
    }

    /// Add one source after validating its URL, root fingerprint, and
    /// collision invariants.
    pub(crate) fn add(&self, args: AddArgs) -> Result<AddOutcome, IndexError> {
        validate_index_id(&args.id)?;
        if args.id == BUILTIN_INDEX_ID {
            return Err(IndexError::BuiltinProtected);
        }
        let source = build_source(args)?;
        self.mutate(|config| {
            if config.sources.iter().any(|item| item.id == source.id) {
                return Err(IndexError::DuplicateId(source.id.clone()));
            }
            config.sources.push(source.clone());
            config.validate()?;
            Ok(AddOutcome {
                source: source.clone(),
            })
        })
    }

    /// List sources in pretty or JSON form.
    pub(crate) fn list(&self, args: ListArgs) -> Result<String, IndexError> {
        let sources = self.load()?;
        match args.format {
            IndexListFormat::Pretty => Ok(render_pretty(&sources)),
            IndexListFormat::Json => serde_json::to_string_pretty(&sources)
                .map_err(|source| IndexError::JsonSerialize { source }),
        }
    }

    /// Remove a source unless the injected usage checker reports references.
    pub(crate) fn remove<C: UsageChecker>(
        &self,
        args: RemoveArgs,
        usage: &C,
    ) -> Result<RemoveOutcome, IndexError> {
        validate_index_id(&args.id)?;
        if args.id == BUILTIN_INDEX_ID {
            return Err(IndexError::BuiltinProtected);
        }
        let _lock = self.acquire_lock(true)?;
        let mut config = self.read_unlocked()?;
        self.apply_builtin(&mut config)?;
        let index = config
            .sources
            .iter()
            .position(|source| source.id == args.id)
            .ok_or_else(|| IndexError::NotFound(args.id.clone()))?;
        if config.sources[index].built_in || args.id == BUILTIN_INDEX_ID {
            return Err(IndexError::BuiltinProtected);
        }
        let references = usage
            .references(&args.id)
            .map_err(|error| IndexError::Usage(error.to_string()))?;
        if !references.is_empty() {
            return Ok(RemoveOutcome::Blocked {
                id: args.id,
                references,
            });
        }
        let source = config.sources.remove(index);
        config.validate()?;
        self.write_unlocked(&config)?;
        Ok(RemoveOutcome::Removed { source })
    }

    /// Refresh verified metadata using an injected transport and TUF
    /// verifier. A returned root must byte-match the pinned root; changing it
    /// requires `rotate_root`.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn update<T: RefreshTransport, V: MetadataVerifier>(
        &self,
        args: UpdateArgs,
        transport: &T,
        verifier: &V,
    ) -> Result<UpdateOutcome, IndexError> {
        validate_index_id(&args.id)?;
        let _lock = self.acquire_lock(true)?;
        let mut config = self.read_unlocked()?;
        self.apply_builtin(&mut config)?;
        let index = config
            .sources
            .iter()
            .position(|source| source.id == args.id)
            .ok_or_else(|| IndexError::NotFound(args.id.clone()))?;
        let source = config.sources[index].clone();
        let root_bytes = source.root.bytes()?;
        let response = transport
            .refresh(&source)
            .map_err(|error| IndexError::Refresh {
                id: source.id.clone(),
                message: error.to_string(),
            })?;
        if response
            .root
            .as_deref()
            .is_some_and(|returned| returned != root_bytes.as_slice())
        {
            return Err(IndexError::RootMismatch { id: source.id });
        }
        let verified_metadata = verifier
            .verify(
                &source,
                &root_bytes,
                &response.metadata,
                source.metadata.as_ref(),
            )
            .map_err(|error| IndexError::Verification {
                id: source.id.clone(),
                message: error.to_string(),
            })?;
        let snapshot = verified_metadata.into_snapshot()?;
        config.sources[index].metadata = Some(snapshot.clone());
        config.validate()?;
        self.write_unlocked(&config)?;
        Ok(UpdateOutcome {
            id: source.id,
            snapshot,
        })
    }

    /// Persist a snapshot produced by the real TUF adapter. This method does
    /// not verify bytes itself; callers must obtain the snapshot from
    /// `TufIndexAdapter` (or another explicit `MetadataVerifier`) and should not
    /// expose this as a user-facing bypass.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn record_verified_metadata(
        &self,
        id: String,
        expected_root_fingerprint: &str,
        snapshot: MetadataSnapshot,
    ) -> Result<UpdateOutcome, IndexError> {
        validate_index_id(&id)?;
        let _lock = self.acquire_lock(true)?;
        let mut config = self.read_unlocked()?;
        self.apply_builtin(&mut config)?;
        let index = config
            .sources
            .iter()
            .position(|source| source.id == id)
            .ok_or_else(|| IndexError::NotFound(id.clone()))?;
        if config.sources[index].root.fingerprint != expected_root_fingerprint {
            return Err(IndexError::RootMismatch { id });
        }
        snapshot.validate()?;
        config.sources[index].metadata = Some(snapshot.clone());
        config.validate()?;
        self.write_unlocked(&config)?;
        Ok(UpdateOutcome { id, snapshot })
    }

    /// Explicitly rotate a trust root after the real verifier validates the
    /// root transition. Regular update never calls this path.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn rotate_root<V: MetadataVerifier>(
        &self,
        rotation: RootRotation,
        verifier: &V,
    ) -> Result<IndexSource, IndexError> {
        validate_index_id(&rotation.id)?;
        let _lock = self.acquire_lock(true)?;
        let mut config = self.read_unlocked()?;
        self.apply_builtin(&mut config)?;
        let index = config
            .sources
            .iter()
            .position(|source| source.id == rotation.id)
            .ok_or_else(|| IndexError::NotFound(rotation.id.clone()))?;
        let old_root = config.sources[index].root.bytes()?;
        if config.sources[index].built_in || rotation.id == BUILTIN_INDEX_ID {
            return Err(IndexError::BuiltinProtected);
        }
        // Do not even read or validate an operator-supplied replacement for
        // the compiled built-in source: the protection check above is the
        // authoritative refusal path, regardless of the candidate bytes.
        let new_root = rotation.root.to_pinned(&rotation.fingerprint)?;
        verifier
            .verify_root_rotation(
                &config.sources[index],
                &old_root,
                &new_root.bytes()?,
                &rotation.proof,
            )
            .map_err(|_| IndexError::RootRotationRefused {
                id: rotation.id.clone(),
            })?;
        config.sources[index].root = new_root;
        config.sources[index].metadata = None;
        config.validate()?;
        self.write_unlocked(&config)?;
        Ok(config.sources[index].clone())
    }

    fn mutate<R, F>(&self, mutator: F) -> Result<R, IndexError>
    where
        F: FnOnce(&mut IndexConfig) -> Result<R, IndexError>,
    {
        let _lock = self.acquire_lock(true)?;
        let mut config = self.read_unlocked()?;
        self.apply_builtin(&mut config)?;
        let result = mutator(&mut config)?;
        config.validate()?;
        self.write_unlocked(&config)?;
        Ok(result)
    }

    fn apply_builtin(&self, config: &mut IndexConfig) -> Result<(), IndexError> {
        config.validate()?;
        if let Some(builtin) = &self.builtin {
            match config
                .sources
                .iter_mut()
                .find(|source| source.id == BUILTIN_INDEX_ID)
            {
                Some(stored) => {
                    let expected = &builtin.source;
                    if stored.base_url != expected.base_url
                        || stored.root != expected.root
                        || stored.enabled != expected.enabled
                        || stored.priority != expected.priority
                    {
                        return Err(IndexError::BuiltinRepointed);
                    }
                    stored.built_in = true;
                },
                None => config.sources.push(builtin.source.clone()),
            }
        } else if config
            .sources
            .iter()
            .any(|source| source.built_in || source.id == BUILTIN_INDEX_ID)
        {
            // A build without the compiled official root must not accept a
            // hand-written `astrid` record as if it were the official source.
            // Keep this a typed hook so dispatch can later supply the real
            // root ceremony without inventing one here.
            return Err(if config.sources.iter().any(|source| source.built_in) {
                IndexError::BuiltinRepointed
            } else {
                IndexError::BuiltinRootUnavailable
            });
        }
        config.validate()
    }

    fn read_unlocked(&self) -> Result<IndexConfig, IndexError> {
        match fs::read_to_string(&self.paths.config) {
            Ok(contents) => {
                let config: IndexConfig =
                    toml::from_str(&contents).map_err(|source| IndexError::CorruptConfig {
                        path: self.paths.config.clone(),
                        source,
                    })?;
                config.validate()?;
                Ok(config)
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(IndexConfig::default()),
            Err(source) => Err(IndexError::Io {
                path: self.paths.config.clone(),
                source,
            }),
        }
    }

    fn write_unlocked(&self, config: &IndexConfig) -> Result<(), IndexError> {
        let serialized = config.to_stable_toml()?;
        let parent = self.paths.config.parent().ok_or_else(|| IndexError::Io {
            path: self.paths.config.clone(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "config path has no parent"),
        })?;
        fs::create_dir_all(parent).map_err(|source| IndexError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        restrict_directory(parent).map_err(|source| IndexError::Io {
            path: parent.to_path_buf(),
            source,
        })?;

        let mut temp = tempfile::Builder::new()
            .prefix(".indexes.")
            .suffix(".tmp")
            .tempfile_in(parent)
            .map_err(|source| IndexError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        let temp_path = temp.path().to_path_buf();
        restrict_file(temp.as_file()).map_err(|source| IndexError::Io {
            path: temp_path.clone(),
            source,
        })?;
        temp.as_file_mut()
            .write_all(serialized.as_bytes())
            .and_then(|()| temp.as_file().sync_all())
            .map_err(|source| IndexError::Io {
                path: temp_path.clone(),
                source,
            })?;
        // A same-directory rename is atomic. If the process dies before this
        // line, the old config remains and the orphaned .tmp is ignored.
        temp.persist(&self.paths.config)
            .map_err(|error| IndexError::Io {
                path: self.paths.config.clone(),
                source: error.error,
            })?;
        restrict_path(&self.paths.config).map_err(|source| IndexError::Io {
            path: self.paths.config.clone(),
            source,
        })?;
        sync_directory(parent).map_err(|source| IndexError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        Ok(())
    }

    fn acquire_lock(&self, exclusive: bool) -> Result<File, IndexError> {
        let parent = self.paths.lock.parent().ok_or_else(|| IndexError::Lock {
            path: self.paths.lock.clone(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "lock path has no parent"),
        })?;
        fs::create_dir_all(parent).map_err(|source| IndexError::Lock {
            path: parent.to_path_buf(),
            source,
        })?;
        restrict_directory(parent).map_err(|source| IndexError::Lock {
            path: parent.to_path_buf(),
            source,
        })?;
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.paths.lock)
            .map_err(|source| IndexError::Lock {
                path: self.paths.lock.clone(),
                source,
            })?;
        restrict_file(&file).map_err(|source| IndexError::Lock {
            path: self.paths.lock.clone(),
            source,
        })?;
        if exclusive {
            file.lock_exclusive().map_err(|source| IndexError::Lock {
                path: self.paths.lock.clone(),
                source,
            })?;
        } else {
            file.lock_shared().map_err(|source| IndexError::Lock {
                path: self.paths.lock.clone(),
                source,
            })?;
        }
        Ok(file)
    }
}

/// Input accepted by add and explicit root rotation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootInput {
    /// Root bytes supplied directly by the caller.
    Bytes(Vec<u8>),
    /// Path to a root file.
    Path(PathBuf),
}

impl RootInput {
    fn to_pinned(&self, fingerprint: &str) -> Result<PinnedRoot, IndexError> {
        match self {
            Self::Bytes(bytes) => PinnedRoot::from_bytes(bytes, fingerprint),
            Self::Path(path) => PinnedRoot::from_path(path, fingerprint),
        }
    }
}

/// Arguments for index add, independent of clap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddArgs {
    /// Stable source ID.
    pub(crate) id: String,
    /// Pages base URL.
    pub(crate) base_url: String,
    /// Explicit trust root bytes or file.
    pub(crate) root: RootInput,
    /// Fingerprint claimed for the exact root bytes.
    pub(crate) fingerprint: String,
    /// Whether the source is enabled.
    pub(crate) enabled: bool,
    /// Explicit resolution priority.
    pub(crate) priority: i32,
}

/// Result of adding a source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddOutcome {
    /// Added source.
    pub(crate) source: IndexSource,
}

/// Arguments for index list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ListArgs {
    /// Requested output format.
    pub(crate) format: IndexListFormat,
}

/// List rendering format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IndexListFormat {
    /// Human-readable deterministic table.
    Pretty,
    /// Stable JSON data.
    Json,
}

impl IndexListFormat {
    /// Parse the global format value used by dispatch.
    pub(crate) fn parse(value: &str) -> Result<Self, IndexError> {
        match value {
            "pretty" => Ok(Self::Pretty),
            "json" => Ok(Self::Json),
            other => Err(IndexError::Format(other.to_owned())),
        }
    }
}

/// Arguments for index remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoveArgs {
    /// Stable source ID.
    pub(crate) id: String,
}

/// Result of attempting to remove a source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case", tag = "status")]
pub(crate) enum RemoveOutcome {
    /// Source was removed.
    Removed {
        /// Removed source.
        source: IndexSource,
    },
    /// Source remains because lock/index references were reported.
    Blocked {
        /// Source ID.
        id: String,
        /// Existing references.
        references: Vec<String>,
    },
}

/// Arguments for index update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateArgs {
    /// Stable source ID.
    pub(crate) id: String,
}

/// Response from a refresh transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RefreshResponse {
    /// Root bytes returned by the server, if it served a root object.
    pub(crate) root: Option<Vec<u8>>,
    /// Timestamp/snapshot metadata bundle consumed by the verifier.
    pub(crate) metadata: Vec<u8>,
}

/// Verified metadata returned by a real TUF adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedMetadata {
    /// TUF metadata version.
    pub(crate) version: u64,
    /// Exact bytes that passed verification.
    pub(crate) bytes: Vec<u8>,
    /// Digest of bytes, normally from the adapter's canonical digest helper.
    pub(crate) digest: String,
}

impl VerifiedMetadata {
    fn into_snapshot(self) -> Result<MetadataSnapshot, IndexError> {
        MetadataSnapshot::new(self.version, &self.bytes, &self.digest)
    }
}

/// Refresh transport seam. Production code should fetch Pages anonymously.
pub(crate) trait RefreshTransport {
    /// Fetch current root and metadata bytes for a source.
    fn refresh(&self, source: &IndexSource) -> Result<RefreshResponse, IndexError>;
}

/// TUF verifier seam. This module intentionally does not implement metadata
/// cryptography; production dispatch must adapt the real TUF crate here.
pub(crate) trait MetadataVerifier {
    /// Verify metadata against the pinned root and prior snapshot.
    fn verify(
        &self,
        source: &IndexSource,
        root: &[u8],
        metadata: &[u8],
        previous: Option<&MetadataSnapshot>,
    ) -> Result<VerifiedMetadata, IndexError>;

    /// Verify an explicit root transition proof. The default refuses all
    /// rotations, so a production adapter must opt in deliberately.
    fn verify_root_rotation(
        &self,
        source: &IndexSource,
        _old_root: &[u8],
        _new_root: &[u8],
        _proof: &[u8],
    ) -> Result<(), IndexError> {
        Err(IndexError::RootRotationRefused {
            id: source.id.clone(),
        })
    }
}

/// Usage lookup seam for remove. A non-empty result blocks removal.
pub(crate) trait UsageChecker {
    /// Return lockfiles or index references that still name a source.
    fn references(&self, id: &str) -> Result<Vec<String>, IndexError>;
}

impl<F> UsageChecker for F
where
    F: Fn(&str) -> Result<Vec<String>, IndexError>,
{
    fn references(&self, id: &str) -> Result<Vec<String>, IndexError> {
        self(id)
    }
}

/// Result of a successful metadata update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UpdateOutcome {
    /// Source ID.
    pub(crate) id: String,
    /// Persisted verified snapshot.
    pub(crate) snapshot: MetadataSnapshot,
}

/// Explicit root rotation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootRotation {
    /// Stable source ID.
    pub(crate) id: String,
    /// New trust-root bytes or path.
    pub(crate) root: RootInput,
    /// Fingerprint claimed for the new root.
    pub(crate) fingerprint: String,
    /// Proof consumed by the verifier adapter.
    pub(crate) proof: Vec<u8>,
}

fn build_source(args: AddArgs) -> Result<IndexSource, IndexError> {
    validate_index_id(&args.id)?;
    let base_url = validate_base_url(&args.base_url)?;
    let root = args.root.to_pinned(&args.fingerprint)?;
    Ok(IndexSource {
        id: args.id,
        base_url,
        root,
        enabled: args.enabled,
        priority: args.priority,
        built_in: false,
        metadata: None,
    })
}

fn sorted_sources(mut sources: Vec<IndexSource>) -> Vec<IndexSource> {
    sources.sort_by(|left, right| {
        left.priority
            .cmp(&right.priority)
            .then_with(|| left.id.cmp(&right.id))
    });
    sources
}

fn render_pretty(sources: &[IndexSource]) -> String {
    let mut output = String::from("ID  ENABLED  PRIORITY  BASE URL  ROOT FINGERPRINT\n");
    for source in sources {
        let _ = writeln!(
            output,
            "{}  {}  {}  {}  {}",
            source.id,
            if source.enabled { "yes" } else { "no" },
            source.priority,
            source.base_url,
            source.root.fingerprint
        );
    }
    output
}

fn restrict_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_file(file: &File) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn restrict_path(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }
    Ok(())
}
