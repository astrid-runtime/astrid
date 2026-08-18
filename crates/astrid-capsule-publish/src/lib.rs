#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! Offline preparation of Capsule Index publication records.
//!
//! This crate intentionally has no HTTP, GitHub, signing, or git dependency.
//! It reads an already-built installable archive, derives claims from the
//! exact bytes, and emits a typed [`PublicationRecord`].  A caller supplies
//! all publisher, source, provenance, index, and artifact-location identity;
//! omitted identity is an error rather than a guessed value.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component as PathComponent, Path, PathBuf};

use astrid_build::artifact::verify_archive;
use astrid_capsule_index::{
    ArtifactDescriptor, BuildProvenance, CanonicalSemVer, CapabilityClaims, CapsuleName,
    Coordinate, DependencyClaims, DependencySpec, Digest, DigestAlgorithm, EmbeddedPackageIdentity,
    IndexError, IndexId, MirrorUrl, Namespace, PublicationClassification, PublicationKey,
    PublicationRecord, PublisherIdentity, RuntimeRequirements, SourceProvenance,
};
use astrid_capsule_types::manifest::CapsuleManifest;
use flate2::read::GzDecoder;
use sha2::{Digest as Sha2Digest, Sha256};
use tar::Archive;
use tempfile::NamedTempFile;
use thiserror::Error;

const MEDIA_TYPE: &str = "application/vnd.astrid.capsule";
const PACKAGE_DOMAIN: &[u8] = b"astrid:capsule-index:package-claims:v1\0";
const IPC_DOMAIN: &[u8] = b"astrid:capsule-index:ipc-claims:v1\0";
const WIT_DOMAIN: &[u8] = b"astrid:capsule-index:wit-claims:v1\0";
/// Maximum compressed archive bytes accepted by offline preparation.
pub const MAX_ARCHIVE_BYTES: u64 = 50 * 1024 * 1024;
/// Maximum decompressed bytes retained across archive entries.
pub const MAX_ARCHIVE_CONTENT_BYTES: u64 = 50 * 1024 * 1024;
/// Maximum bytes retained for one regular archive entry.
pub const MAX_ARCHIVE_ENTRY_BYTES: u64 = 50 * 1024 * 1024;
/// Maximum number of regular archive entries accepted.
pub const MAX_ARCHIVE_ENTRIES: usize = 100_000;

/// Errors returned while preparing or writing a publication.
#[derive(Debug, Error)]
pub enum PublishError {
    /// An archive or output filesystem operation failed.
    #[error("publication I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The capsule archive is malformed or does not contain a required claim.
    #[error("invalid capsule archive: {0}")]
    Archive(String),
    /// The embedded Capsule.toml could not be parsed or disagrees with CLI identity.
    #[error("invalid capsule manifest: {0}")]
    Manifest(String),
    /// A supplied protocol value failed its structural validation.
    #[error("invalid publication input: {0}")]
    Input(String),
    /// The domain protocol rejected a typed value or sealed record.
    #[error("publication protocol error: {0}")]
    Protocol(#[from] IndexError),
    /// A publication JSON document could not be read or written.
    #[error("publication JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    /// The same coordinate/version already has a different immutable digest.
    #[error("same-coordinate publication equivocation at {0}")]
    Equivocation(PublicationKey),
    /// The preflight source was asked to provide an unsupported remote lookup.
    #[error("remote publication lookup is unavailable in offline preparation")]
    RemoteLookup,
}

/// All caller-supplied identity needed to prepare one publication.
#[derive(Clone, Debug)]
pub struct PublishOptions {
    /// Existing installable `.capsule` path.
    pub artifact_path: PathBuf,
    /// Target Capsule Index identifier.
    pub index_id: IndexId,
    /// Explicit HTTPS base URL for the target Index.
    pub index_base: MirrorUrl,
    /// Capsule coordinate requested by the caller.
    pub coordinate: Coordinate,
    /// Canonical publication version requested by the caller.
    pub version: CanonicalSemVer,
    /// Original artifact URL(s) to put in the immutable record.
    pub artifact_locations: Vec<MirrorUrl>,
    /// Explicit publisher actor and signing-key fingerprint.
    pub publisher: PublisherIdentity,
    /// Explicit source repository and immutable git provenance.
    pub source: SourceProvenance,
    /// Explicit build statement and attestation identity.
    pub provenance: BuildProvenance,
    /// Runtime requirement string.  It must agree with `package.astrid-version`.
    pub runtime: String,
    /// Component Model ABI requirement.  This is explicit because an archive
    /// does not safely encode a human-compatible runtime ABI claim.
    pub abi: String,
    /// Explicit output directory.  No default or home-directory fallback exists.
    pub output_dir: PathBuf,
}

impl PublishOptions {
    /// Creates publication options.  Empty URLs, runtime/ABI, or output paths
    /// are rejected during [`prepare`].
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        artifact_path: impl Into<PathBuf>,
        index_id: IndexId,
        index_base: MirrorUrl,
        coordinate: Coordinate,
        version: CanonicalSemVer,
        artifact_locations: Vec<MirrorUrl>,
        publisher: PublisherIdentity,
        source: SourceProvenance,
        provenance: BuildProvenance,
        runtime: impl Into<String>,
        abi: impl Into<String>,
        output_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            artifact_path: artifact_path.into(),
            index_id,
            index_base,
            coordinate,
            version,
            artifact_locations,
            publisher,
            source,
            provenance,
            runtime: runtime.into(),
            abi: abi.into(),
            output_dir: output_dir.into(),
        }
    }
}

/// Read-only seam used to classify an occupied coordinate before output.
/// Implementations may read a local checkout, a fixture, or a previously
/// verified index snapshot; this crate never performs a remote request.
pub trait PublicationPreflight {
    /// Return the record occupying `key`, if any.
    ///
    /// # Errors
    ///
    /// Implementations report malformed local records or unavailable lookup
    /// state as [`PublishError`].
    fn existing(&self, key: &PublicationKey) -> Result<Option<PublicationRecord>, PublishError>;
}

/// A preflight source containing no records.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmptyPreflight;

impl PublicationPreflight for EmptyPreflight {
    fn existing(&self, _key: &PublicationKey) -> Result<Option<PublicationRecord>, PublishError> {
        Ok(None)
    }
}

/// Local preflight source reading canonical records beneath a directory.
#[derive(Debug, Clone)]
pub struct FilePreflight {
    root: PathBuf,
}

impl FilePreflight {
    /// Reads records from `root/records/<namespace>/<name>/<version>.json`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the path used for a record in a PR-ready output tree.
    #[must_use]
    pub fn record_path(&self, key: &PublicationKey) -> PathBuf {
        self.root
            .join("records")
            .join(key.coordinate.namespace.as_str())
            .join(key.coordinate.name.as_str())
            .join(format!("{}.json", key.version))
    }
}

impl PublicationPreflight for FilePreflight {
    fn existing(&self, key: &PublicationKey) -> Result<Option<PublicationRecord>, PublishError> {
        let mut path = self.record_path(key);
        if !path.exists() {
            // Read legacy preparation trees without ever writing them.  New
            // submissions are always emitted beneath `records/`.
            let legacy = self
                .root
                .join("releases")
                .join(key.coordinate.namespace.as_str())
                .join(key.coordinate.name.as_str())
                .join(format!("{}.json", key.version));
            if legacy.exists() {
                path = legacy;
            }
        }
        reject_output_symlinks(&self.root, &path)?;
        match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PublishError::Input(format!(
                    "record path is a symlink: {}",
                    path.display()
                )));
            },
            Err(error) => return Err(PublishError::Io(error)),
            Ok(_) => {},
        }
        let bytes = fs::read(&path)?;
        let record = serde_json::from_slice::<PublicationRecord>(&bytes)?;
        if record.key() != *key {
            return Err(PublishError::Input(format!(
                "record at {} is bound to {}, expected {}",
                path.display(),
                record.key(),
                key
            )));
        }
        Ok(Some(record))
    }
}

/// Classification result and not-yet-written publication document.
#[derive(Clone, Debug)]
pub struct PreparedPublication {
    record: PublicationRecord,
    classification: PublicationClassification,
    output_path: PathBuf,
    artifact_path: PathBuf,
    index_base: MirrorUrl,
    output_dir: PathBuf,
}

impl PreparedPublication {
    /// Sealed typed publication record.
    #[must_use]
    pub fn record(&self) -> &PublicationRecord {
        &self.record
    }

    /// New/idempotent/equivocation classification from preflight.
    #[must_use]
    pub const fn classification(&self) -> PublicationClassification {
        self.classification
    }

    /// Canonical output path under the explicit output directory.
    #[must_use]
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }

    /// Exact source artifact path used for hashing.
    #[must_use]
    pub fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    /// Explicit Index base supplied by the caller.
    #[must_use]
    pub fn index_base(&self) -> &MirrorUrl {
        &self.index_base
    }

    /// Canonical JSON bytes for the typed publication record.
    ///
    /// # Errors
    ///
    /// Returns an error if the typed record cannot be serialized.
    pub fn json_bytes(&self) -> Result<Vec<u8>, PublishError> {
        Ok(serde_json::to_vec_pretty(&self.record)?)
    }
}

/// Outcome from atomically writing a prepared record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WriteOutcome {
    /// A new record was atomically created at `path`.
    Written {
        /// Final record path.
        path: PathBuf,
    },
    /// The existing record was byte-for-byte idempotent; no write occurred.
    Idempotent {
        /// Existing record path.
        path: PathBuf,
    },
}

/// Prepare a publication using a caller-supplied read-only preflight seam.
///
/// # Errors
///
/// Returns an error for malformed archives, missing claims, invalid typed
/// inputs, preflight failures, or same-coordinate equivocation.
pub fn prepare<P: PublicationPreflight>(
    options: &PublishOptions,
    preflight: &P,
) -> Result<PreparedPublication, PublishError> {
    validate_options(options)?;
    let entries = read_capsule_entries(&options.artifact_path)?;
    let manifest_bytes = entries
        .get("Capsule.toml")
        .ok_or_else(|| PublishError::Archive("archive is missing Capsule.toml".into()))?;
    let manifest_text = std::str::from_utf8(manifest_bytes)
        .map_err(|error| PublishError::Manifest(format!("Capsule.toml is not UTF-8: {error}")))?;
    let manifest = toml::from_str::<CapsuleManifest>(manifest_text)
        .map_err(|error| PublishError::Manifest(error.to_string()))?;
    validate_manifest_identity(&manifest, options)?;

    let component_bytes = read_component(&entries, &manifest)?;
    let wit_bytes = canonical_wit_bytes(&entries)?;
    let manifest_digest = Digest::blake3(manifest_bytes);
    let component_digest = Digest::blake3(&component_bytes);
    let wit_digest = Digest::blake3(&wit_bytes);
    let capabilities = derive_capabilities(&manifest)?;
    let dependencies = derive_dependencies(&manifest)?;
    let runtime = RuntimeRequirements::new(options.runtime.clone(), options.abi.clone())
        .map_err(PublishError::Protocol)?;
    let package_digest = package_digest(
        &options.coordinate,
        &options.version,
        &manifest_digest,
        &component_digest,
        &wit_digest,
        &capabilities,
        &runtime,
        &dependencies,
    );
    let embedded = EmbeddedPackageIdentity::new(
        options.coordinate.clone(),
        options.version.clone(),
        package_digest,
    );
    let package = astrid_capsule_index::PackageClaims::new(
        embedded,
        manifest_digest,
        component_digest,
        wit_digest,
        capabilities,
        runtime,
        dependencies,
    );
    let artifact_bytes = fs::read(&options.artifact_path)?;
    let sha256 = Sha256::digest(&artifact_bytes);
    let sha256 = Digest::from_bytes(DigestAlgorithm::Sha256, sha256.as_slice())?;
    let artifact = ArtifactDescriptor::new_with_digest_set(
        artifact_bytes.len() as u64,
        MEDIA_TYPE,
        options.artifact_locations.clone(),
        vec![Digest::blake3(&artifact_bytes), sha256],
    )?;
    let record = PublicationRecord::seal(astrid_capsule_index::PublicationRecordInput {
        schema: astrid_capsule_index::SchemaVersion::v1(),
        index_id: options.index_id.clone(),
        coordinate: options.coordinate.clone(),
        version: options.version.clone(),
        artifact,
        metadata: BTreeMap::new(),
        publisher: options.publisher.clone(),
        source: options.source.clone(),
        package,
        provenance: options.provenance.clone(),
    })?;
    let key = record.key();
    let existing = preflight.existing(&key)?;
    let classification = record.classify_against(existing.as_ref());
    if classification == PublicationClassification::Equivocation {
        return Err(PublishError::Equivocation(key));
    }
    let output_path = FilePreflight::new(&options.output_dir).record_path(&key);
    Ok(PreparedPublication {
        record,
        classification,
        output_path,
        artifact_path: options.artifact_path.clone(),
        index_base: options.index_base.clone(),
        output_dir: options.output_dir.clone(),
    })
}

/// Atomically write a prepared publication.  A dry run must skip this
/// function; it has no network path and never mutates an existing idempotent
/// record.
///
/// # Errors
///
/// Returns an error when the output directory is unsafe, serialization fails,
/// or an immutable record races with a different writer.
pub fn write_submission(prepared: &PreparedPublication) -> Result<WriteOutcome, PublishError> {
    if prepared.classification == PublicationClassification::Idempotent {
        return Ok(WriteOutcome::Idempotent {
            path: prepared.output_path.clone(),
        });
    }
    let parent = prepared
        .output_path
        .parent()
        .ok_or_else(|| PublishError::Input("output path has no parent".into()))?;
    reject_output_symlinks(&prepared.output_dir, parent)?;
    fs::create_dir_all(parent)?;
    reject_output_symlinks(&prepared.output_dir, parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&prepared.json_bytes()?)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(&prepared.output_path) {
        Ok(_) => {
            // Persisting a record is a transaction: flush the containing
            // directory so a power loss cannot leave a renamed-but-unlinked
            // submission behind.
            File::open(parent)?.sync_all()?;
            Ok(WriteOutcome::Written {
                path: prepared.output_path.clone(),
            })
        },
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            // A concurrent writer won the race.  Re-read and require exact
            // idempotence rather than replacing another immutable record.
            let existing = fs::read(&prepared.output_path)?;
            let candidate = serde_json::from_slice::<PublicationRecord>(&existing)?;
            if candidate == prepared.record {
                Ok(WriteOutcome::Idempotent {
                    path: prepared.output_path.clone(),
                })
            } else {
                Err(PublishError::Equivocation(prepared.record.key()))
            }
        },
        Err(error) => Err(PublishError::Io(error.error)),
    }
}

fn validate_options(options: &PublishOptions) -> Result<(), PublishError> {
    if options.artifact_path.as_os_str().is_empty() {
        return Err(PublishError::Input("artifact path is required".into()));
    }
    if options.output_dir.as_os_str().is_empty() {
        return Err(PublishError::Input("output directory is required".into()));
    }
    if options.artifact_locations.is_empty() {
        return Err(PublishError::Input(
            "at least one explicit artifact URL is required".into(),
        ));
    }
    if options.runtime.trim().is_empty() || options.abi.trim().is_empty() {
        return Err(PublishError::Input(
            "runtime and ABI requirements are required".into(),
        ));
    }
    if options.index_base.as_str().is_empty() {
        return Err(PublishError::Input("index base URL is required".into()));
    }
    Ok(())
}

fn validate_manifest_identity(
    manifest: &CapsuleManifest,
    options: &PublishOptions,
) -> Result<(), PublishError> {
    if manifest.package.publish == Some(false) {
        return Err(PublishError::Manifest(
            "package.publish = false forbids publication".into(),
        ));
    }
    if manifest.package.name != options.coordinate.name.as_str() {
        return Err(PublishError::Manifest(format!(
            "manifest package.name {:?} does not match {}",
            manifest.package.name, options.coordinate.name
        )));
    }
    let manifest_version = CanonicalSemVer::parse(&manifest.package.version)
        .map_err(|error| PublishError::Manifest(error.to_string()))?;
    if manifest_version != options.version {
        return Err(PublishError::Manifest(format!(
            "manifest package.version {} does not match {}",
            manifest_version, options.version
        )));
    }
    let required_runtime = manifest
        .package
        .astrid_version
        .as_deref()
        .ok_or_else(|| PublishError::Manifest("package.astrid-version is required".into()))?;
    if required_runtime != options.runtime {
        return Err(PublishError::Manifest(format!(
            "runtime requirement {:?} does not match package.astrid-version {:?}",
            options.runtime, required_runtime
        )));
    }
    if let Some(repository) = &manifest.package.repository {
        let repository = MirrorUrl::new(repository.clone())
            .map_err(|error| PublishError::Manifest(error.to_string()))?;
        if repository != *options.source.repository() {
            return Err(PublishError::Manifest(
                "manifest repository does not match source.repository".into(),
            ));
        }
    }
    Ok(())
}

fn derive_capabilities(manifest: &CapsuleManifest) -> Result<CapabilityClaims, PublishError> {
    let names = manifest.capabilities.held_names();
    let mut ipc = Vec::new();
    for topic in &manifest.publishes {
        ipc.push(("publish", topic.0.as_str()));
    }
    for topic in &manifest.subscribes {
        ipc.push(("subscribe", topic.0.as_str()));
    }
    ipc.sort_unstable();
    let mut projection = IPC_DOMAIN.to_vec();
    put_u64(&mut projection, ipc.len() as u64);
    for (direction, topic) in ipc {
        put_text(&mut projection, direction);
        put_text(&mut projection, topic);
    }
    CapabilityClaims::new(names, Digest::blake3(&projection)).map_err(PublishError::Protocol)
}

fn derive_dependencies(manifest: &CapsuleManifest) -> Result<DependencyClaims, PublishError> {
    let mut dependencies = Vec::new();
    for (namespace, interfaces) in &manifest.imports {
        let namespace = Namespace::new(namespace.clone())
            .map_err(|error| PublishError::Manifest(error.to_string()))?;
        for (name, import) in interfaces {
            let name = CapsuleName::new(name.clone())
                .map_err(|error| PublishError::Manifest(error.to_string()))?;
            let coordinate = Coordinate::new(namespace.clone(), name);
            dependencies.push(
                DependencySpec::new(coordinate, import.version.to_string(), import.optional)
                    .map_err(PublishError::Protocol)?,
            );
        }
    }
    DependencyClaims::new(dependencies).map_err(PublishError::Protocol)
}

#[allow(clippy::too_many_arguments)]
fn package_digest(
    coordinate: &Coordinate,
    version: &CanonicalSemVer,
    manifest_digest: &Digest,
    component_digest: &Digest,
    wit_digest: &Digest,
    capabilities: &CapabilityClaims,
    runtime: &RuntimeRequirements,
    dependencies: &DependencyClaims,
) -> Digest {
    let mut bytes = PACKAGE_DOMAIN.to_vec();
    put_text(&mut bytes, &coordinate.to_string());
    put_text(&mut bytes, &version.to_string());
    put_digest(&mut bytes, manifest_digest);
    put_digest(&mut bytes, component_digest);
    put_digest(&mut bytes, wit_digest);
    put_u64(&mut bytes, capabilities.capabilities().len() as u64);
    for capability in capabilities.capabilities() {
        put_text(&mut bytes, capability);
    }
    put_digest(&mut bytes, capabilities.declaration_digest());
    put_digest(&mut bytes, capabilities.effective_ipc_digest());
    put_text(&mut bytes, runtime.runtime());
    put_text(&mut bytes, runtime.abi());
    put_digest(&mut bytes, runtime.digest());
    put_u64(&mut bytes, dependencies.dependencies().len() as u64);
    for dependency in dependencies.dependencies() {
        put_text(&mut bytes, &dependency.coordinate().to_string());
        put_text(&mut bytes, dependency.requirement());
        bytes.push(u8::from(dependency.optional()));
    }
    put_digest(&mut bytes, dependencies.digest());
    Digest::blake3(&bytes)
}

fn read_capsule_entries(path: &Path) -> Result<BTreeMap<String, Vec<u8>>, PublishError> {
    let compressed_size = fs::metadata(path)?.len();
    if compressed_size > MAX_ARCHIVE_BYTES {
        return Err(PublishError::Archive(format!(
            "compressed archive is {compressed_size} bytes; limit is {MAX_ARCHIVE_BYTES}"
        )));
    }
    let file = File::open(path)?;
    let mut archive = Archive::new(GzDecoder::new(file));
    let mut entries = BTreeMap::new();
    let mut total_size = 0_u64;
    let mut entry_count = 0_usize;
    for entry in archive
        .entries()
        .map_err(|error| PublishError::Archive(error.to_string()))?
    {
        let mut entry = entry.map_err(|error| PublishError::Archive(error.to_string()))?;
        let path = normalized_entry_path(&entry)?;
        if !entry.header().entry_type().is_file() {
            if entry.header().entry_type().is_dir() {
                continue;
            }
            return Err(PublishError::Archive(format!(
                "unsupported non-regular archive entry {path:?}"
            )));
        }
        let entry_size = entry.size();
        if entry_size > MAX_ARCHIVE_ENTRY_BYTES {
            return Err(PublishError::Archive(format!(
                "archive entry {path:?} is {entry_size} bytes; limit is {MAX_ARCHIVE_ENTRY_BYTES}"
            )));
        }
        total_size = total_size
            .checked_add(entry_size)
            .ok_or_else(|| PublishError::Archive("archive content size overflow".into()))?;
        if total_size > MAX_ARCHIVE_CONTENT_BYTES {
            return Err(PublishError::Archive(format!(
                "decompressed archive content exceeds {MAX_ARCHIVE_CONTENT_BYTES} bytes"
            )));
        }
        if entries.contains_key(&path) {
            return Err(PublishError::Archive(format!(
                "duplicate archive entry {path:?}"
            )));
        }
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| PublishError::Archive("archive entry count overflow".into()))?;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(PublishError::Archive(format!(
                "archive contains more than {MAX_ARCHIVE_ENTRIES} regular entries"
            )));
        }
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        entries.insert(path, bytes);
    }
    // Build's canonical reader rejects malformed signatures, duplicate paths,
    // links, and unsafe entries.  Run it only after our bounded pass so a
    // compressed archive cannot trigger an unbounded second decompression.
    verify_archive(path)
        .map_err(|error| PublishError::Archive(format!("archive verification failed: {error}")))?;
    Ok(entries)
}

fn reject_output_symlinks(root: &Path, path: &Path) -> Result<(), PublishError> {
    let root = if root.is_absolute() {
        root.to_path_buf()
    } else {
        std::env::current_dir()?.join(root)
    };
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    if !path.starts_with(&root) {
        return Err(PublishError::Input(
            "output path escaped the explicit output directory".into(),
        ));
    }
    let relative = path
        .strip_prefix(&root)
        .map_err(|_| PublishError::Input("output path escaped output directory".into()))?;
    // Inspect every existing component up to (and including) the explicit
    // root.  `/var` is a platform-owned alias on macOS; rejecting that stable
    // system prefix would make every `tempdir()`-based output unusable, so it
    // is the one intentionally permitted ancestor.
    let mut ancestor = PathBuf::new();
    for component in root.components() {
        ancestor.push(component.as_os_str());
        if ancestor == Path::new("/var") {
            continue;
        }
        match fs::symlink_metadata(&ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PublishError::Input(format!(
                    "output path contains symlink ancestor {}",
                    ancestor.display()
                )));
            },
            Ok(_) | Err(_) => {},
        }
    }
    let mut current = root.clone();
    for component in relative.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(PublishError::Input(format!(
                        "output path contains symlink component {}",
                        current.display()
                    )));
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => return Err(PublishError::Io(error)),
        }
    }
    Ok(())
}

fn normalized_entry_path<R: Read>(entry: &tar::Entry<'_, R>) -> Result<String, PublishError> {
    let path = entry
        .path()
        .map_err(|error| PublishError::Archive(error.to_string()))?;
    let mut pieces = Vec::new();
    for component in path.components() {
        match component {
            PathComponent::Normal(piece) => {
                let piece = piece
                    .to_str()
                    .ok_or_else(|| PublishError::Archive("archive path is not UTF-8".into()))?;
                if piece.is_empty() || piece.contains('\\') || piece.contains('\0') {
                    return Err(PublishError::Archive("unsafe archive path".into()));
                }
                pieces.push(piece);
            },
            PathComponent::CurDir
            | PathComponent::ParentDir
            | PathComponent::RootDir
            | PathComponent::Prefix(_) => {
                return Err(PublishError::Archive(format!(
                    "unsafe archive path {}",
                    path.display()
                )));
            },
        }
    }
    if pieces.is_empty() {
        return Err(PublishError::Archive("empty archive path".into()));
    }
    Ok(pieces.join("/"))
}

fn read_component(
    entries: &BTreeMap<String, Vec<u8>>,
    manifest: &CapsuleManifest,
) -> Result<Vec<u8>, PublishError> {
    if manifest.components.len() != 1 {
        return Err(PublishError::Manifest(format!(
            "publication requires exactly one component; found {}",
            manifest.components.len()
        )));
    }
    let path = manifest.components[0]
        .path
        .to_str()
        .ok_or_else(|| PublishError::Manifest("component path is not UTF-8".into()))?;
    let path = path.strip_prefix("./").unwrap_or(path);
    let bytes = entries
        .get(path)
        .ok_or_else(|| PublishError::Archive(format!("component {path:?} is not in archive")))?;
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        return Err(PublishError::Archive(format!(
            "component {path:?} is not a WebAssembly binary"
        )));
    }
    Ok(bytes.clone())
}

fn canonical_wit_bytes(entries: &BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, PublishError> {
    let wit: Vec<(&String, &Vec<u8>)> = entries
        .iter()
        .filter(|(path, _)| path.as_str() == "wit" || path.starts_with("wit/"))
        .filter(|(_, bytes)| !bytes.is_empty())
        .collect();
    if wit.is_empty() {
        return Err(PublishError::Archive(
            "archive must contain at least one non-empty wit/ file".into(),
        ));
    }
    let mut bytes = WIT_DOMAIN.to_vec();
    put_u64(&mut bytes, wit.len() as u64);
    for (path, content) in wit {
        put_text(&mut bytes, path);
        put_u64(&mut bytes, content.len() as u64);
        bytes.extend_from_slice(content);
    }
    Ok(bytes)
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_text(bytes: &mut Vec<u8>, value: &str) {
    put_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

fn put_digest(bytes: &mut Vec<u8>, digest: &Digest) {
    put_text(bytes, &digest.to_string());
}

/// Serialize a prepared publication in the same shape as its output file.
///
/// # Errors
///
/// Returns an error if the typed record cannot be serialized.
pub fn canonical_json(prepared: &PreparedPublication) -> Result<String, PublishError> {
    Ok(serde_json::to_string_pretty(&prepared.record)? + "\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_capsule_index::{ActorId, GitObjectId};
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Cursor;
    use tar::Builder;

    fn digest(seed: u8) -> Digest {
        Digest::blake3(&[seed; 3])
    }

    fn archive(path: &Path, publish: bool, component: &[u8]) {
        let file = File::create(path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        let manifest = format!(
            "[package]\nname = \"demo\"\nversion = \"1.2.3\"\nastrid-version = \"^0.10\"\nrepository = \"https://example.com/repo\"\npublish = {publish}\n\n[[component]]\nfile = \"demo.wasm\"\n\n[capabilities]\nnet = [\"example.com\"]\n\n[imports.astrid]\nfoo = \"^1.0\"\n\n[publish]\n\"demo/events\" = \"opaque\"\n"
        );
        for (name, bytes) in [
            ("Capsule.toml", manifest.as_bytes()),
            ("demo.wasm", component),
            ("wit/demo.wit", b"package demo:demo;".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, name, Cursor::new(bytes))
                .unwrap();
        }
        builder.into_inner().unwrap().finish().unwrap();
    }

    fn options(artifact: &Path, output: &Path) -> PublishOptions {
        let index_id = IndexId::new("public").unwrap();
        let coordinate = Coordinate::new(
            Namespace::new("demo").unwrap(),
            CapsuleName::new("demo").unwrap(),
        );
        PublishOptions::new(
            artifact,
            index_id,
            MirrorUrl::new("https://index.example/releases").unwrap(),
            coordinate,
            CanonicalSemVer::parse("1.2.3").unwrap(),
            vec![MirrorUrl::new("https://index.example/artifacts/demo.capsule").unwrap()],
            PublisherIdentity::new(ActorId::new("did:example:publisher").unwrap(), digest(1)),
            SourceProvenance::new(
                MirrorUrl::new("https://example.com/repo").unwrap(),
                1,
                2,
                GitObjectId::new("a".repeat(40)).unwrap(),
                GitObjectId::new("b".repeat(40)).unwrap(),
                "v1.2.3",
                None,
                digest(2),
            )
            .unwrap(),
            BuildProvenance::new(
                "https://slsa.dev/provenance/v1",
                digest(3),
                MirrorUrl::new("https://builder.example/id").unwrap(),
                "attestation-1",
            )
            .unwrap(),
            "^0.10",
            "component-model-v1",
            output,
        )
    }

    #[test]
    fn prepares_and_classifies_idempotence_and_tamper() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = temp.path().join("demo.capsule");
        archive(&artifact, true, b"\0asm\x01\0\0\0");
        let output = temp.path().join("out");
        let options = options(&artifact, &output);
        let first = prepare(&options, &EmptyPreflight).unwrap();
        assert_eq!(first.classification(), PublicationClassification::New);
        write_submission(&first).unwrap();
        let second = prepare(&options, &FilePreflight::new(&output)).unwrap();
        assert_eq!(
            second.classification(),
            PublicationClassification::Idempotent
        );

        archive(&artifact, true, b"\0asm\x01\0\0\x01");
        let err = prepare(&options, &FilePreflight::new(&output)).unwrap_err();
        assert!(matches!(err, PublishError::Equivocation(_)));
    }

    #[test]
    fn publish_false_is_rejected_before_claim_derivation() {
        let temp = tempfile::tempdir().unwrap();
        let artifact = temp.path().join("demo.capsule");
        archive(&artifact, false, b"\0asm\x01\0\0\0");
        let err = prepare(
            &options(&artifact, &temp.path().join("out")),
            &EmptyPreflight,
        )
        .unwrap_err();
        assert!(err.to_string().contains("publish = false"));
    }

    #[test]
    fn archive_limits_fail_before_materializing_entries() {
        let temp = tempfile::tempdir().unwrap();
        let oversized = temp.path().join("oversized.capsule");
        let file = File::create(&oversized).unwrap();
        file.set_len(MAX_ARCHIVE_BYTES + 1).unwrap();
        let err = read_capsule_entries(&oversized).unwrap_err();
        assert!(err.to_string().contains("compressed archive"));

        let entry_archive = temp.path().join("entry-limit.capsule");
        let file = File::create(&entry_archive).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(MAX_ARCHIVE_ENTRY_BYTES + 1);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "too-large", Cursor::new(Vec::<u8>::new()))
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap();
        let err = read_capsule_entries(&entry_archive).unwrap_err();
        assert!(err.to_string().contains("archive entry"));
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_output_parent_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let artifact = temp.path().join("demo.capsule");
        archive(&artifact, true, b"\0asm\x01\0\0\0");
        let output = temp.path().join("out");
        let target = temp.path().join("target");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&output).unwrap();
        symlink(&target, output.join("records")).unwrap();
        let prepared = prepare(&options(&artifact, &output), &EmptyPreflight).unwrap();
        let err = write_submission(&prepared).unwrap_err();
        assert!(err.to_string().contains("symlink"));
    }
}
