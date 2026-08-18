//! Repository-side validation and deterministic read-plane generation for a
//! Capsule Index.
//!
//! The protocol crate (`astrid-capsule-index`) owns the typed publication and
//! lifecycle model.  This crate deliberately keeps the repository boundary
//! hostile: it treats files as untrusted input, computes all digests itself,
//! rejects aliases and mutable history, and emits only canonical objects.

use astrid_capsule_index::{
    EventAuthorization, EventAuthorizationVerifier, EventBody, EventEnvelope, IndexError,
    IndexEvent as ProtocolIndexEvent, IndexEventKind as ProtocolIndexEventKind, IndexId,
    IndexIdentity, IndexLedger, IndexResult, NamespaceClaim as ProtocolNamespaceClaim,
    PublicationRecord as ProtocolPublicationRecord,
};
use astrid_capsule_index_tuf::{TrustConfig, VerificationMode, load as load_verified_index};
use jiff::Timestamp;
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Write};
use std::num::NonZeroU64;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use tempfile::Builder;
use thiserror::Error;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::{RoleType, Root, Signed, Target};
use tough::{FilesystemTransport, TargetName};
use url::Url;

/// Maximum accepted input file size.  Capsule artifacts themselves are not
/// copied by this tool; repository metadata must remain small enough to scan
/// safely in CI.
pub const DEFAULT_MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;
/// The read plane always emits every identity shard, including empty shards.
pub const IDENTITY_SHARD_COUNT: usize = 256;

const DEFAULT_INDEX_ID: &str = "astrid";
const RELEASE_ROOTS: &[&str] = &["records", "releases", "release-records", "packages"];
const IMMUTABLE_KINDS: &[EntryKind] = &[EntryKind::Release, EntryKind::Event, EntryKind::Namespace];

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("{path}: {message}")]
    Repository { path: String, message: String },
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{path}: invalid JSON: {source}")]
    Json {
        path: String,
        source: serde_json::Error,
    },
    #[error("{path}: {message}")]
    Invalid { path: String, message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: String,
    pub severity: DiagnosticSeverity,
    pub path: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coordinate: Option<String>,
}

impl Diagnostic {
    fn error(code: &str, path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.to_owned(),
            severity: DiagnosticSeverity::Error,
            path: path.into(),
            message: message.into(),
            coordinate: None,
        }
    }

    fn coordinate_error(
        code: &str,
        path: impl Into<String>,
        coordinate: &Coordinate,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code: code.to_owned(),
            severity: DiagnosticSeverity::Error,
            path: path.into(),
            message: message.into(),
            coordinate: Some(coordinate.display()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcome {
    Accepted,
    Idempotent,
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationReport {
    pub outcome: ValidationOutcome,
    pub diagnostics: Vec<Diagnostic>,
    pub new_releases: usize,
    pub idempotent_releases: usize,
    pub new_events: usize,
}

impl ValidationReport {
    fn rejected(diagnostics: Vec<Diagnostic>) -> Self {
        Self {
            outcome: ValidationOutcome::Rejected,
            diagnostics,
            new_releases: 0,
            idempotent_releases: 0,
            new_events: 0,
        }
    }

    fn sort_diagnostics(&mut self) {
        self.diagnostics.sort_by(|a, b| {
            a.path
                .cmp(&b.path)
                .then_with(|| a.code.cmp(&b.code))
                .then_with(|| a.message.cmp(&b.message))
        });
    }

    /// A machine-readable report suitable for CI logs.
    ///
    /// # Errors
    ///
    /// Returns a serialization error only if the report contains a value that
    /// `serde_json` cannot encode.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

#[derive(Clone)]
pub struct ValidationConfig {
    /// The repository's independent Index identity.  A record carrying a
    /// different identity is a cross-index collision, never a valid alias.
    pub index_id: String,
    pub max_file_bytes: u64,
    /// Detached authorization verifier supplied by the index/TUF boundary.
    /// The repository tool fails closed for authoritative events when this is
    /// absent; evidence references are never treated as signatures here.
    pub authorization_verifier: Option<Arc<dyn EventAuthorizationVerifier + Send + Sync>>,
}

/// Explicit review-evidence verifier suitable for curator-reviewed PRs.
///
/// This policy binds each authorization's digest to the UTF-8 bytes of its
/// evidence reference and recursively checks all three authorizations on a
/// namespace transfer.  It is deliberately not a publisher signature scheme:
/// protected curator review plus the later TUF role signatures remain the
/// deployment authority.
#[derive(Debug, Clone, Copy, Default)]
pub struct CuratorReviewVerifier;

impl EventAuthorizationVerifier for CuratorReviewVerifier {
    fn verify(&self, envelope: &EventEnvelope) -> IndexResult<()> {
        verify_curator_authorization(envelope.authorization())?;
        if let EventBody::NamespaceTransfer(transfer) = envelope.body() {
            verify_curator_authorization(transfer.outgoing_authorization())?;
            verify_curator_authorization(transfer.incoming_acceptance())?;
            verify_curator_authorization(transfer.index_review_authorization())?;
        }
        Ok(())
    }
}

fn verify_curator_authorization(authorization: &EventAuthorization) -> IndexResult<()> {
    let expected = astrid_capsule_index::Digest::blake3(authorization.evidence().as_bytes());
    if expected != *authorization.signature_digest() {
        return Err(IndexError::InvalidEvent(
            "curator review evidence digest does not match its reference bytes",
        ));
    }
    Ok(())
}

impl std::fmt::Debug for ValidationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidationConfig")
            .field("index_id", &self.index_id)
            .field("max_file_bytes", &self.max_file_bytes)
            .field(
                "authorization_verifier",
                &self.authorization_verifier.as_ref().map(|_| "configured"),
            )
            .finish()
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            index_id: DEFAULT_INDEX_ID.to_owned(),
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            authorization_verifier: None,
        }
    }
}

impl ValidationConfig {
    #[must_use]
    pub fn with_index_id(mut self, index_id: impl Into<String>) -> Self {
        self.index_id = index_id.into();
        self
    }

    #[must_use]
    pub fn with_max_file_bytes(mut self, max_file_bytes: u64) -> Self {
        self.max_file_bytes = max_file_bytes;
        self
    }

    /// Supplies the detached event-authorization verifier used by repository
    /// validation and generation.  The verifier should bind evidence bytes to
    /// the namespace claim's signing identity and reject unknown/invalid
    /// signatures; this crate intentionally does not implement that crypto.
    #[must_use]
    pub fn with_authorization_verifier<V>(mut self, verifier: V) -> Self
    where
        V: EventAuthorizationVerifier + Send + Sync + 'static,
    {
        self.authorization_verifier = Some(Arc::new(verifier));
        self
    }

    /// Alias for [`ValidationConfig::with_authorization_verifier`].
    #[must_use]
    pub fn with_event_verifier<V>(self, verifier: V) -> Self
    where
        V: EventAuthorizationVerifier + Send + Sync + 'static,
    {
        self.with_authorization_verifier(verifier)
    }

    /// Enables the explicit curator-review evidence policy for CLI-style
    /// repository validation.  This is a digest-bound review receipt, not a
    /// cryptographic publisher signature.
    #[must_use]
    pub fn with_curator_review_verifier(self) -> Self {
        self.with_authorization_verifier(CuratorReviewVerifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Coordinate {
    pub index_id: String,
    pub namespace: String,
    pub name: String,
    pub version: String,
}

impl Coordinate {
    #[must_use]
    pub fn display(&self) -> String {
        format!(
            "{}:{}/{}@{}",
            self.index_id, self.namespace, self.name, self.version
        )
    }

    #[must_use]
    pub fn identity(&self) -> String {
        format!("@{}/{}@{}", self.namespace, self.name, self.version)
    }
}

impl Ord for Coordinate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.index_id
            .cmp(&other.index_id)
            .then_with(|| self.namespace.cmp(&other.namespace))
            .then_with(|| self.name.cmp(&other.name))
            .then_with(|| {
                Version::parse(&self.version)
                    .ok()
                    .cmp(&Version::parse(&other.version).ok())
            })
            .then_with(|| self.version.cmp(&other.version))
    }
}

impl PartialOrd for Coordinate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum EntryKind {
    Release,
    Event,
    Namespace,
    Metadata,
    Other,
}

#[derive(Debug, Clone)]
struct RepoFile {
    path: String,
    bytes: Vec<u8>,
    kind: EntryKind,
}

#[derive(Debug, Clone)]
struct ReleaseRecord {
    file: RepoFile,
    protocol: ProtocolPublicationRecord,
    coordinate: Coordinate,
    publication_digest: String,
    canonical: Vec<u8>,
}

#[derive(Debug, Clone)]
struct NamespaceClaim {
    file: RepoFile,
    namespace: String,
    protocol: ProtocolNamespaceClaim,
}

#[derive(Debug, Clone)]
struct IndexEvent {
    file: RepoFile,
    envelope: EventEnvelope,
    protocol: Option<ProtocolIndexEvent>,
    kind: String,
    target: EventTarget,
    sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum EventTarget {
    Release(Coordinate),
    Namespace(String),
}

impl EventTarget {
    fn display(&self) -> String {
        match self {
            Self::Release(coordinate) => coordinate.display(),
            Self::Namespace(namespace) => format!("namespace:{namespace}"),
        }
    }
}

#[derive(Debug, Clone)]
struct Repository {
    files: BTreeMap<String, RepoFile>,
    releases: BTreeMap<Coordinate, ReleaseRecord>,
    namespaces: BTreeMap<String, NamespaceClaim>,
    events: BTreeMap<String, IndexEvent>,
    index_id: String,
    parse_diagnostics: Vec<Diagnostic>,
    event_identity: Option<IndexIdentity>,
}

/// Validate a candidate repository against an accepted base tree.
///
/// # Errors
///
/// Returns a repository error when a tree cannot be safely scanned.  Content
/// and policy failures are returned as structured diagnostics in the report.
pub fn validate_trees(
    base: &Path,
    candidate: &Path,
    config: &ValidationConfig,
) -> Result<ValidationReport, ToolError> {
    let base_scan = scan_repository(base, config)?;
    let candidate_scan = scan_repository(candidate, config)?;
    let mut diagnostics = Vec::new();

    diagnostics.extend(base_scan.parse_diagnostics.clone());
    diagnostics.extend(candidate_scan.parse_diagnostics.clone());
    if base_scan
        .event_identity
        .as_ref()
        .zip(candidate_scan.event_identity.as_ref())
        .is_some_and(|(base, candidate)| base != candidate)
    {
        diagnostics.push(Diagnostic::error(
            "CROSS_INDEX_COLLISION",
            "events",
            "candidate event history is bound to a different trust-root identity",
        ));
    }
    validate_repository_shape(&base_scan, config, &mut diagnostics);
    validate_repository_shape(&candidate_scan, config, &mut diagnostics);
    compare_append_only(&base_scan, &candidate_scan, &mut diagnostics);
    validate_event_ledger(&candidate_scan, config, &mut diagnostics);
    validate_aliases(&candidate_scan, &mut diagnostics);

    let mut report = if diagnostics
        .iter()
        .any(|d| d.severity == DiagnosticSeverity::Error)
    {
        ValidationReport::rejected(diagnostics)
    } else {
        let base_coords: BTreeSet<_> = base_scan.releases.keys().cloned().collect();
        let candidate_coords: BTreeSet<_> = candidate_scan.releases.keys().cloned().collect();
        let new_releases = candidate_coords.difference(&base_coords).count();
        let idempotent_releases = candidate_coords
            .intersection(&base_coords)
            .filter(|coordinate| {
                base_scan
                    .releases
                    .get(*coordinate)
                    .zip(candidate_scan.releases.get(*coordinate))
                    .is_some_and(|(a, b)| a.canonical == b.canonical)
            })
            .count();
        let new_events = candidate_scan
            .events
            .keys()
            .filter(|path| !base_scan.events.contains_key(*path))
            .count();
        let outcome = if new_releases == 0 && new_events == 0 {
            ValidationOutcome::Idempotent
        } else {
            ValidationOutcome::Accepted
        };
        ValidationReport {
            outcome,
            diagnostics,
            new_releases,
            idempotent_releases,
            new_events,
        }
    };
    report.sort_diagnostics();
    Ok(report)
}

/// Validate one repository against itself.  This is useful before generation
/// and catches duplicate coordinates, malformed events, aliases, and unsafe
/// files without requiring an accepted base checkout.
///
/// # Errors
///
/// Returns a repository error when the tree cannot be safely scanned.
pub fn validate_repository(
    repository: &Path,
    config: &ValidationConfig,
) -> Result<ValidationReport, ToolError> {
    validate_trees(repository, repository, config)
}

/// Short alias used by integrations that call the host validator directly.
///
/// # Errors
///
/// See [`validate_trees`].
pub fn validate(
    base: &Path,
    candidate: &Path,
    config: &ValidationConfig,
) -> Result<ValidationReport, ToolError> {
    validate_trees(base, candidate, config)
}

fn scan_repository(root: &Path, config: &ValidationConfig) -> Result<Repository, ToolError> {
    let files = scan_tree(root, config.max_file_bytes)?;
    let index_id = read_index_id(&files, config)?;
    let mut releases = BTreeMap::new();
    let mut namespaces = BTreeMap::new();
    let mut events = BTreeMap::new();
    let mut diagnostics = Vec::new();
    let mut event_identity = None;

    for file in files.values() {
        match file.kind {
            EntryKind::Release => match parse_release(file, &index_id) {
                Ok(record) => {
                    if releases.insert(record.coordinate.clone(), record).is_some() {
                        diagnostics.push(Diagnostic::error(
                            "DUPLICATE_COORDINATE",
                            &file.path,
                            "more than one release record claims the same canonical coordinate",
                        ));
                    }
                },
                Err(diag) => diagnostics.push(diag),
            },
            EntryKind::Namespace => match parse_namespace(file, &index_id) {
                Ok(claim) => {
                    if namespaces.insert(claim.namespace.clone(), claim).is_some() {
                        diagnostics.push(Diagnostic::error(
                            "DUPLICATE_NAMESPACE",
                            &file.path,
                            "more than one namespace claim exists",
                        ));
                    }
                },
                Err(diag) => diagnostics.push(diag),
            },
            EntryKind::Event => match parse_event(file, &index_id) {
                Ok(event) => {
                    if let Some(identity) = &event_identity {
                        if identity != event.envelope.index() {
                            diagnostics.push(Diagnostic::error(
                                "CROSS_INDEX_COLLISION",
                                &file.path,
                                "event envelope is bound to a different index trust identity",
                            ));
                        }
                    } else {
                        event_identity = Some(event.envelope.index().clone());
                    }
                    if events.insert(file.path.clone(), event).is_some() {
                        diagnostics.push(Diagnostic::error(
                            "DUPLICATE_EVENT_PATH",
                            &file.path,
                            "duplicate event path",
                        ));
                    }
                },
                Err(diag) => diagnostics.push(diag),
            },
            EntryKind::Metadata | EntryKind::Other => {},
        }
    }

    Ok(Repository {
        files,
        releases,
        namespaces,
        events,
        index_id,
        parse_diagnostics: diagnostics,
        event_identity,
    })
}

fn scan_tree(root: &Path, max_file_bytes: u64) -> Result<BTreeMap<String, RepoFile>, ToolError> {
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.is_dir() {
        return Err(ToolError::Repository {
            path: root.display().to_string(),
            message: "repository root is not a directory".to_owned(),
        });
    }
    if metadata.file_type().is_symlink() {
        return Err(ToolError::Repository {
            path: root.display().to_string(),
            message: "repository root may not be a symlink".to_owned(),
        });
    }

    let mut files = BTreeMap::new();
    scan_dir(root, root, max_file_bytes, &mut files)?;
    Ok(files)
}

fn scan_dir(
    root: &Path,
    directory: &Path,
    max_file_bytes: u64,
    files: &mut BTreeMap<String, RepoFile>,
) -> Result<(), ToolError> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, io::Error>>()?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|_| ToolError::Repository {
            path: path.display().to_string(),
            message: "path escaped repository root".to_owned(),
        })?;
        validate_relative_path(relative)?;
        let relative_string = relative
            .to_str()
            .ok_or_else(|| ToolError::Repository {
                path: path.display().to_string(),
                message: "non-UTF-8 paths are not valid repository identities".to_owned(),
            })?
            .replace(std::path::MAIN_SEPARATOR, "/");
        // A GitHub checkout carries VCS metadata that is not part of the
        // signed repository object graph.  Ignore it before inspecting the
        // entry type (worktrees commonly represent `.git` as a file).
        if relative
            .components()
            .next()
            .is_some_and(|component| matches!(component, Component::Normal(value) if value == OsStr::new(".git")))
        {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(ToolError::Repository {
                path: relative_string,
                message: "symlinks are not allowed in an Index repository".to_owned(),
            });
        }
        if metadata.is_dir() {
            scan_dir(root, &path, max_file_bytes, files)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(ToolError::Repository {
                path: relative_string,
                message: "special files are not allowed in an Index repository".to_owned(),
            });
        }
        if metadata.len() > max_file_bytes {
            return Err(ToolError::Repository {
                path: relative_string,
                message: format!(
                    "file is {} bytes, exceeding the {} byte limit",
                    metadata.len(),
                    max_file_bytes
                ),
            });
        }
        let bytes = fs::read(&path)?;
        let kind = classify_path(&relative_string);
        files.insert(
            relative_string.clone(),
            RepoFile {
                path: relative_string,
                bytes,
                kind,
            },
        );
    }
    Ok(())
}

fn validate_relative_path(path: &Path) -> Result<(), ToolError> {
    if path.is_absolute() {
        return Err(ToolError::Repository {
            path: path.display().to_string(),
            message: "absolute paths are not valid repository entries".to_owned(),
        });
    }
    for component in path.components() {
        match component {
            Component::Normal(value) if value != OsStr::new("") => {},
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => {
                return Err(ToolError::Repository {
                    path: path.display().to_string(),
                    message: "path traversal or non-normal component".to_owned(),
                });
            },
            Component::Normal(_) => {
                return Err(ToolError::Repository {
                    path: path.display().to_string(),
                    message: "empty path component".to_owned(),
                });
            },
        }
    }
    Ok(())
}

fn classify_path(path: &str) -> EntryKind {
    let components: Vec<_> = path.split('/').collect();
    if path == "index.json" || path == ".index.json" {
        return EntryKind::Metadata;
    }
    if components.first().is_some_and(|root| *root == "events")
        && has_json_extension(path)
        && components.len() == 2
    {
        return EntryKind::Event;
    }
    if components.first().is_some_and(|root| *root == "namespaces")
        && has_json_extension(path)
        && components.len() == 2
    {
        return EntryKind::Namespace;
    }
    if components.len() == 4
        && RELEASE_ROOTS.contains(&components[0])
        && has_json_extension(components[3])
    {
        return EntryKind::Release;
    }
    EntryKind::Other
}

fn has_json_extension(path: &str) -> bool {
    Path::new(path)
        .extension()
        .is_some_and(|extension| extension == OsStr::new("json"))
}

fn read_index_id(
    files: &BTreeMap<String, RepoFile>,
    config: &ValidationConfig,
) -> Result<String, ToolError> {
    let mut index_id = config.index_id.clone();
    if let Some(file) = files.get("index.json").or_else(|| files.get(".index.json")) {
        let value = parse_json(file)?;
        if let Some(value) = value.get("index_id").and_then(Value::as_str) {
            value.clone_into(&mut index_id);
        } else if let Some(value) = value.get("id").and_then(Value::as_str) {
            value.clone_into(&mut index_id);
        }
    }
    if !valid_ascii_identifier(&index_id, false) {
        return Err(ToolError::Invalid {
            path: "index.json".to_owned(),
            message: format!("invalid Index ID `{index_id}`"),
        });
    }
    Ok(index_id)
}

fn parse_json(file: &RepoFile) -> Result<Value, ToolError> {
    serde_json::from_slice(&file.bytes).map_err(|source| ToolError::Json {
        path: file.path.clone(),
        source,
    })
}

fn parse_release(file: &RepoFile, index_id: &str) -> Result<ReleaseRecord, Diagnostic> {
    let object = parse_json(file)
        .map_err(|error| Diagnostic::error("INVALID_JSON", &file.path, error.to_string()))?;
    validate_release_shape(&object, &file.path)?;
    let protocol =
        serde_json::from_slice::<ProtocolPublicationRecord>(&file.bytes).map_err(|error| {
            Diagnostic::error(
                "INVALID_RELEASE_SCHEMA",
                &file.path,
                format!("release record must be a sealed PublicationRecord: {error}"),
            )
        })?;
    let protocol_index = protocol.index_id().to_string();
    if protocol_index != index_id {
        return Err(Diagnostic::error(
            "CROSS_INDEX_COLLISION",
            &file.path,
            format!("record belongs to Index `{protocol_index}`, expected `{index_id}`"),
        ));
    }
    let coordinate = Coordinate {
        index_id: protocol_index,
        namespace: protocol.coordinate().namespace.to_string(),
        name: protocol.coordinate().name.to_string(),
        version: protocol.version().to_string(),
    };
    validate_identifier(&coordinate.namespace, "namespace", &file.path)?;
    validate_identifier(&coordinate.name, "capsule name", &file.path)?;
    if let Some(path_coordinate) = coordinate_from_path(&file.path, index_id)
        && path_coordinate != coordinate
    {
        return Err(Diagnostic::coordinate_error(
            "PATH_IDENTITY_MISMATCH",
            &file.path,
            &coordinate,
            format!(
                "path encodes {}, record encodes {}",
                path_coordinate.display(),
                coordinate.display()
            ),
        ));
    }
    let canonical = canonical_json_bytes(&object)
        .map_err(|message| Diagnostic::error("NON_CANONICAL_JSON", &file.path, message))?;
    let publication_digest = protocol.publication_digest().to_string();
    Ok(ReleaseRecord {
        file: file.clone(),
        protocol,
        coordinate,
        publication_digest,
        canonical,
    })
}

#[allow(clippy::too_many_lines)]
fn validate_release_shape(object: &Value, path: &str) -> Result<(), Diagnostic> {
    ensure_known_keys(
        object,
        &[
            "schema",
            "index_id",
            "coordinate",
            "version",
            "artifact",
            "package",
            "publisher",
            "source",
            "provenance",
            "metadata",
            "publication_digest",
        ],
        path,
    )?;
    for (field, allowed) in [
        ("coordinate", &["namespace", "name"][..]),
        (
            "artifact",
            &["digests", "size", "media_type", "locations"][..],
        ),
        (
            "package",
            &[
                "embedded_identity",
                "manifest_digest",
                "component_digest",
                "wit_digest",
                "capability_digest",
                "ipc_digest",
                "runtime_abi_digest",
                "dependency_digest",
                "capabilities",
                "dependencies",
                "runtime",
            ][..],
        ),
        ("publisher", &["identity", "signing_key"][..]),
        (
            "source",
            &[
                "repository_url",
                "github_owner_id",
                "github_repository_id",
                "commit",
                "tree",
                "tag",
                "subdirectory",
                "source_digest",
            ][..],
        ),
        (
            "provenance",
            &[
                "predicate_type",
                "statement_digest",
                "builder_identity",
                "attestation_identity",
            ][..],
        ),
        ("metadata", &[][..]),
    ] {
        if let Some(value) = object.get(field) {
            ensure_known_keys(value, allowed, &format!("{path}:{field}"))?;
        }
    }
    if let Some(package) = object.get("package")
        && let Some(embedded) = package.get("embedded_identity")
    {
        ensure_known_keys(
            embedded,
            &["coordinate", "version", "package_digest"],
            &format!("{path}:package.embedded_identity"),
        )?;
        if let Some(coordinate) = embedded.get("coordinate") {
            ensure_known_keys(
                coordinate,
                &["namespace", "name"],
                &format!("{path}:package.embedded_identity.coordinate"),
            )?;
        }
    }
    if let Some(package) = object.get("package")
        && let Some(runtime) = package.get("runtime")
    {
        ensure_known_keys(
            runtime,
            &["runtime", "abi", "digest"],
            &format!("{path}:package.runtime"),
        )?;
    }
    if let Some(package) = object.get("package")
        && let Some(dependencies) = package.get("dependencies").and_then(Value::as_array)
    {
        for (index, dependency) in dependencies.iter().enumerate() {
            ensure_known_keys(
                dependency,
                &["coordinate", "requirement", "optional"],
                &format!("{path}:package.dependencies[{index}]"),
            )?;
            if let Some(coordinate) = dependency.get("coordinate") {
                ensure_known_keys(
                    coordinate,
                    &["namespace", "name"],
                    &format!("{path}:package.dependencies[{index}].coordinate"),
                )?;
            }
        }
    }
    Ok(())
}

fn ensure_known_keys(value: &Value, allowed: &[&str], path: &str) -> Result<(), Diagnostic> {
    let Some(object) = value.as_object() else {
        return Err(Diagnostic::error(
            "INVALID_RELEASE_SCHEMA",
            path,
            "typed record field must be a JSON object",
        ));
    };
    if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(Diagnostic::error(
            "INVALID_RELEASE_SCHEMA",
            path,
            format!("unknown field `{unknown}` is not part of the normative typed schema"),
        ));
    }
    Ok(())
}

fn parse_namespace(file: &RepoFile, index_id: &str) -> Result<NamespaceClaim, Diagnostic> {
    let object = parse_json(file)
        .map_err(|error| Diagnostic::error("INVALID_JSON", &file.path, error.to_string()))?;
    ensure_known_keys(
        &object,
        &[
            "namespace",
            "owner",
            "security_contact",
            "repository_url",
            "github_owner_id",
            "github_repository_id",
            "signing_identity",
            "license",
            "reserved_authority",
        ],
        &file.path,
    )?;
    let claim = serde_json::from_slice::<ProtocolNamespaceClaim>(&file.bytes).map_err(|error| {
        Diagnostic::error(
            "INVALID_NAMESPACE_SCHEMA",
            &file.path,
            format!("namespace claim must use the normative typed schema: {error}"),
        )
    })?;
    let namespace = validate_identifier(claim.namespace().as_str(), "namespace", &file.path)?;
    let file_namespace = Path::new(&file.path)
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or_default();
    if file_namespace != namespace {
        return Err(Diagnostic::error(
            "NAMESPACE_PATH_MISMATCH",
            &file.path,
            "namespace path must use the canonical lowercase namespace",
        ));
    }
    let expected_index = IndexId::new(index_id.to_owned()).map_err(|error| {
        Diagnostic::error(
            "INVALID_INDEX_ID",
            &file.path,
            format!("configured Index ID is invalid: {error}"),
        )
    })?;
    if let Err(error) = claim.validate_for_index(&expected_index) {
        return Err(Diagnostic::error(
            "CROSS_INDEX_COLLISION",
            &file.path,
            format!("namespace claim is not admitted by this Index: {error}"),
        ));
    }
    Ok(NamespaceClaim {
        file: file.clone(),
        namespace,
        protocol: claim,
    })
}

fn parse_event(file: &RepoFile, index_id: &str) -> Result<IndexEvent, Diagnostic> {
    let envelope = serde_json::from_slice::<EventEnvelope>(&file.bytes).map_err(|error| {
        Diagnostic::error(
            "INVALID_EVENT_SCHEMA",
            &file.path,
            format!(
                "authoritative repository events must be sealed EventEnvelope values (legacy or unsigned IndexEvent is migration input only): {error}"
            ),
        )
    })?;
    envelope.verify_digest().map_err(|error| {
        Diagnostic::error(
            "INVALID_EVENT_DIGEST",
            &file.path,
            format!("event envelope digest verification failed: {error}"),
        )
    })?;
    if envelope.index().id.as_str() != index_id {
        return Err(Diagnostic::error(
            "CROSS_INDEX_COLLISION",
            &file.path,
            "event envelope belongs to another Index",
        ));
    }
    let expected_path = canonical_event_path(&envelope);
    if file.path != expected_path {
        return Err(Diagnostic::error(
            "EVENT_PATH_IDENTITY",
            &file.path,
            format!("event path must be `{expected_path}` for its sequence and digest"),
        ));
    }
    let (protocol, kind, target) = match envelope.body() {
        EventBody::Publication(event) => {
            if let Some(message) = validate_event_payload(event) {
                return Err(Diagnostic::error(
                    "INVALID_EVENT_PAYLOAD",
                    &file.path,
                    message,
                ));
            }
            let publication = event.publication();
            let target = EventTarget::Release(Coordinate {
                index_id: publication.index_id.to_string(),
                namespace: publication.coordinate.namespace.to_string(),
                name: publication.coordinate.name.to_string(),
                version: publication.version.to_string(),
            });
            let kind = match event.kind() {
                ProtocolIndexEventKind::Yank => "yank",
                ProtocolIndexEventKind::Unyank => "unyank",
                ProtocolIndexEventKind::Deprecate => "deprecate",
                ProtocolIndexEventKind::Revoke => "revoke",
                ProtocolIndexEventKind::Tombstone => "tombstone",
                ProtocolIndexEventKind::OwnerChange => "owner_change",
                ProtocolIndexEventKind::AddMirror => "add_mirror",
                ProtocolIndexEventKind::AddAttestation => "add_attestation",
                ProtocolIndexEventKind::Annotation => "annotation",
            }
            .to_owned();
            (Some(event.clone()), kind, target)
        },
        EventBody::NamespaceTransfer(transfer) => (
            None,
            "namespace_transfer".to_owned(),
            EventTarget::Namespace(transfer.namespace().as_str().to_owned()),
        ),
    };
    let sequence = envelope.sequence();
    Ok(IndexEvent {
        file: file.clone(),
        envelope,
        protocol,
        kind,
        target,
        sequence,
    })
}

fn canonical_event_path(envelope: &EventEnvelope) -> String {
    format!(
        "events/{:020}-{}.json",
        envelope.sequence(),
        hex::encode(envelope.event_digest().as_bytes())
    )
}

fn validate_event_payload(event: &ProtocolIndexEvent) -> Option<String> {
    match event {
        ProtocolIndexEvent::Revoke { reason, .. }
        | ProtocolIndexEvent::Tombstone { reason, .. }
            if reason.trim().is_empty() =>
        {
            Some("reason is empty".to_owned())
        },
        ProtocolIndexEvent::Annotation { key, .. } if key.trim().is_empty() => {
            Some("annotation key is empty".to_owned())
        },
        ProtocolIndexEvent::Annotation { key, value, .. }
            if key.contains('\0') || value.contains('\0') =>
        {
            Some("annotation contains NUL".to_owned())
        },
        ProtocolIndexEvent::OwnerChange { from, to, .. } if from == to => {
            Some("owner does not change".to_owned())
        },
        _ => None,
    }
}

fn validate_repository_shape(
    repository: &Repository,
    config: &ValidationConfig,
    diagnostics: &mut Vec<Diagnostic>,
) {
    if repository.index_id != config.index_id {
        diagnostics.push(Diagnostic::error(
            "CROSS_INDEX_COLLISION",
            "index.json",
            format!(
                "repository Index ID `{}` does not match configured `{}`",
                repository.index_id, config.index_id
            ),
        ));
    }
    // Namespace claims are intentionally checked in parse_namespace.  Keep a
    // separate reserved namespace guard here so an otherwise valid record
    // cannot silently claim another authority's prefix.
    for namespace in repository.namespaces.keys().chain(
        repository
            .releases
            .values()
            .map(|r| &r.coordinate.namespace),
    ) {
        if (namespace == "astrid" && config.index_id != "astrid")
            || (namespace == "aos" && config.index_id != "aos")
        {
            diagnostics.push(Diagnostic::error(
                "RESERVED_NAMESPACE",
                namespace,
                format!("namespace `{namespace}` is reserved for its authority"),
            ));
        }
    }
    for file in repository.files.values() {
        let first = file.path.split('/').next().unwrap_or_default();
        if (RELEASE_ROOTS.contains(&first) || first == "events" || first == "namespaces")
            && file.kind == EntryKind::Other
        {
            diagnostics.push(Diagnostic::error(
                "UNAUTHORIZED_REPOSITORY_SHAPE",
                &file.path,
                "reserved repository directories contain an unrecognized path; use the canonical typed JSON layout",
            ));
        }
    }
}

fn compare_append_only(
    base: &Repository,
    candidate: &Repository,
    diagnostics: &mut Vec<Diagnostic>,
) {
    for (path, base_file) in &base.files {
        let Some(candidate_file) = candidate.files.get(path) else {
            if IMMUTABLE_KINDS.contains(&base_file.kind) {
                diagnostics.push(Diagnostic::error(
                    "APPEND_ONLY_DELETE",
                    path,
                    "accepted release, event, or namespace record cannot be deleted",
                ));
            }
            continue;
        };
        if base_file.kind == EntryKind::Release || base_file.kind == EntryKind::Event {
            if base_file.bytes != candidate_file.bytes {
                diagnostics.push(Diagnostic::error("APPEND_ONLY_EDIT", path, "accepted release records and events are immutable; corrections require a new version or event"));
            }
        } else if base_file.kind == EntryKind::Namespace && base_file.bytes != candidate_file.bytes
        {
            diagnostics.push(Diagnostic::error(
                "APPEND_ONLY_EDIT",
                path,
                "namespace claims are immutable; ownership changes are represented by a namespace transfer envelope",
            ));
        }
    }

    for (coordinate, candidate_record) in &candidate.releases {
        if let Some(base_record) = base.releases.get(coordinate) {
            if base_record.canonical == candidate_record.canonical {
                continue;
            }
            if base_record.publication_digest == candidate_record.publication_digest {
                diagnostics.push(Diagnostic::coordinate_error("APPEND_ONLY_EDIT", &candidate_record.file.path, coordinate, "same publication digest was submitted with changed release-record bytes; accepted records are byte immutable"));
            } else {
                diagnostics.push(Diagnostic::coordinate_error(
                    "EQUIVOCATION",
                    &candidate_record.file.path,
                    coordinate,
                    "same coordinate has a different publication digest",
                ));
            }
        }
    }

    // Detect two independently authored files that normalize to one identity.
    // parse_release already rejects malformed case/Unicode names; this catches
    // duplicate canonical coordinates represented by different directory roots.
    let mut paths_by_coordinate: HashMap<Coordinate, Vec<String>> = HashMap::new();
    for record in candidate.releases.values() {
        paths_by_coordinate
            .entry(record.coordinate.clone())
            .or_default()
            .push(record.file.path.clone());
    }
    for (coordinate, mut paths) in paths_by_coordinate {
        paths.sort();
        if paths.len() > 1 {
            diagnostics.push(Diagnostic::coordinate_error(
                "DUPLICATE_COORDINATE",
                paths.join(", "),
                &coordinate,
                "concurrent or duplicate claims normalize to the same coordinate",
            ));
        }
    }
}

fn validate_aliases(repository: &Repository, diagnostics: &mut Vec<Diagnostic>) {
    let mut identities = HashMap::<String, String>::new();
    for record in repository.releases.values() {
        let identity = record.coordinate.identity();
        if let Some(previous) = identities.insert(identity.clone(), record.file.path.clone())
            && previous != record.file.path
        {
            diagnostics.push(Diagnostic::error(
                "IDENTITY_ALIAS",
                record.file.path.clone(),
                format!("identity `{identity}` is already represented by `{previous}`"),
            ));
        }
    }
}

fn validate_event_ledger(
    repository: &Repository,
    config: &ValidationConfig,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(identity) = repository.event_identity.clone() else {
        // There is no event history.  Namespace claims and release records
        // are still checked by their typed parsers; a ledger is only needed
        // once an authoritative envelope exists.
        return;
    };
    let mut ledger = seed_event_ledger(repository, identity, diagnostics);
    let mut events: Vec<&IndexEvent> = repository.events.values().collect();
    events.sort_by(|a, b| {
        a.sequence
            .cmp(&b.sequence)
            .then_with(|| a.file.path.cmp(&b.file.path))
    });
    let release_targets: HashSet<_> = repository
        .releases
        .keys()
        .cloned()
        .map(EventTarget::Release)
        .collect();
    let namespace_targets: HashSet<_> = repository
        .namespaces
        .keys()
        .cloned()
        .map(EventTarget::Namespace)
        .collect();
    for event in events {
        validate_one_event(
            event,
            &mut ledger,
            config,
            &release_targets,
            &namespace_targets,
            diagnostics,
        );
    }
}

fn seed_event_ledger(
    repository: &Repository,
    identity: IndexIdentity,
    diagnostics: &mut Vec<Diagnostic>,
) -> IndexLedger {
    let mut ledger = IndexLedger::new(identity);
    for claim in repository.namespaces.values() {
        if let Err(error) = ledger.register_namespace_claim(claim.protocol.clone()) {
            diagnostics.push(Diagnostic::error(
                "UNAUTHORIZED_NAMESPACE",
                &claim.file.path,
                format!("namespace claim is not admissible: {error}"),
            ));
        }
    }
    for release in repository.releases.values() {
        if let Err(error) = ledger.publish(release.protocol.clone()) {
            diagnostics.push(Diagnostic::coordinate_error(
                "INVALID_RELEASE_LEDGER",
                &release.file.path,
                &release.coordinate,
                format!("release cannot be admitted to the event ledger: {error}"),
            ));
        }
    }
    ledger
}

fn validate_one_event(
    event: &IndexEvent,
    ledger: &mut IndexLedger,
    config: &ValidationConfig,
    release_targets: &HashSet<EventTarget>,
    namespace_targets: &HashSet<EventTarget>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(verifier) = config.authorization_verifier.as_deref() else {
        diagnostics.push(Diagnostic::error(
            "AUTH_VERIFIER_REQUIRED",
            &event.file.path,
            "authoritative event authorization cannot be accepted without a supplied verifier",
        ));
        return;
    };
    if let Err(error) = event.envelope.verify_authorization(verifier) {
        diagnostics.push(Diagnostic::error(
            "UNAUTHORIZED_EVENT",
            &event.file.path,
            format!("event authorization verification failed: {error}"),
        ));
        return;
    }
    if matches!(event.target, EventTarget::Release(_)) && !release_targets.contains(&event.target) {
        diagnostics.push(Diagnostic::error(
            "STALE_EVENT_TARGET",
            &event.file.path,
            format!(
                "event targets a release that is not present: {}",
                event.target.display()
            ),
        ));
        return;
    }
    if matches!(event.target, EventTarget::Namespace(_))
        && !namespace_targets.contains(&event.target)
    {
        diagnostics.push(Diagnostic::error(
            "STALE_NAMESPACE_TARGET",
            &event.file.path,
            format!(
                "transfer targets a namespace that is not claimed: {}",
                event.target.display()
            ),
        ));
        return;
    }
    if let EventBody::Publication(publication) = event.envelope.body()
        && let Some(current_owner) = ledger.owner(publication.publication())
        && current_owner != publication.actor()
    {
        diagnostics.push(Diagnostic::error(
            "UNAUTHORIZED_EVENT",
            &event.file.path,
            format!(
                "event actor `{}` is not the current publication owner `{}`",
                publication.actor().as_str(),
                current_owner.as_str()
            ),
        ));
        return;
    }
    if let Err(error) = ledger.append_envelope(event.envelope.clone()) {
        diagnostics.push(Diagnostic::error(
            event_error_code(&error),
            &event.file.path,
            format!(
                "cannot append event envelope at sequence {}: {error}",
                event.sequence
            ),
        ));
    }
}

fn event_error_code(error: &IndexError) -> &'static str {
    let message = error.to_string();
    if message.contains("sequence") {
        "EVENT_SEQUENCE"
    } else if message.contains("prior") || message.contains("chain") {
        "EVENT_CHAIN"
    } else if message.contains("owner") || message.contains("authorization") {
        "UNAUTHORIZED_EVENT"
    } else if message.contains("unknown publication") {
        "STALE_EVENT_TARGET"
    } else if message.contains("namespace") {
        "UNAUTHORIZED_NAMESPACE"
    } else {
        "INVALID_EVENT_TRANSITION"
    }
}

/// Generate a deterministic sparse Pages tree.  The output path must not
/// already exist; a temporary sibling is populated and renamed into place so
/// readers observe either the old tree or the complete new tree.
///
/// # Errors
///
/// Returns a repository error for unsafe input/output paths or filesystem
/// failures, and a structured validation failure when input records are not
/// acceptable.
#[allow(clippy::too_many_lines)]
pub fn generate_pages(
    repository: &Path,
    output: &Path,
    config: &ValidationConfig,
) -> Result<GenerationReport, ToolError> {
    let scanned = scan_repository(repository, config)?;
    let mut diagnostics = scanned.parse_diagnostics.clone();
    validate_repository_shape(&scanned, config, &mut diagnostics);
    validate_event_ledger(&scanned, config, &mut diagnostics);
    validate_aliases(&scanned, &mut diagnostics);
    if diagnostics
        .iter()
        .any(|d| d.severity == DiagnosticSeverity::Error)
    {
        return Err(ToolError::Invalid {
            path: repository.display().to_string(),
            message: serde_json::to_string(&diagnostics)
                .unwrap_or_else(|_| "repository validation failed".to_owned()),
        });
    }
    validate_output_target(output)?;
    if output.exists() {
        return Err(ToolError::Repository {
            path: output.display().to_string(),
            message: "output directory already exists; generation requires a fresh destination"
                .to_owned(),
        });
    }
    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = Builder::new().prefix(".astrid-index-").tempdir_in(parent)?;
    let stage = temporary.path();
    let mut targets = BTreeMap::<String, TargetDigest>::new();

    let mut releases: Vec<_> = scanned.releases.values().collect();
    releases.sort_by(|a, b| a.coordinate.cmp(&b.coordinate));
    let mut identities = Vec::<SearchEntry>::new();
    for release in releases {
        let (algorithm, digest) =
            release
                .publication_digest
                .split_once(':')
                .ok_or_else(|| ToolError::Invalid {
                    path: release.file.path.clone(),
                    message: "publication digest must be algorithm tagged".to_owned(),
                })?;
        let target_path = format!("objects/{algorithm}/{}/{digest}.json", &digest[..2]);
        let object_path = format!("v1/{target_path}");
        write_staged(stage, &object_path, &release.canonical)?;
        let object_size = release.canonical.len() as u64;
        targets.insert(
            target_path.clone(),
            TargetDigest {
                // The publication digest is the immutable release identity;
                // the TUF target digest must cover the bytes actually emitted
                // at this object path.  Those are not necessarily the same
                // digest domain, so derive it from the canonical object.
                digest: format!("blake3:{}", digest_bytes(&release.canonical)),
                size: object_size,
            },
        );
        let shard = identity_shard(&release.coordinate.identity());
        identities.push(SearchEntry {
            identity: release.coordinate.identity(),
            namespace: release.coordinate.namespace.clone(),
            name: release.coordinate.name.clone(),
            version: release.coordinate.version.clone(),
            release_digest: release.publication_digest.clone(),
            object: target_path,
            artifact_locations: artifact_locations(release, &scanned.events),
            status: lifecycle_status(&release.coordinate, &scanned.events),
            authoritative: true,
            shard,
        });
    }
    identities.sort_by(|a, b| {
        a.identity
            .cmp(&b.identity)
            .then_with(|| a.version.cmp(&b.version))
    });
    for shard in 0..IDENTITY_SHARD_COUNT {
        let shard_hex = format!("{shard:02x}");
        let entries: Vec<_> = identities
            .iter()
            .filter(|entry| entry.shard == shard)
            .cloned()
            .collect();
        let bytes = canonical_json_bytes(&serde_json::json!({
            "schema": "astrid.capsule-index.identity-shard.v1",
            "shard": shard_hex,
            "entries": entries,
        }))
        .map_err(|message| ToolError::Invalid {
            path: format!("v1/shards/{shard:02x}.json"),
            message,
        })?;
        let target_path = format!("shards/{shard:02x}.json");
        let path = format!("v1/{target_path}");
        write_staged(stage, &path, &bytes)?;
        targets.insert(
            target_path,
            TargetDigest {
                digest: format!("blake3:{}", digest_bytes(&bytes)),
                size: bytes.len() as u64,
            },
        );
    }
    let search_bytes = canonical_json_bytes(&serde_json::json!({
        "schema": "astrid.capsule-index.search.v1",
        "authoritative": false,
        "entries": identities,
    }))
    .map_err(|message| ToolError::Invalid {
        path: "v1/search.json".to_owned(),
        message,
    })?;
    write_staged(stage, "v1/search.json", &search_bytes)?;
    targets.insert(
        "search.json".to_owned(),
        TargetDigest {
            digest: format!("blake3:{}", digest_bytes(&search_bytes)),
            size: search_bytes.len() as u64,
        },
    );

    // This is a deterministic manifest input.  It is deliberately marked
    // unsigned; the TUF crate consumes `_tuf-input/targets.json` and emits
    // signed role metadata later.  Keeping this outside `v1/` prevents an
    // unsigned file from being mistaken for deployable trust metadata.
    let snapshot_without_digest = serde_json::json!({
        "schema": "astrid.capsule-index.snapshot.v1",
        "input_only": true,
        "signed": false,
        "index_id": scanned.index_id,
        "targets": targets,
    });
    let snapshot_bytes =
        canonical_json_bytes(&snapshot_without_digest).map_err(|message| ToolError::Invalid {
            path: "_tuf-input/snapshot.json".to_owned(),
            message,
        })?;
    let generation = digest_bytes(&snapshot_bytes);
    let snapshot = serde_json::json!({
        "schema": "astrid.capsule-index.snapshot.v1",
        "input_only": true,
        "signed": false,
        "index_id": scanned.index_id,
        "generation": generation,
        "targets": snapshot_without_digest["targets"].clone(),
    });
    let snapshot_bytes = canonical_json_bytes(&snapshot).map_err(|message| ToolError::Invalid {
        path: "_tuf-input/snapshot.json".to_owned(),
        message,
    })?;
    write_staged(stage, "_tuf-input/snapshot.json", &snapshot_bytes)?;
    let tuf_targets = canonical_json_bytes(&serde_json::json!({
        "schema": "astrid.capsule-index.tuf-targets-input.v1",
        "input_only": true,
        "signed": false,
        "consistent_snapshot": true,
        "targets": snapshot["targets"].clone(),
    }))
    .map_err(|message| ToolError::Invalid {
        path: "_tuf-input/targets.json".to_owned(),
        message,
    })?;
    write_staged(stage, "_tuf-input/targets.json", &tuf_targets)?;

    fs::rename(stage, output)?;
    // Keep the TempDir alive until rename completes.  Its destructor observes
    // that the original path no longer exists and leaves the final tree alone.
    Ok(GenerationReport {
        output: output.to_path_buf(),
        generation,
        target_count: snapshot["targets"].as_object().map_or(0, Map::len),
        release_count: scanned.releases.len(),
        deployment_ready: false,
    })
}

/// Short alias for deterministic Pages generation.
///
/// # Errors
///
/// See [`generate_pages`].
pub fn generate(
    repository: &Path,
    output: &Path,
    config: &ValidationConfig,
) -> Result<GenerationReport, ToolError> {
    generate_pages(repository, output, config)
}

/// Explicit inputs required to sign one generated Pages tree.
///
/// The root is an existing, offline-approved TUF root.  Targets, snapshot,
/// and timestamp keys are supplied independently; no role key is generated or
/// inferred by this crate.  Expirations and role versions are mandatory so a
/// caller cannot accidentally publish metadata with a stale default.
#[derive(Debug, Clone)]
pub struct SignConfig {
    /// Index identifier embedded in the generated repository identity.
    pub index_id: String,
    /// Existing offline-approved `v1/root.json`.
    pub root_path: PathBuf,
    /// Explicit key files authorized for the targets role.
    pub targets_keys: Vec<PathBuf>,
    /// Explicit key files authorized for the snapshot role.
    pub snapshot_keys: Vec<PathBuf>,
    /// Explicit key files authorized for the timestamp role.
    pub timestamp_keys: Vec<PathBuf>,
    /// New targets role version.
    pub targets_version: u64,
    /// New snapshot role version.
    pub snapshot_version: u64,
    /// New timestamp role version.
    pub timestamp_version: u64,
    /// RFC 3339 targets expiration.
    pub targets_expires: String,
    /// RFC 3339 snapshot expiration.
    pub snapshot_expires: String,
    /// RFC 3339 timestamp expiration.
    pub timestamp_expires: String,
    /// Optional previously deployed tree used for monotonic-version checks.
    pub previous: Option<PathBuf>,
    /// Optional event authorization policy marker carried by the CLI.  A
    /// generated tree has already been validated; `curator-review` remains
    /// the only accepted explicit policy name and denotes review evidence,
    /// not publisher cryptographic signing.
    pub event_authorization: Option<String>,
}

/// Result of a successful TUF signing and verification pass.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningReport {
    /// Atomically deployed output tree.
    pub output: PathBuf,
    /// Signed targets role version.
    pub targets_version: u64,
    /// Signed snapshot role version.
    pub snapshot_version: u64,
    /// Signed timestamp role version.
    pub timestamp_version: u64,
    /// Number of target files covered by the signed targets role.
    pub target_count: usize,
    /// True only after `astrid-capsule-index-tuf` verifies all roles and targets.
    pub deployment_ready: bool,
}

/// Sign and atomically deploy a generated Pages tree using `tough`'s vetted
/// [`RepositoryEditor`].
///
/// The input must be a fresh output from [`generate_pages`].  Claimed digest
/// and size values in `_tuf-input/targets.json` are treated as advisory; every
/// target hash and length is recomputed from the bytes that are signed.  The
/// resulting `/v1` tree is loaded again through
/// `astrid-capsule-index-tuf` before the final rename.
///
/// # Errors
///
/// Returns a structured repository error for unsafe paths, missing or
/// unauthorized keys, malformed metadata, role rollback/equivocation, expired
/// inputs, signing failures, or post-sign verification failures.
pub fn sign_pages(
    input: &Path,
    output: &Path,
    config: &SignConfig,
) -> Result<SigningReport, ToolError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| ToolError::Invalid {
            path: "sign".to_owned(),
            message: format!("cannot create signing runtime: {error}"),
        })?;
    runtime.block_on(sign_pages_async(input, output, config))
}

/// Alias for [`sign_pages`].
///
/// # Errors
///
/// See [`sign_pages`].
pub fn sign(input: &Path, output: &Path, config: &SignConfig) -> Result<SigningReport, ToolError> {
    sign_pages(input, output, config)
}

struct SigningKeyInfo {
    path: PathBuf,
    key_id: String,
}

async fn sign_pages_async(
    input: &Path,
    output: &Path,
    config: &SignConfig,
) -> Result<SigningReport, ToolError> {
    validate_event_authorization_policy(config.event_authorization.as_deref())?;
    validate_output_target(output)?;
    if output.exists() {
        return Err(ToolError::Repository {
            path: output.display().to_string(),
            message: "output directory already exists; signing requires a fresh destination"
                .to_owned(),
        });
    }
    let root_bytes = read_regular_file(&config.root_path, "root metadata")?;
    let root: Signed<Root> =
        serde_json::from_slice(&root_bytes).map_err(|error| ToolError::Json {
            path: config.root_path.display().to_string(),
            source: error,
        })?;
    validate_root_for_signing(&root.signed, &config.root_path)?;
    let role_versions = RoleVersions::new(config)?;
    let role_expirations = RoleExpirations::new(config)?;
    let target_paths = read_signing_targets(input)?;
    let role_keys = load_role_keys(config, &root.signed).await?;
    let all_keys = merge_signing_keys(&role_keys)?;

    let parent = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let temporary = Builder::new()
        .prefix(".astrid-index-sign-")
        .tempdir_in(parent)?;
    let stage = temporary.path();
    for target_path in &target_paths {
        let source = input.join("v1").join(target_path);
        let bytes = fs::read(&source)?;
        write_staged(stage, &format!("v1/{target_path}"), &bytes)?;
    }

    let mut editor = RepositoryEditor::new(&config.root_path)
        .await
        .map_err(|error| signing_error(&config.root_path, error))?;
    for target_path in &target_paths {
        let source = input.join("v1").join(target_path);
        let target = Target::from_path(&source)
            .await
            .map_err(|error| signing_error(&source, error))?;
        // Consistent-snapshot repositories serve each target under the
        // SHA-256-prefixed filename that tough resolves.  Keep the canonical
        // unprefixed path too for Pages/debug consumers, but derive this alias
        // from the bytes just hashed by tough rather than claimed input data.
        let bytes = fs::read(&source)?;
        let digest_prefix = hex::encode(target.hashes.sha256.as_ref());
        write_staged(stage, &format!("v1/{digest_prefix}.{target_path}"), &bytes)?;
        let target_name = TargetName::new(target_path.clone())
            .map_err(|error| signing_error(Path::new(target_path), error))?;
        editor
            .add_target(target_name, target)
            .map_err(|error| signing_error(Path::new(target_path), error))?;
    }
    editor
        .targets_version(role_versions.targets)
        .map_err(|error| signing_error(Path::new("targets"), error))?;
    editor
        .targets_expires(role_expirations.targets)
        .map_err(|error| signing_error(Path::new("targets"), error))?;
    editor
        .snapshot_version(role_versions.snapshot)
        .snapshot_expires(role_expirations.snapshot)
        .timestamp_version(role_versions.timestamp)
        .timestamp_expires(role_expirations.timestamp);
    let signed = editor
        .sign(&all_keys)
        .await
        .map_err(|error| signing_error(Path::new("sign"), error))?;
    signed
        .write(stage.join("v1"))
        .await
        .map_err(|error| signing_error(&stage.join("v1"), error))?;
    compare_previous_metadata(config.previous.as_deref(), stage, &role_versions)?;
    verify_signed_stage(stage, &config.index_id, &root_bytes, &target_paths).await?;
    fs::rename(stage, output)?;
    Ok(SigningReport {
        output: output.to_path_buf(),
        targets_version: role_versions.targets.get(),
        snapshot_version: role_versions.snapshot.get(),
        timestamp_version: role_versions.timestamp.get(),
        target_count: target_paths.len(),
        deployment_ready: true,
    })
}

fn validate_event_authorization_policy(policy: Option<&str>) -> Result<(), ToolError> {
    if let Some(policy) = policy
        && policy != "curator-review"
    {
        return Err(ToolError::Invalid {
            path: "event-authorization".to_owned(),
            message: format!(
                "unsupported event authorization policy `{policy}`; use `curator-review`"
            ),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct RoleVersions {
    targets: NonZeroU64,
    snapshot: NonZeroU64,
    timestamp: NonZeroU64,
}

impl RoleVersions {
    fn new(config: &SignConfig) -> Result<Self, ToolError> {
        Ok(Self {
            targets: nonzero_version("targets", config.targets_version)?,
            snapshot: nonzero_version("snapshot", config.snapshot_version)?,
            timestamp: nonzero_version("timestamp", config.timestamp_version)?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct RoleExpirations {
    targets: Timestamp,
    snapshot: Timestamp,
    timestamp: Timestamp,
}

impl RoleExpirations {
    fn new(config: &SignConfig) -> Result<Self, ToolError> {
        Ok(Self {
            targets: parse_expiration("targets", &config.targets_expires)?,
            snapshot: parse_expiration("snapshot", &config.snapshot_expires)?,
            timestamp: parse_expiration("timestamp", &config.timestamp_expires)?,
        })
    }
}

fn nonzero_version(role: &str, version: u64) -> Result<NonZeroU64, ToolError> {
    NonZeroU64::new(version).ok_or_else(|| ToolError::Invalid {
        path: role.to_owned(),
        message: "role version must be greater than zero".to_owned(),
    })
}

fn parse_expiration(role: &str, value: &str) -> Result<Timestamp, ToolError> {
    let timestamp = value
        .parse::<Timestamp>()
        .map_err(|error| ToolError::Invalid {
            path: role.to_owned(),
            message: format!("expiration must be RFC 3339: {error}"),
        })?;
    if timestamp <= Timestamp::now() {
        return Err(ToolError::Invalid {
            path: role.to_owned(),
            message: "expiration is not in the future".to_owned(),
        });
    }
    Ok(timestamp)
}

fn read_regular_file(path: &Path, label: &str) -> Result<Vec<u8>, ToolError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ToolError::Repository {
            path: path.display().to_string(),
            message: format!("{label} must be a regular non-symlink file"),
        });
    }
    if metadata.len() > DEFAULT_MAX_FILE_BYTES {
        return Err(ToolError::Repository {
            path: path.display().to_string(),
            message: format!("{label} exceeds the {DEFAULT_MAX_FILE_BYTES} byte limit"),
        });
    }
    Ok(fs::read(path)?)
}

fn validate_root_for_signing(root: &Root, path: &Path) -> Result<(), ToolError> {
    if !root.consistent_snapshot {
        return Err(ToolError::Invalid {
            path: path.display().to_string(),
            message: "root must enable consistent snapshots".to_owned(),
        });
    }
    for role in [
        RoleType::Root,
        RoleType::Targets,
        RoleType::Snapshot,
        RoleType::Timestamp,
    ] {
        let Some(keys) = root.roles.get(&role) else {
            return Err(ToolError::Invalid {
                path: path.display().to_string(),
                message: format!("root is missing the {role} role"),
            });
        };
        if keys.keyids.is_empty() || keys.threshold.get() > keys.keyids.len() as u64 {
            return Err(ToolError::Invalid {
                path: path.display().to_string(),
                message: format!("root has an invalid {role} threshold"),
            });
        }
    }
    Ok(())
}

async fn load_role_keys(
    config: &SignConfig,
    root: &Root,
) -> Result<BTreeMap<&'static str, Vec<SigningKeyInfo>>, ToolError> {
    let mut result = BTreeMap::new();
    for (role_name, paths, role_type) in [
        ("targets", &config.targets_keys, RoleType::Targets),
        ("snapshot", &config.snapshot_keys, RoleType::Snapshot),
        ("timestamp", &config.timestamp_keys, RoleType::Timestamp),
    ] {
        if paths.is_empty() {
            return Err(ToolError::Invalid {
                path: role_name.to_owned(),
                message: "at least one explicit key file is required".to_owned(),
            });
        }
        let allowed: BTreeSet<String> = root
            .roles
            .get(&role_type)
            .expect("validated role exists")
            .keyids
            .iter()
            .map(|key_id| hex::encode(key_id.as_ref()))
            .collect();
        let threshold = usize::try_from(
            root.roles
                .get(&role_type)
                .expect("validated role exists")
                .threshold
                .get(),
        )
        .map_err(|_| ToolError::Invalid {
            path: role_name.to_owned(),
            message: "role threshold does not fit in host usize".to_owned(),
        })?;
        let mut infos = Vec::new();
        let mut ids = BTreeSet::new();
        for path in paths {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ToolError::Repository {
                    path: path.display().to_string(),
                    message: format!("{role_name} key source must be a regular non-symlink file"),
                });
            }
            let source = LocalKeySource { path: path.clone() };
            let sign = source.as_sign().await.map_err(|error| ToolError::Invalid {
                path: path.display().to_string(),
                message: format!("cannot load {role_name} key: {error}"),
            })?;
            let key_id = sign
                .tuf_key()
                .key_id()
                .map_err(|error| ToolError::Invalid {
                    path: path.display().to_string(),
                    message: format!("cannot derive {role_name} key ID: {error}"),
                })?;
            let key_id = hex::encode(key_id.as_ref());
            if !allowed.contains(&key_id) {
                return Err(ToolError::Invalid {
                    path: path.display().to_string(),
                    message: format!("key {key_id} is not authorized for the {role_name} role"),
                });
            }
            if ids.insert(key_id.clone()) {
                infos.push(SigningKeyInfo {
                    path: path.clone(),
                    key_id,
                });
            }
        }
        if ids.len() < threshold {
            return Err(ToolError::Invalid {
                path: role_name.to_owned(),
                message: format!(
                    "provided {} unique keys, but threshold is {threshold}",
                    ids.len()
                ),
            });
        }
        result.insert(role_name, infos);
    }
    Ok(result)
}

fn merge_signing_keys(
    role_keys: &BTreeMap<&'static str, Vec<SigningKeyInfo>>,
) -> Result<Vec<Box<dyn KeySource>>, ToolError> {
    let mut by_path = BTreeMap::<String, PathBuf>::new();
    let mut by_id = BTreeMap::<String, PathBuf>::new();
    for infos in role_keys.values() {
        for info in infos {
            let path_key = info.path.to_string_lossy().into_owned();
            by_path.entry(path_key).or_insert_with(|| info.path.clone());
            if let Some(previous) = by_id.insert(info.key_id.clone(), info.path.clone())
                && previous != info.path
            {
                return Err(ToolError::Invalid {
                    path: info.path.display().to_string(),
                    message: format!(
                        "key ID {} is supplied by multiple role source files ({})",
                        info.key_id,
                        previous.display()
                    ),
                });
            }
        }
    }
    Ok(by_path
        .into_values()
        .map(|path| Box::new(LocalKeySource { path }) as Box<dyn KeySource>)
        .collect())
}

fn read_signing_targets(input: &Path) -> Result<Vec<String>, ToolError> {
    let target_input_path = input.join("_tuf-input/targets.json");
    let target_input_bytes = read_regular_file(&target_input_path, "TUF targets input")?;
    let target_input: Value =
        serde_json::from_slice(&target_input_bytes).map_err(|error| ToolError::Json {
            path: target_input_path.display().to_string(),
            source: error,
        })?;
    let target_map = target_input
        .get("targets")
        .and_then(Value::as_object)
        .ok_or_else(|| ToolError::Invalid {
            path: target_input_path.display().to_string(),
            message: "TUF targets input must contain an object-valued targets map".to_owned(),
        })?;
    if target_map.is_empty() {
        return Err(ToolError::Invalid {
            path: target_input_path.display().to_string(),
            message: "TUF targets input may not be empty".to_owned(),
        });
    }
    let v1 = input.join("v1");
    let files = scan_tree(&v1, DEFAULT_MAX_FILE_BYTES)?;
    let mut target_paths = Vec::new();
    for (target_path, metadata) in target_map {
        validate_relative_path(Path::new(target_path))?;
        if target_path == "v1" || target_path.starts_with("v1/") {
            return Err(ToolError::Invalid {
                path: target_input_path.display().to_string(),
                message: format!("target `{target_path}` must be relative to /v1"),
            });
        }
        if !metadata.is_object() {
            return Err(ToolError::Invalid {
                path: target_input_path.display().to_string(),
                message: format!("target `{target_path}` metadata must be an object"),
            });
        }
        if !files.contains_key(target_path) {
            return Err(ToolError::Invalid {
                path: target_path.clone(),
                message: "target input does not correspond to a generated file".to_owned(),
            });
        }
        target_paths.push(target_path.clone());
    }
    for path in files.keys() {
        if !target_map.contains_key(path) {
            return Err(ToolError::Invalid {
                path: path.clone(),
                message: "generated file is not covered by the TUF targets input".to_owned(),
            });
        }
    }
    target_paths.sort();
    Ok(target_paths)
}

fn signing_error(path: &Path, error: impl std::fmt::Display) -> ToolError {
    ToolError::Invalid {
        path: path.display().to_string(),
        message: format!("TUF signing failed: {error}"),
    }
}

fn compare_previous_metadata(
    previous: Option<&Path>,
    stage: &Path,
    versions: &RoleVersions,
) -> Result<(), ToolError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let previous_root = read_versioned_root(previous)?;
    let current_root = read_versioned_root(stage)?;
    if previous_root != current_root {
        return Err(ToolError::Invalid {
            path: previous.join("v1/root.json").display().to_string(),
            message: "root metadata changed; root rotation requires a separate offline workflow"
                .to_owned(),
        });
    }
    for (role, current) in [
        (
            "targets",
            stage.join(format!("v1/{}.targets.json", versions.targets)),
        ),
        (
            "snapshot",
            stage.join(format!("v1/{}.snapshot.json", versions.snapshot)),
        ),
        ("timestamp", stage.join("v1/timestamp.json")),
    ] {
        let current_bytes = read_regular_file(&current, "signed metadata")?;
        let current_value: Value =
            serde_json::from_slice(&current_bytes).map_err(|error| ToolError::Json {
                path: current.display().to_string(),
                source: error,
            })?;
        let current_signed = current_value
            .get("signed")
            .ok_or_else(|| ToolError::Invalid {
                path: current.display().to_string(),
                message: "signed metadata is missing the signed payload".to_owned(),
            })?;
        let current_version = current_signed
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| ToolError::Invalid {
                path: current.display().to_string(),
                message: "signed metadata is missing a numeric version".to_owned(),
            })?;
        let Some((previous_path, previous_bytes)) = find_role_metadata(previous, role)? else {
            continue;
        };
        let previous_value: Value =
            serde_json::from_slice(&previous_bytes).map_err(|error| ToolError::Json {
                path: previous_path.display().to_string(),
                source: error,
            })?;
        let previous_signed = previous_value
            .get("signed")
            .ok_or_else(|| ToolError::Invalid {
                path: previous_path.display().to_string(),
                message: "previous metadata is missing the signed payload".to_owned(),
            })?;
        let previous_version = previous_signed
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| ToolError::Invalid {
                path: previous_path.display().to_string(),
                message: "previous metadata is missing a numeric version".to_owned(),
            })?;
        if current_version < previous_version {
            return Err(ToolError::Invalid {
                path: current.display().to_string(),
                message: format!(
                    "{role} metadata rollback: previous version {previous_version}, observed {current_version}"
                ),
            });
        }
        if current_version == previous_version
            && canonical_json_bytes(current_signed).map_err(|message| ToolError::Invalid {
                path: current.display().to_string(),
                message,
            })? != canonical_json_bytes(previous_signed).map_err(|message| {
                ToolError::Invalid {
                    path: previous_path.display().to_string(),
                    message,
                }
            })?
        {
            return Err(ToolError::Invalid {
                path: current.display().to_string(),
                message: format!("{role} metadata changed while reusing version {current_version}"),
            });
        }
    }
    Ok(())
}

fn read_versioned_root(tree: &Path) -> Result<Vec<u8>, ToolError> {
    let files = scan_tree(&tree.join("v1"), DEFAULT_MAX_FILE_BYTES)?;
    let Some((_, file)) = files
        .into_iter()
        .find(|(relative, _)| relative.ends_with(".root.json") || relative == "root.json")
    else {
        return Err(ToolError::Repository {
            path: tree.join("v1").display().to_string(),
            message: "signed tree is missing root metadata".to_owned(),
        });
    };
    Ok(file.bytes)
}

fn find_role_metadata(
    previous: &Path,
    role: &str,
) -> Result<Option<(PathBuf, Vec<u8>)>, ToolError> {
    let files = scan_tree(&previous.join("v1"), DEFAULT_MAX_FILE_BYTES)?;
    let mut found = None;
    for (relative, file) in files {
        let value: Value = match serde_json::from_slice(&file.bytes) {
            Ok(value) => value,
            Err(_) => continue,
        };
        let Some(signed) = value.get("signed") else {
            continue;
        };
        let Some(kind) = signed.get("_type").and_then(Value::as_str) else {
            continue;
        };
        if kind == role {
            found = Some((previous.join("v1").join(relative), file.bytes));
        }
    }
    Ok(found)
}

async fn verify_signed_stage(
    stage: &Path,
    index_id: &str,
    root_bytes: &[u8],
    target_paths: &[String],
) -> Result<(), ToolError> {
    let root_fingerprint = astrid_capsule_index_tuf::root_fingerprint_from_bytes(root_bytes)
        .map_err(|error| signing_error(Path::new("root"), error))?;
    let identity = IndexIdentity::new(
        IndexId::new(index_id.to_owned())
            .map_err(|error| signing_error(Path::new("index_id"), error))?,
        root_fingerprint,
    );
    let base_url = Url::from_directory_path(stage.join("v1")).map_err(|()| ToolError::Invalid {
        path: stage.display().to_string(),
        message: "signed output path cannot be represented as a file URL".to_owned(),
    })?;
    let verify_dir = Builder::new()
        .prefix(".astrid-index-verify-")
        .tempdir_in(stage.parent().unwrap_or_else(|| Path::new(".")))?;
    let trust = TrustConfig::new(
        identity,
        root_bytes,
        base_url.clone(),
        base_url,
        verify_dir.path().join("state.json"),
        verify_dir.path().join("datastore"),
    )
    .map_err(|error| signing_error(Path::new("verification"), error))?
    .mode(VerificationMode::Offline(
        astrid_capsule_index_tuf::OfflinePolicy::RejectExpired,
    ));
    let verified = load_verified_index(trust, FilesystemTransport)
        .await
        .map_err(|error| signing_error(Path::new("verification"), error))?;
    for target_path in target_paths {
        verified
            .read_target(target_path)
            .await
            .map_err(|error| signing_error(Path::new(target_path), error))?;
    }
    Ok(())
}

fn validate_output_target(output: &Path) -> Result<(), ToolError> {
    if output
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(ToolError::Repository {
            path: output.display().to_string(),
            message: "output path may not contain traversal components".to_owned(),
        });
    }
    if let Ok(metadata) = fs::symlink_metadata(output)
        && metadata.file_type().is_symlink()
    {
        return Err(ToolError::Repository {
            path: output.display().to_string(),
            message: "output path may not be a symlink".to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerationReport {
    pub output: PathBuf,
    pub generation: String,
    pub target_count: usize,
    pub release_count: usize,
    /// False until the separate TUF signer emits trusted role files.
    pub deployment_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TargetDigest {
    digest: String,
    size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SearchEntry {
    identity: String,
    namespace: String,
    name: String,
    version: String,
    release_digest: String,
    object: String,
    artifact_locations: Vec<String>,
    status: String,
    authoritative: bool,
    #[serde(skip)]
    shard: usize,
}

fn artifact_locations(
    release: &ReleaseRecord,
    events: &BTreeMap<String, IndexEvent>,
) -> Vec<String> {
    let mut locations: BTreeSet<String> = release
        .protocol
        .artifact()
        .locations()
        .iter()
        .map(|location| location.as_str().to_owned())
        .collect();
    for event in events.values() {
        let Some(ProtocolIndexEvent::AddMirror {
            publication,
            mirror,
            ..
        }) = event.protocol.as_ref()
        else {
            continue;
        };
        if publication == &release.protocol.key() {
            locations.insert(mirror.as_str().to_owned());
        }
    }
    locations.into_iter().collect()
}

fn lifecycle_status(coordinate: &Coordinate, events: &BTreeMap<String, IndexEvent>) -> String {
    let target = EventTarget::Release(coordinate.clone());
    let mut status = "active";
    let mut ordered: Vec<_> = events
        .values()
        .filter(|event| event.target == target)
        .collect();
    ordered.sort_by(|a, b| {
        a.sequence
            .cmp(&b.sequence)
            .then_with(|| a.file.path.cmp(&b.file.path))
    });
    for event in ordered {
        status = match event.kind.as_str() {
            "yank" => "yanked",
            "unyank" => "active",
            "deprecate" => "deprecated",
            "revoke" => "revoked",
            "tombstone" => "tombstoned",
            _ => status,
        };
    }
    status.to_owned()
}

fn identity_shard(identity: &str) -> usize {
    blake3::hash(identity.as_bytes()).as_bytes()[0] as usize
}

fn write_staged(stage: &Path, relative: &str, bytes: &[u8]) -> Result<(), ToolError> {
    let relative_path = Path::new(relative);
    validate_relative_path(relative_path)?;
    let destination = stage.join(relative_path);
    let parent = destination.parent().ok_or_else(|| ToolError::Repository {
        path: relative.to_owned(),
        message: "generated path has no parent".to_owned(),
    })?;
    fs::create_dir_all(parent)?;
    let mut file = File::create(destination)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn digest_bytes(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            serde_json::to_writer(output, value).map_err(|error| error.to_string())?;
        },
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        },
        Value::Object(values) => {
            output.push(b'{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key).map_err(|error| error.to_string())?;
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        },
    }
    Ok(())
}

fn validate_identifier(value: &str, label: &str, path: &str) -> Result<String, Diagnostic> {
    if !valid_ascii_identifier(value, true) {
        return Err(Diagnostic::error(
            "INVALID_IDENTITY",
            path,
            format!("{label} `{value}` must use lowercase ASCII identifier grammar"),
        ));
    }
    Ok(value.to_owned())
}

fn valid_ascii_identifier(value: &str, allow_reserved_prefix: bool) -> bool {
    if value.is_empty()
        || value.len() > 80
        || value.bytes().any(|byte| {
            !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && !matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return false;
    }
    if !value.as_bytes()[0].is_ascii_lowercase() && !value.as_bytes()[0].is_ascii_digit() {
        return false;
    }
    if value.ends_with('.') || value.ends_with('-') || value.ends_with('_') {
        return false;
    }
    allow_reserved_prefix || value != "astrid" && value != "aos"
}

fn coordinate_from_path(path: &str, index_id: &str) -> Option<Coordinate> {
    let components: Vec<_> = path.split('/').collect();
    if components.len() != 4
        || !RELEASE_ROOTS.contains(&components[0])
        || !has_json_extension(components[3])
    {
        return None;
    }
    let version = components[3].strip_suffix(".json")?;
    Some(Coordinate {
        index_id: index_id.to_owned(),
        namespace: components[1].to_owned(),
        name: components[2].to_owned(),
        version: version.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use astrid_capsule_index::{
        ActorId, BuildProvenance, CanonicalSemVer, CapabilityClaims, CapsuleName,
        Coordinate as ProtocolCoordinate, DependencyClaims, Digest, EmbeddedPackageIdentity,
        EventAuthorization, EventAuthorizationVerifier, EventBody, EventEnvelope, GitObjectId,
        IndexEvent, IndexId, IndexResult, MirrorUrl, Namespace,
        NamespaceClaim as ProtocolNamespaceClaim, NamespaceTransfer as ProtocolNamespaceTransfer,
        PublicationKey, PublicationRecord, PublisherIdentity, RuntimeRequirements, SchemaVersion,
        SourceProvenance, TrustRootFingerprint,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest as ShaDigest, Sha256};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    #[allow(clippy::needless_pass_by_value)]
    fn write_json(root: &Path, path: &str, value: Value) {
        let destination = root.join(path);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::write(destination, serde_json::to_vec(&value).unwrap()).unwrap();
    }

    fn release_for(index_id: &str, version: &str, digest: &str) -> Value {
        let digest = Digest::parse(&format!("blake3:{digest}")).unwrap();
        let coordinate = ProtocolCoordinate::new(
            Namespace::new("demo").unwrap(),
            CapsuleName::new("hello").unwrap(),
        );
        let canonical_version: CanonicalSemVer = version.parse().unwrap();
        let source = SourceProvenance::new(
            MirrorUrl::new("https://example.invalid/source").unwrap(),
            1,
            1,
            GitObjectId::new("0".repeat(40)).unwrap(),
            GitObjectId::new("1".repeat(40)).unwrap(),
            version,
            None,
            digest.clone(),
        )
        .unwrap();
        let capability_declaration_digest = Digest::blake3(&[]);
        let capabilities = CapabilityClaims::new_with_digests(
            Vec::new(),
            digest.clone(),
            capability_declaration_digest.clone(),
        )
        .unwrap();
        let dependencies = DependencyClaims::new_with_digest(Vec::new(), digest.clone()).unwrap();
        let provenance = BuildProvenance::new(
            "https://slsa.dev/provenance/v1",
            digest.clone(),
            MirrorUrl::new("https://example.invalid/builder").unwrap(),
            "test-builder",
        )
        .unwrap();
        let record = PublicationRecord::builder(
            IndexId::new(index_id).unwrap(),
            coordinate.clone(),
            canonical_version.clone(),
        )
        .artifact_locations(
            1,
            "application/vnd.astrid.capsule",
            vec![MirrorUrl::new("https://example.invalid/artifact").unwrap()],
            digest.clone(),
        )
        .unwrap()
        .publisher(PublisherIdentity::new(
            ActorId::new("publisher").unwrap(),
            digest.clone(),
        ))
        .source(source)
        .runtime(
            RuntimeRequirements::new_with_digest(
                "astrid",
                "wasm32-unknown-unknown",
                digest.clone(),
            )
            .unwrap(),
        )
        .package(EmbeddedPackageIdentity::new(
            coordinate,
            canonical_version,
            digest.clone(),
        ))
        .manifest_digest(digest.clone())
        .component_digest(digest.clone())
        .wit_digest(digest.clone())
        .capabilities(capabilities)
        .dependencies(dependencies)
        .capability_digest(capability_declaration_digest)
        .dependency_digest(digest.clone())
        .provenance(provenance)
        .provenance_digest(digest.clone())
        .source_digest(digest)
        .seal()
        .unwrap();
        serde_json::to_value(record).unwrap()
    }

    fn release(version: &str, digest: &str) -> Value {
        release_for("community", version, digest)
    }

    fn config() -> ValidationConfig {
        ValidationConfig::default()
            .with_index_id("community")
            .with_authorization_verifier(TestVerifier)
    }

    #[derive(Debug)]
    struct TestVerifier;

    impl EventAuthorizationVerifier for TestVerifier {
        fn verify(&self, _envelope: &EventEnvelope) -> IndexResult<()> {
            Ok(())
        }
    }

    fn event_identity() -> IndexIdentity {
        IndexIdentity::new(
            IndexId::new("community").unwrap(),
            TrustRootFingerprint::new(
                Digest::parse(
                    "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
            ),
        )
    }

    fn envelope(sequence: u64, event: IndexEvent, prior: Option<Digest>) -> EventEnvelope {
        let actor = event.actor().clone();
        let authorization = EventAuthorization::new(
            actor.clone(),
            "test-evidence",
            Digest::blake3(b"test-signature"),
        )
        .unwrap();
        EventEnvelope::seal(
            SchemaVersion::event_v1(),
            event_identity(),
            sequence,
            "2026-01-01T00:00:00Z",
            actor,
            authorization,
            prior,
            EventBody::Publication(event),
        )
        .unwrap()
    }

    fn event_path(envelope: &EventEnvelope) -> String {
        canonical_event_path(envelope)
    }

    fn write_signing_root(directory: &Path) -> (PathBuf, PathBuf) {
        let seed = [7_u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let public = hex::encode(signing_key.verifying_key().to_bytes());
        let key_value = serde_json::json!({
            "keytype": "ed25519",
            "scheme": "ed25519",
            "keyval": {"public": public},
        });
        let key_id = hex::encode(Sha256::digest(canonical_json_bytes(&key_value).unwrap()));
        let role = serde_json::json!({"keyids": [key_id.clone()], "threshold": 1});
        let signed = serde_json::json!({
            "_type": "root",
            "spec_version": "1.0",
            "consistent_snapshot": true,
            "version": 1,
            "expires": "2035-01-01T00:00:00Z",
            "keys": {key_id.clone(): key_value},
            "roles": {
                "root": role,
                "targets": {"keyids": [key_id.clone()], "threshold": 1},
                "snapshot": {"keyids": [key_id.clone()], "threshold": 1},
                "timestamp": {"keyids": [key_id], "threshold": 1},
            },
        });
        let signature = signing_key.sign(&canonical_json_bytes(&signed).unwrap());
        let root = serde_json::json!({
            "signed": signed,
            "signatures": [{
                "keyid": hex::encode(Sha256::digest(canonical_json_bytes(&key_value).unwrap())),
                "sig": hex::encode(signature.to_bytes()),
            }],
        });
        let root_path = directory.join("root.json");
        fs::write(&root_path, serde_json::to_vec(&root).unwrap()).unwrap();
        let key_der = [
            vec![
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20,
            ],
            seed.to_vec(),
        ]
        .concat();
        let key_path = directory.join("role-key.der");
        fs::write(&key_path, key_der).unwrap();
        (root_path, key_path)
    }

    fn publication_key(version: &str) -> PublicationKey {
        PublicationKey::new(
            IndexId::new("community").unwrap(),
            ProtocolCoordinate::new(
                Namespace::new("demo").unwrap(),
                CapsuleName::new("hello").unwrap(),
            ),
            version.parse().unwrap(),
        )
    }

    #[test]
    fn byte_identical_resubmission_is_idempotent() {
        let base = TempDir::new().unwrap();
        write_json(
            base.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let report = validate_trees(base.path(), base.path(), &config()).unwrap();
        assert_eq!(report.outcome, ValidationOutcome::Idempotent);
    }

    #[test]
    fn changed_publication_is_rejected() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write_json(
            base.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        write_json(
            candidate.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert_eq!(report.outcome, ValidationOutcome::Rejected);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "EQUIVOCATION")
        );
    }

    #[test]
    fn deleting_an_accepted_version_is_rejected() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write_json(
            base.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "APPEND_ONLY_DELETE")
        );
    }

    #[test]
    fn duplicate_concurrent_claims_are_rejected() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        let value = release(
            "1.0.0",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        write_json(
            candidate.path(),
            "records/demo/hello/1.0.0.json",
            value.clone(),
        );
        write_json(candidate.path(), "releases/demo/hello/1.0.0.json", value);
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "DUPLICATE_COORDINATE")
        );
    }

    #[test]
    fn malformed_case_alias_is_rejected_by_typed_schema() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        let mut value = release(
            "1.0.0",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        value["coordinate"]["name"] = Value::String("Hello".to_owned());
        write_json(candidate.path(), "records/demo/Hello/1.0.0.json", value);
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "INVALID_RELEASE_SCHEMA")
        );
    }

    #[test]
    fn stale_lifecycle_target_is_rejected() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        let event = envelope(
            1,
            IndexEvent::yank(
                ActorId::new("publisher").unwrap(),
                publication_key("9.9.9"),
                Some("not present".to_owned()),
            ),
            None,
        );
        let path = candidate.path().join(event_path(&event));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec(&event).unwrap()).unwrap();
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "STALE_EVENT_TARGET")
        );
    }

    #[test]
    fn ordered_yank_then_unyank_is_accepted() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write_json(
            candidate.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let first = envelope(
            1,
            IndexEvent::yank(
                ActorId::new("publisher").unwrap(),
                publication_key("1.0.0"),
                Some("withdrawn".to_owned()),
            ),
            None,
        );
        write_json(
            candidate.path(),
            &event_path(&first),
            serde_json::to_value(&first).unwrap(),
        );
        let second = envelope(
            2,
            IndexEvent::unyank(ActorId::new("publisher").unwrap(), publication_key("1.0.0")),
            Some(first.event_digest().clone()),
        );
        write_json(
            candidate.path(),
            &event_path(&second),
            serde_json::to_value(&second).unwrap(),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert_eq!(report.outcome, ValidationOutcome::Accepted);
        assert!(
            !report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "INVALID_EVENT_TRANSITION")
        );
    }

    #[test]
    fn repeated_yank_is_rejected_by_protocol_lifecycle() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write_json(
            candidate.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let first = envelope(
            1,
            IndexEvent::yank(
                ActorId::new("publisher").unwrap(),
                publication_key("1.0.0"),
                None,
            ),
            None,
        );
        write_json(
            candidate.path(),
            &event_path(&first),
            serde_json::to_value(&first).unwrap(),
        );
        let second = envelope(
            2,
            IndexEvent::yank(
                ActorId::new("publisher").unwrap(),
                publication_key("1.0.0"),
                None,
            ),
            Some(first.event_digest().clone()),
        );
        write_json(
            candidate.path(),
            &event_path(&second),
            serde_json::to_value(&second).unwrap(),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert_eq!(report.outcome, ValidationOutcome::Rejected);
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "INVALID_EVENT_TRANSITION")
        );
    }

    #[test]
    fn cross_index_publication_is_rejected() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write_json(
            candidate.path(),
            "records/demo/hello/1.0.0.json",
            release_for(
                "other",
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "CROSS_INDEX_COLLISION")
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_rejected() {
        let root = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        fs::write(outside.path().join("record.json"), b"{}").unwrap();
        symlink(
            outside.path().join("record.json"),
            root.path().join("records.json"),
        )
        .unwrap();
        let error = validate_repository(root.path(), &config()).unwrap_err();
        assert!(error.to_string().contains("symlink"));
    }

    #[test]
    fn generated_tree_has_all_shards() {
        let repository = TempDir::new().unwrap();
        write_json(
            repository.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let output_parent = TempDir::new().unwrap();
        let output = output_parent.path().join("pages");
        let report = generate_pages(repository.path(), &output, &config()).unwrap();
        assert_eq!(report.release_count, 1);
        for shard in 0..IDENTITY_SHARD_COUNT {
            assert!(output.join(format!("v1/shards/{shard:02x}.json")).is_file());
        }
        let first = fs::read(output.join("_tuf-input/snapshot.json")).unwrap();
        assert!(!output.join("v1/snapshot.json").exists());
        assert!(!output.join("v1/root.json").exists());
        assert!(!output.join("v1/timestamp.json").exists());
        assert!(!output.join("v1/targets.json").exists());
        assert!(!output.join("v1/snapshot.1.json").exists());
        let second_output = output_parent.path().join("pages-2");
        generate_pages(repository.path(), &second_output, &config()).unwrap();
        assert_eq!(
            first,
            fs::read(second_output.join("_tuf-input/snapshot.json")).unwrap()
        );
    }

    #[test]
    fn generated_tuf_targets_match_emitted_bytes() {
        let repository = TempDir::new().unwrap();
        write_json(
            repository.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let output_parent = TempDir::new().unwrap();
        let output = output_parent.path().join("pages");
        generate_pages(repository.path(), &output, &config()).unwrap();

        let tuf_input: Value =
            serde_json::from_slice(&fs::read(output.join("_tuf-input/targets.json")).unwrap())
                .unwrap();
        let targets = tuf_input.get("targets").and_then(Value::as_object).unwrap();
        assert!(!targets.is_empty());
        for (relative_path, metadata) in targets {
            let bytes = fs::read(output.join("v1").join(relative_path)).unwrap();
            let expected_digest = format!("blake3:{}", digest_bytes(&bytes));
            assert_eq!(metadata["digest"], expected_digest, "{relative_path}");
            assert_eq!(metadata["size"].as_u64(), Some(bytes.len() as u64));
        }
    }

    #[test]
    fn authorized_mirror_event_updates_shard_without_changing_object_identity() {
        let plain = TempDir::new().unwrap();
        write_json(
            plain.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let with_mirror = TempDir::new().unwrap();
        write_json(
            with_mirror.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let mirror = MirrorUrl::new("https://mirror.example.invalid/capsule").unwrap();
        let event = envelope(
            1,
            IndexEvent::add_mirror(
                ActorId::new("publisher").unwrap(),
                publication_key("1.0.0"),
                mirror.clone(),
            ),
            None,
        );
        write_json(
            with_mirror.path(),
            &event_path(&event),
            serde_json::to_value(&event).unwrap(),
        );
        let output_parent = TempDir::new().unwrap();
        let plain_output = output_parent.path().join("plain");
        let mirror_output = output_parent.path().join("mirror");
        generate_pages(plain.path(), &plain_output, &config()).unwrap();
        generate_pages(with_mirror.path(), &mirror_output, &config()).unwrap();
        let plain_targets: Value = serde_json::from_slice(
            &fs::read(plain_output.join("_tuf-input/targets.json")).unwrap(),
        )
        .unwrap();
        let object = plain_targets["targets"]
            .as_object()
            .unwrap()
            .keys()
            .find(|path| path.starts_with("objects/"))
            .unwrap()
            .clone();
        assert_eq!(
            fs::read(plain_output.join("v1").join(&object)).unwrap(),
            fs::read(mirror_output.join("v1").join(&object)).unwrap()
        );
        let shard = identity_shard("@demo/hello@1.0.0");
        let shard_value: Value = serde_json::from_slice(
            &fs::read(mirror_output.join(format!("v1/shards/{shard:02x}.json"))).unwrap(),
        )
        .unwrap();
        assert!(
            shard_value["entries"][0]["artifact_locations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|value| value == mirror.as_str())
        );
    }

    #[test]
    fn output_traversal_is_rejected() {
        let repository = TempDir::new().unwrap();
        write_json(
            repository.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let output_parent = TempDir::new().unwrap();
        let output = output_parent.path().join("nested/../pages");
        let error = generate_pages(repository.path(), &output, &config()).unwrap_err();
        assert!(error.to_string().contains("traversal"));
    }

    #[test]
    fn oversized_repository_file_is_rejected() {
        let repository = TempDir::new().unwrap();
        fs::write(repository.path().join("notes.txt"), vec![b'x'; 32]).unwrap();
        let error = validate_repository(
            repository.path(),
            &ValidationConfig::default()
                .with_index_id("community")
                .with_max_file_bytes(8),
        )
        .unwrap_err();
        assert!(error.to_string().contains("exceeding"));
    }

    #[test]
    fn unsigned_legacy_event_is_rejected_before_ledger_replay() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write_json(
            candidate.path(),
            "events/0001.json",
            serde_json::to_value(IndexEvent::yank(
                ActorId::new("publisher").unwrap(),
                publication_key("1.0.0"),
                Some("unsigned".to_owned()),
            ))
            .unwrap(),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(report.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "INVALID_EVENT_SCHEMA"
                && diagnostic.message.contains("sealed EventEnvelope")
        }));
    }

    #[test]
    fn envelope_gap_and_prior_replay_are_rejected() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write_json(
            candidate.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let first = envelope(
            1,
            IndexEvent::yank(
                ActorId::new("publisher").unwrap(),
                publication_key("1.0.0"),
                Some("withdrawn".to_owned()),
            ),
            None,
        );
        let second = envelope(
            3,
            IndexEvent::unyank(ActorId::new("publisher").unwrap(), publication_key("1.0.0")),
            Some(first.event_digest().clone()),
        );
        write_json(
            candidate.path(),
            &event_path(&first),
            serde_json::to_value(&first).unwrap(),
        );
        write_json(
            candidate.path(),
            &event_path(&second),
            serde_json::to_value(&second).unwrap(),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "EVENT_SEQUENCE")
        );
    }

    #[test]
    fn envelope_retarget_and_unauthorized_owner_are_rejected() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        write_json(
            candidate.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let stale = envelope(
            1,
            IndexEvent::yank(
                ActorId::new("publisher").unwrap(),
                publication_key("9.9.9"),
                Some("retarget".to_owned()),
            ),
            None,
        );
        write_json(
            candidate.path(),
            &event_path(&stale),
            serde_json::to_value(&stale).unwrap(),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "STALE_EVENT_TARGET")
        );

        let candidate = TempDir::new().unwrap();
        write_json(
            candidate.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let unauthorized = envelope(
            1,
            IndexEvent::yank(
                ActorId::new("not-the-publisher").unwrap(),
                publication_key("1.0.0"),
                Some("wrong owner".to_owned()),
            ),
            None,
        );
        write_json(
            candidate.path(),
            &event_path(&unauthorized),
            serde_json::to_value(&unauthorized).unwrap(),
        );
        let report = validate_trees(base.path(), candidate.path(), &config()).unwrap();
        assert!(
            report
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "UNAUTHORIZED_EVENT")
        );
    }

    #[test]
    fn curator_review_policy_binds_evidence_digest_and_is_not_publisher_signing() {
        let actor = ActorId::new("publisher").unwrap();
        let authorization = EventAuthorization::new(
            actor.clone(),
            "curator-review:pr-42",
            Digest::blake3(b"curator-review:pr-42"),
        )
        .unwrap();
        let envelope = EventEnvelope::seal(
            SchemaVersion::event_v1(),
            event_identity(),
            1,
            "2026-01-01T00:00:00Z",
            actor.clone(),
            authorization,
            None,
            EventBody::Publication(IndexEvent::yank(
                actor,
                publication_key("1.0.0"),
                Some("reviewed".to_owned()),
            )),
        )
        .unwrap();
        CuratorReviewVerifier.verify(&envelope).unwrap();
        let mut tampered = serde_json::to_value(&envelope).unwrap();
        tampered["authorization"]["signature_digest"] = Value::String(
            "blake3:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        );
        assert!(serde_json::from_value::<EventEnvelope>(tampered).is_err());
    }

    #[test]
    fn namespace_transfer_replays_claim_owner_and_nested_review_evidence() {
        let base = TempDir::new().unwrap();
        let candidate = TempDir::new().unwrap();
        let namespace = Namespace::new("demo").unwrap();
        let publisher = ActorId::new("publisher").unwrap();
        let incoming = ActorId::new("incoming-owner").unwrap();
        let claim = ProtocolNamespaceClaim::new(
            namespace.clone(),
            publisher.clone(),
            "security@example.invalid",
            MirrorUrl::new("https://example.invalid/repository").unwrap(),
            1,
            1,
            publisher.clone(),
            "MIT",
            None,
        )
        .unwrap();
        write_json(
            candidate.path(),
            "namespaces/demo.json",
            serde_json::to_value(claim).unwrap(),
        );
        let outgoing = EventAuthorization::new(
            publisher.clone(),
            "outgoing-review",
            Digest::blake3(b"outgoing-review"),
        )
        .unwrap();
        let acceptance = EventAuthorization::new(
            incoming.clone(),
            "incoming-review",
            Digest::blake3(b"incoming-review"),
        )
        .unwrap();
        let review = EventAuthorization::new(
            ActorId::new("curator").unwrap(),
            "index-review",
            Digest::blake3(b"index-review"),
        )
        .unwrap();
        let transfer = ProtocolNamespaceTransfer::new(
            namespace, publisher, incoming, outgoing, acceptance, review, 1,
        )
        .unwrap();
        let envelope_actor = ActorId::new("curator").unwrap();
        let envelope_auth = EventAuthorization::new(
            envelope_actor.clone(),
            "envelope-review",
            Digest::blake3(b"envelope-review"),
        )
        .unwrap();
        let envelope = EventEnvelope::seal(
            SchemaVersion::event_v1(),
            event_identity(),
            1,
            "2026-01-01T00:00:00Z",
            envelope_actor,
            envelope_auth,
            None,
            EventBody::NamespaceTransfer(transfer),
        )
        .unwrap();
        write_json(
            candidate.path(),
            &event_path(&envelope),
            serde_json::to_value(&envelope).unwrap(),
        );
        let policy = ValidationConfig::default()
            .with_index_id("community")
            .with_curator_review_verifier();
        let report = validate_trees(base.path(), candidate.path(), &policy).unwrap();
        assert_eq!(report.outcome, ValidationOutcome::Accepted);
        assert!(report.diagnostics.is_empty());
    }

    #[test]
    fn sign_pages_emits_verified_consistent_snapshot_roles() {
        let repository = TempDir::new().unwrap();
        write_json(
            repository.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let generated_parent = TempDir::new().unwrap();
        let generated = generated_parent.path().join("generated");
        generate_pages(repository.path(), &generated, &config()).unwrap();
        // Claimed input hashes are advisory.  Signing must recompute target
        // digests from bytes and still verify the resulting TUF role.
        let target_input_path = generated.join("_tuf-input/targets.json");
        let mut target_input: Value =
            serde_json::from_slice(&fs::read(&target_input_path).unwrap()).unwrap();
        let first_target = target_input["targets"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        target_input["targets"][&first_target]["digest"] = Value::String(
            "blake3:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
        );
        fs::write(
            &target_input_path,
            serde_json::to_vec(&target_input).unwrap(),
        )
        .unwrap();
        let signing_parent = TempDir::new().unwrap();
        let (root, key) = write_signing_root(signing_parent.path());
        let signed = signing_parent.path().join("signed");
        let report = sign_pages(
            &generated,
            &signed,
            &SignConfig {
                index_id: "community".to_owned(),
                root_path: root,
                targets_keys: vec![key.clone()],
                snapshot_keys: vec![key.clone()],
                timestamp_keys: vec![key],
                targets_version: 1,
                snapshot_version: 1,
                timestamp_version: 1,
                targets_expires: "2035-01-01T00:00:00Z".to_owned(),
                snapshot_expires: "2035-01-01T00:00:00Z".to_owned(),
                timestamp_expires: "2035-01-01T00:00:00Z".to_owned(),
                previous: None,
                event_authorization: None,
            },
        )
        .unwrap();
        assert!(report.deployment_ready);
        assert!(signed.join("v1/1.root.json").is_file());
        assert!(signed.join("v1/1.targets.json").is_file());
        assert!(signed.join("v1/1.snapshot.json").is_file());
        assert!(signed.join("v1/timestamp.json").is_file());
        assert!(!signed.join("_tuf-input").exists());
    }

    #[test]
    fn sign_pages_rejects_wrong_or_missing_role_key() {
        let repository = TempDir::new().unwrap();
        write_json(
            repository.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let generated_parent = TempDir::new().unwrap();
        let generated = generated_parent.path().join("generated");
        generate_pages(repository.path(), &generated, &config()).unwrap();
        let signing_parent = TempDir::new().unwrap();
        let (root, authorized_key) = write_signing_root(signing_parent.path());
        let wrong_key = signing_parent.path().join("wrong-key.der");
        let wrong_seed = [8_u8; 32];
        fs::write(
            &wrong_key,
            [
                vec![
                    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04,
                    0x22, 0x04, 0x20,
                ],
                wrong_seed.to_vec(),
            ]
            .concat(),
        )
        .unwrap();
        let config_for = |key: PathBuf| SignConfig {
            index_id: "community".to_owned(),
            root_path: root.clone(),
            targets_keys: vec![key.clone()],
            snapshot_keys: vec![key.clone()],
            timestamp_keys: vec![key],
            targets_version: 1,
            snapshot_version: 1,
            timestamp_version: 1,
            targets_expires: "2035-01-01T00:00:00Z".to_owned(),
            snapshot_expires: "2035-01-01T00:00:00Z".to_owned(),
            timestamp_expires: "2035-01-01T00:00:00Z".to_owned(),
            previous: None,
            event_authorization: None,
        };
        let wrong = sign_pages(
            &generated,
            &signing_parent.path().join("wrong-output"),
            &config_for(wrong_key),
        )
        .unwrap_err();
        assert!(wrong.to_string().contains("not authorized"));
        let missing = sign_pages(
            &generated,
            &signing_parent.path().join("missing-output"),
            &config_for(signing_parent.path().join("missing.der")),
        )
        .unwrap_err();
        assert!(
            missing.to_string().contains("No such file")
                || missing.to_string().contains("not found")
        );
        assert!(authorized_key.is_file());
    }

    #[test]
    fn sign_pages_rejects_expired_role_inputs() {
        let repository = TempDir::new().unwrap();
        write_json(
            repository.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let generated_parent = TempDir::new().unwrap();
        let generated = generated_parent.path().join("generated");
        generate_pages(repository.path(), &generated, &config()).unwrap();
        let signing_parent = TempDir::new().unwrap();
        let (root, key) = write_signing_root(signing_parent.path());
        let expired = SignConfig {
            index_id: "community".to_owned(),
            root_path: root,
            targets_keys: vec![key.clone()],
            snapshot_keys: vec![key.clone()],
            timestamp_keys: vec![key],
            targets_version: 1,
            snapshot_version: 1,
            timestamp_version: 1,
            targets_expires: "2020-01-01T00:00:00Z".to_owned(),
            snapshot_expires: "2035-01-01T00:00:00Z".to_owned(),
            timestamp_expires: "2035-01-01T00:00:00Z".to_owned(),
            previous: None,
            event_authorization: None,
        };
        let error =
            sign_pages(&generated, &signing_parent.path().join("expired"), &expired).unwrap_err();
        assert!(error.to_string().contains("not in the future"));
    }

    #[test]
    fn sign_pages_rejects_threshold_without_enough_authorized_keys() {
        let repository = TempDir::new().unwrap();
        write_json(
            repository.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let generated_parent = TempDir::new().unwrap();
        let generated = generated_parent.path().join("generated");
        generate_pages(repository.path(), &generated, &config()).unwrap();
        let signing_parent = TempDir::new().unwrap();
        let (root, key) = write_signing_root(signing_parent.path());
        let mut root_value: Value = serde_json::from_slice(&fs::read(&root).unwrap()).unwrap();
        root_value["signed"]["roles"]["targets"]["threshold"] = Value::from(2_u64);
        fs::write(&root, serde_json::to_vec(&root_value).unwrap()).unwrap();
        let threshold = SignConfig {
            index_id: "community".to_owned(),
            root_path: root,
            targets_keys: vec![key.clone()],
            snapshot_keys: vec![key.clone()],
            timestamp_keys: vec![key],
            targets_version: 1,
            snapshot_version: 1,
            timestamp_version: 1,
            targets_expires: "2035-01-01T00:00:00Z".to_owned(),
            snapshot_expires: "2035-01-01T00:00:00Z".to_owned(),
            timestamp_expires: "2035-01-01T00:00:00Z".to_owned(),
            previous: None,
            event_authorization: None,
        };
        let error = sign_pages(
            &generated,
            &signing_parent.path().join("threshold"),
            &threshold,
        )
        .unwrap_err();
        assert!(error.to_string().contains("threshold"));
    }

    #[test]
    fn sign_pages_refuses_equal_version_changed_metadata_and_is_deterministic() {
        let repository = TempDir::new().unwrap();
        write_json(
            repository.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        );
        let generated_parent = TempDir::new().unwrap();
        let generated = generated_parent.path().join("generated");
        generate_pages(repository.path(), &generated, &config()).unwrap();
        let signing_parent = TempDir::new().unwrap();
        let (root, key) = write_signing_root(signing_parent.path());
        let config_for = |_output: &Path, previous: Option<PathBuf>| SignConfig {
            index_id: "community".to_owned(),
            root_path: root.clone(),
            targets_keys: vec![key.clone()],
            snapshot_keys: vec![key.clone()],
            timestamp_keys: vec![key.clone()],
            targets_version: 1,
            snapshot_version: 1,
            timestamp_version: 1,
            targets_expires: "2035-01-01T00:00:00Z".to_owned(),
            snapshot_expires: "2035-01-01T00:00:00Z".to_owned(),
            timestamp_expires: "2035-01-01T00:00:00Z".to_owned(),
            previous,
            event_authorization: None,
        };
        let first = signing_parent.path().join("first");
        sign_pages(&generated, &first, &config_for(&first, None)).unwrap();
        let second = signing_parent.path().join("second");
        sign_pages(&generated, &second, &config_for(&second, None)).unwrap();
        let first_targets: Value =
            serde_json::from_slice(&fs::read(first.join("v1/1.targets.json")).unwrap()).unwrap();
        let second_targets: Value =
            serde_json::from_slice(&fs::read(second.join("v1/1.targets.json")).unwrap()).unwrap();
        assert_eq!(
            canonical_json_bytes(first_targets.get("signed").unwrap()).unwrap(),
            canonical_json_bytes(second_targets.get("signed").unwrap()).unwrap()
        );

        let changed_repo = TempDir::new().unwrap();
        write_json(
            changed_repo.path(),
            "records/demo/hello/1.0.0.json",
            release(
                "1.0.0",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
        );
        let changed = generated_parent.path().join("changed");
        generate_pages(changed_repo.path(), &changed, &config()).unwrap();
        let rollback = sign_pages(
            &changed,
            &signing_parent.path().join("rollback"),
            &config_for(&changed, Some(first)),
        )
        .unwrap_err();
        assert!(
            rollback
                .to_string()
                .contains("changed while reusing version")
        );
    }
}
