//! Native runtime integration for durable principal-owned state.
//!
//! The legacy raw KV database is migrated under the kernel's singleton boot
//! lock. A durable store is not served until every legacy entry has been
//! imported, independently verified by owner, flushed, and covered by a
//! completion marker. The legacy database remains untouched as a recovery
//! source.

use std::cmp::Ordering;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_storage_engine::{
    DurableEngine, IdentityScheme, PersistentObjectIdentity, PrincipalCodec, RecoveryLimits,
};
use astrid_storage_model::{
    ObjectClass, ObjectFormatVersion, ObjectId, ObjectIdentity, ObjectKind, ObjectRecord,
    ReferenceKind,
};

use crate::error::{StorageError, StorageResult};
#[cfg(all(test, feature = "legacy-surrealkv"))]
use crate::kv::SurrealKvStore;
use crate::kv::{KvPrincipalResolver, KvQuotaResolver, KvStore, TreeKvStore};

const STORE_METADATA_FILE: &str = "store.meta";
const STORE_FORMAT_SPEC: &[u8] =
    include_bytes!("../../../docs/astrid-principal-store-format-v1.txt");

mod migrations;

/// Explicit owner of one durable state root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StateOwner {
    /// Kernel-owned state that must not consume a user's storage quota.
    System,
    /// State owned by one validated Astrid principal.
    Principal(PrincipalId),
}

impl Ord for StateOwner {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::System, Self::System) => Ordering::Equal,
            (Self::System, Self::Principal(_)) => Ordering::Less,
            (Self::Principal(_), Self::System) => Ordering::Greater,
            (Self::Principal(left), Self::Principal(right)) => left.as_str().cmp(right.as_str()),
        }
    }
}

impl PartialOrd for StateOwner {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Version-one canonical BLAKE3 identity for typed storage objects.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake3ObjectIdentityV1;

const BLAKE3_OBJECT_IDENTITY_V1_SCHEME: IdentityScheme = match IdentityScheme::new(1, 1) {
    Some(scheme) => scheme,
    None => panic!("the production identity scheme uses non-zero wire codes"),
};

impl ObjectIdentity for Blake3ObjectIdentityV1 {
    fn identify(&self, record: &ObjectRecord) -> ObjectId {
        let mut hasher =
            blake3::Hasher::new_derive_key("astrid principal store object identity v1");
        hasher.update(&record.kind().code().to_le_bytes());
        hasher.update(&record.format_version().get().to_le_bytes());
        hash_length(&mut hasher, record.canonical_bytes().len());
        hasher.update(record.canonical_bytes());
        hasher.update(&record.logical_bytes().to_le_bytes());
        hasher.update(&[match record.class() {
            ObjectClass::Data => 0,
            ObjectClass::Metadata => 1,
        }]);
        hash_length(&mut hasher, record.references().len());
        for reference in record.references() {
            hash_length(&mut hasher, reference.label().as_bytes().len());
            hasher.update(reference.label().as_bytes());
            hasher.update(reference.target().as_bytes());
            hasher.update(&[match reference.kind() {
                ReferenceKind::Owns => 0,
                ReferenceKind::Evidence => 1,
                ReferenceKind::Lineage => 2,
                ReferenceKind::Derived => 3,
            }]);
        }
        ObjectId::new(*hasher.finalize().as_bytes())
    }
}

impl PersistentObjectIdentity for Blake3ObjectIdentityV1 {
    fn scheme(&self) -> IdentityScheme {
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME
    }
}

fn hash_length(hasher: &mut blake3::Hasher, length: usize) {
    hasher.update(&(length as u128).to_le_bytes());
}

/// Canonical codec for [`StateOwner`].
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerCodecV1;

impl PrincipalCodec<StateOwner> for StateOwnerCodecV1 {
    fn encode(&self, owner: &StateOwner) -> Vec<u8> {
        match owner {
            StateOwner::System => vec![0],
            StateOwner::Principal(principal) => {
                let mut bytes = Vec::with_capacity(principal.as_str().len().saturating_add(1));
                bytes.push(1);
                bytes.extend_from_slice(principal.as_str().as_bytes());
                bytes
            },
        }
    }

    fn decode(&self, bytes: &[u8]) -> Option<StateOwner> {
        match bytes.split_first()? {
            (0, []) => Some(StateOwner::System),
            (1, principal) => std::str::from_utf8(principal)
                .ok()
                .and_then(|value| PrincipalId::new(value.to_owned()).ok())
                .map(StateOwner::Principal),
            _ => None,
        }
    }
}

/// Authority-aware mapping from live KV namespaces to durable owners.
#[derive(Clone, Copy, Debug, Default)]
pub struct StateOwnerResolver;

impl KvPrincipalResolver<StateOwner> for StateOwnerResolver {
    fn resolve(&self, namespace: &str) -> StorageResult<StateOwner> {
        let Some((principal, capsule)) = namespace.split_once(":capsule:") else {
            return Ok(StateOwner::System);
        };
        if capsule.is_empty() {
            return Err(StorageError::InvalidKey(
                "host-stamped capsule namespace has an empty capsule identifier".to_owned(),
            ));
        }
        PrincipalId::new(principal.to_owned())
            .map(StateOwner::Principal)
            .map_err(|error| {
                StorageError::InvalidKey(format!(
                    "capsule namespace has invalid host-stamped principal: {error}"
                ))
            })
    }
}

type RuntimeEngine = DurableEngine<StateOwner, Blake3ObjectIdentityV1, StateOwnerCodecV1>;
type RuntimeStore =
    TreeKvStore<StateOwner, Blake3ObjectIdentityV1, StateOwnerResolver, RuntimeEngine>;

/// Open the native kernel's authoritative KV store.
///
/// The caller must already hold the kernel singleton lock. On first cutover,
/// legacy state is imported and independently verified before the completion
/// marker is made durable. A partial prior destination is quarantined rather
/// than trusted or deleted.
///
/// # Errors
///
/// Returns a storage error if policy, metadata, migration, verification, or
/// durable recovery fails.
pub async fn open_runtime_kv(
    home: &AstridHome,
    quota: Arc<dyn KvQuotaResolver<StateOwner>>,
) -> StorageResult<Arc<dyn KvStore>> {
    let store_path = home.principal_store_path();
    let open_path = store_path.clone();
    let format_spec = format_spec_record()?;
    let format_spec_id = Blake3ObjectIdentityV1.identify(&format_spec);
    let metadata = store_metadata(format_spec_id);
    let engine = tokio::task::spawn_blocking(move || {
        let existing_complete = prepare_destination(&open_path, &metadata)?;
        let engine = RuntimeEngine::open(
            &open_path,
            Blake3ObjectIdentityV1,
            StateOwnerCodecV1,
            RecoveryLimits::process_addressable(),
        )
        .map_err(|error| {
            StorageError::Connection(format!("open durable principal store: {error}"))
        })?;
        match engine.object(format_spec_id).map_err(|error| {
            StorageError::Connection(format!("read in-band store format specification: {error}"))
        })? {
            Some(actual) if actual == format_spec => {},
            Some(_) => {
                return Err(StorageError::Connection(
                    "in-band store format specification does not match store.meta".to_owned(),
                ));
            },
            None if existing_complete => {
                return Err(StorageError::Connection(
                    "completed principal store is missing its in-band format specification"
                        .to_owned(),
                ));
            },
            None => {
                engine
                    .persist_standalone_object(&format_spec)
                    .map_err(|error| {
                        StorageError::Connection(format!(
                            "persist in-band store format specification: {error}"
                        ))
                    })?;
            },
        }
        Ok(engine)
    })
    .await
    .map_err(|error| {
        StorageError::Connection(format!(
            "durable principal-store open worker failed: {error}"
        ))
    })?
    .map(Arc::new)?;

    if !migrations::is_complete(&store_path) {
        migrations::apply_required(home, &store_path, &engine).await?;
    }

    Ok(Arc::new(RuntimeStore::from_engine_with_quota(
        engine,
        StateOwnerResolver,
        quota,
    )))
}

fn format_spec_record() -> StorageResult<ObjectRecord> {
    ObjectRecord::new(
        ObjectKind::Evidence,
        ObjectFormatVersion::V1,
        STORE_FORMAT_SPEC.to_vec(),
        Vec::new(),
        0,
        ObjectClass::Metadata,
    )
    .map_err(|error| {
        StorageError::Serialization(format!(
            "construct in-band store format specification: {error}"
        ))
    })
}

fn store_metadata(format_spec: ObjectId) -> Vec<u8> {
    let digest = object_id_hex(format_spec);
    format!(
        "format=astrid-principal-store-v1\n\
         identity=blake3-object-identity-v1\n\
         identity-wire=tagged-identity-v1\n\
         format-spec-object={}:{}:32:{digest}\n\
         principal-codec=state-owner-v1\n\
         projection=kv-tree-v3\n",
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.algorithm(),
        BLAKE3_OBJECT_IDENTITY_V1_SCHEME.construction(),
    )
    .into_bytes()
}

fn object_id_hex(id: ObjectId) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digest = String::with_capacity(64);
    for byte in id.as_bytes() {
        digest.push(char::from(HEX[usize::from(byte >> 4)]));
        digest.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    digest
}

fn prepare_destination(path: &Path, expected_metadata: &[u8]) -> StorageResult<bool> {
    let mut existing_complete = false;
    if path.exists() {
        if migrations::is_complete(path) {
            existing_complete = true;
        } else {
            quarantine_incomplete(path)?;
        }
    }
    std::fs::create_dir_all(path).map_err(|error| {
        StorageError::Connection(format!(
            "create principal store directory {}: {error}",
            path.display()
        ))
    })?;
    let metadata = path.join(STORE_METADATA_FILE);
    if metadata.exists() {
        let actual = std::fs::read(&metadata).map_err(|error| {
            StorageError::Connection(format!(
                "read principal store metadata {}: {error}",
                metadata.display()
            ))
        })?;
        if actual != expected_metadata {
            return Err(StorageError::Connection(format!(
                "principal store metadata at {} selects an unsupported format",
                metadata.display()
            )));
        }
    } else if existing_complete {
        return Err(StorageError::Connection(format!(
            "completed principal store at {} is missing format metadata",
            path.display()
        )));
    } else {
        atomic_write(&metadata, expected_metadata)?;
    }
    if existing_complete {
        for authoritative in ["objects.arena", "roots.journal"] {
            let required = path.join(authoritative);
            if !required.is_file() {
                return Err(StorageError::Connection(format!(
                    "completed principal store is missing authoritative file {}",
                    required.display()
                )));
            }
        }
    }
    Ok(existing_complete)
}

fn quarantine_incomplete(path: &Path) -> StorageResult<()> {
    let parent = path.parent().ok_or_else(|| {
        StorageError::Connection("principal store path has no parent directory".to_owned())
    })?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            StorageError::Connection("principal store path is not valid UTF-8".to_owned())
        })?;
    let mut suffix = 0_u64;
    let destination = loop {
        let candidate = parent.join(format!("{name}.incomplete.{suffix}"));
        if !candidate.exists() {
            break candidate;
        }
        suffix = suffix.checked_add(1).ok_or_else(|| {
            StorageError::Connection("too many incomplete principal stores".to_owned())
        })?;
    };
    std::fs::rename(path, &destination).map_err(|error| {
        StorageError::Connection(format!(
            "quarantine incomplete principal store {} as {}: {error}",
            path.display(),
            destination.display()
        ))
    })?;
    sync_directory(parent)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> StorageResult<()> {
    let parent = path.parent().ok_or_else(|| {
        StorageError::Connection(format!("path {} has no parent", path.display()))
    })?;
    std::fs::create_dir_all(parent).map_err(|error| {
        StorageError::Connection(format!("create directory {}: {error}", parent.display()))
    })?;
    let temporary = temporary_path(path);
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(|error| {
        StorageError::Connection(format!(
            "open temporary state file {}: {error}",
            temporary.display()
        ))
    })?;
    file.write_all(bytes).map_err(|error| {
        StorageError::Connection(format!(
            "write temporary state file {}: {error}",
            temporary.display()
        ))
    })?;
    file.sync_all().map_err(|error| {
        StorageError::Connection(format!(
            "flush temporary state file {}: {error}",
            temporary.display()
        ))
    })?;
    std::fs::rename(&temporary, path).map_err(|error| {
        StorageError::Connection(format!(
            "publish state file {} as {}: {error}",
            temporary.display(),
            path.display()
        ))
    })?;
    sync_directory(parent)
}

fn temporary_path(path: &Path) -> PathBuf {
    let mut name = path
        .file_name()
        .map_or_else(|| "state".into(), std::ffi::OsString::from);
    name.push(".tmp");
    path.with_file_name(name)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> StorageResult<()> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            StorageError::Connection(format!("flush directory {}: {error}", path.display()))
        })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> StorageResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use astrid_storage_model::{ObjectFormatVersion, ObjectKind};

    use super::*;

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) => Some(u64::MAX),
            })
        })
    }

    #[test]
    fn owner_codec_round_trips_only_canonical_values() {
        let codec = StateOwnerCodecV1;
        let owners = [
            StateOwner::System,
            StateOwner::Principal(PrincipalId::new("alice").unwrap()),
        ];
        for owner in owners {
            let encoded = codec.encode(&owner);
            assert_eq!(codec.decode(&encoded), Some(owner));
        }
        assert_eq!(codec.decode(&[]), None);
        assert_eq!(codec.decode(&[0, 0]), None);
        assert_eq!(codec.decode(&[1]), None);
        assert_eq!(codec.decode(&[1, b':']), None);
    }

    #[test]
    fn object_identity_v1_has_a_stable_golden_vector() {
        let record = ObjectRecord::new(
            ObjectKind::KvLeaf,
            ObjectFormatVersion::V1,
            b"hello".to_vec(),
            Vec::new(),
            0,
            ObjectClass::Data,
        )
        .unwrap();
        assert_eq!(
            Blake3ObjectIdentityV1.identify(&record).as_bytes(),
            &[
                14, 77, 237, 193, 155, 81, 194, 119, 35, 35, 59, 81, 40, 49, 0, 31, 232, 131, 137,
                111, 27, 237, 250, 91, 151, 7, 135, 21, 99, 27, 128, 55,
            ]
        );
    }

    #[test]
    fn format_specification_has_a_tagged_metadata_identity() {
        let record = format_spec_record().unwrap();
        let id = Blake3ObjectIdentityV1.identify(&record);
        let metadata = String::from_utf8(store_metadata(id)).unwrap();

        assert_eq!(record.kind(), ObjectKind::Evidence);
        assert_eq!(record.canonical_bytes(), STORE_FORMAT_SPEC);
        assert!(record.references().is_empty());
        assert!(metadata.contains("identity-wire=tagged-identity-v1\n"));
        assert!(metadata.contains(&format!(
            "format-spec-object=1:1:32:{}\n",
            object_id_hex(id)
        )));
    }

    #[tokio::test]
    async fn new_store_persists_and_verifies_the_in_band_specification() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
        store.close().await.unwrap();
        drop(store);

        let record = format_spec_record().unwrap();
        let id = Blake3ObjectIdentityV1.identify(&record);
        let arena = std::fs::read(home.principal_store_path().join("objects.arena")).unwrap();
        assert_eq!(&arena[52..54], &1_u16.to_le_bytes());
        assert_eq!(&arena[54..56], &1_u16.to_le_bytes());
        assert_eq!(&arena[56..60], &32_u32.to_le_bytes());
        assert_eq!(&arena[60..92], id.as_bytes());

        let engine = RuntimeEngine::open(
            home.principal_store_path(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV1,
            RecoveryLimits::process_addressable(),
        )
        .unwrap();
        assert_eq!(engine.object(id).unwrap(), Some(record));
    }

    #[cfg(not(target_os = "windows"))]
    #[tokio::test]
    async fn independent_reader_accepts_a_rust_produced_store() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
        store
            .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
            .await
            .unwrap();
        store.close().await.unwrap();
        drop(store);

        let script = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../scripts/principal_store_v1_reader.py");
        let output = std::process::Command::new("python3")
            .arg(script)
            .arg(home.principal_store_path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "independent reader failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let decoded: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decoded["roots"]["alice"]["generation"], 0);
        assert!(
            decoded["roots"]["alice"]["commit"]
                .as_str()
                .unwrap()
                .starts_with("1:1:32:")
        );
        assert!(
            decoded["objects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|object| object["kind"] == "Evidence")
        );
        assert!(
            decoded["objects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|object| object["kind"] == "Commit")
        );

        let arena_path = home.principal_store_path().join("objects.arena");
        let mut arena = std::fs::read(&arena_path).unwrap();
        arena[100] ^= 0x80;
        std::fs::write(&arena_path, arena).unwrap();
        let rejected = std::process::Command::new("python3")
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../scripts/principal_store_v1_reader.py"),
            )
            .arg(home.principal_store_path())
            .output()
            .unwrap();
        assert!(
            !rejected.status.success(),
            "independent reader accepted a corrupt Rust-produced store"
        );
    }

    #[tokio::test]
    async fn completed_store_does_not_self_heal_a_missing_rosetta_object() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let path = home.principal_store_path();
        std::fs::create_dir_all(&path).unwrap();
        let record = format_spec_record().unwrap();
        let id = Blake3ObjectIdentityV1.identify(&record);
        std::fs::write(path.join(STORE_METADATA_FILE), store_metadata(id)).unwrap();
        drop(
            RuntimeEngine::open(
                &path,
                Blake3ObjectIdentityV1,
                StateOwnerCodecV1,
                RecoveryLimits::process_addressable(),
            )
            .unwrap(),
        );
        std::fs::write(
            path.join(migrations::MIGRATION_MARKER_FILE),
            b"migration=surrealkv-to-principal-store\nfrom=legacy\nto=1\n",
        )
        .unwrap();

        let Err(error) = open_runtime_kv(&home, unlimited_quota()).await else {
            panic!("completed store without its Rosetta object was accepted");
        };
        assert!(
            error
                .to_string()
                .contains("missing its in-band format specification")
        );
    }

    #[test]
    fn namespace_owner_fails_closed_at_the_host_stamped_boundary() {
        let resolver = StateOwnerResolver;
        assert_eq!(
            resolver.resolve("system:identity").unwrap(),
            StateOwner::System
        );
        assert_eq!(
            resolver.resolve("alice:capsule:shell").unwrap(),
            StateOwner::Principal(PrincipalId::new("alice").unwrap())
        );
        assert!(matches!(
            resolver.resolve("alice:capsule:"),
            Err(StorageError::InvalidKey(message))
                if message.contains("empty capsule identifier")
        ));
    }

    #[cfg(feature = "legacy-surrealkv")]
    #[tokio::test]
    async fn first_boot_migrates_verifies_and_preserves_legacy_state() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let legacy = SurrealKvStore::open(home.state_db_path()).unwrap();
        legacy
            .set("system:identity", "root", b"default".to_vec())
            .await
            .unwrap();
        legacy
            .set("alice:capsule:shell", "cwd", b"/workspace".to_vec())
            .await
            .unwrap();
        legacy
            .set("bob:capsule:build", "toolchain", b"rust".to_vec())
            .await
            .unwrap();
        legacy.close().await.unwrap();

        let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
        assert_eq!(
            store.get("system:identity", "root").await.unwrap(),
            Some(b"default".to_vec())
        );
        assert_eq!(
            store.get("alice:capsule:shell", "cwd").await.unwrap(),
            Some(b"/workspace".to_vec())
        );
        assert_eq!(
            store.get("bob:capsule:build", "toolchain").await.unwrap(),
            Some(b"rust".to_vec())
        );
        assert!(
            home.principal_store_path()
                .join(migrations::MIGRATION_MARKER_FILE)
                .exists()
        );
        store.close().await.unwrap();
        drop(store);

        let legacy = SurrealKvStore::open(home.state_db_path()).unwrap();
        assert_eq!(
            legacy.get("alice:capsule:shell", "cwd").await.unwrap(),
            Some(b"/workspace".to_vec())
        );
        legacy
            .set("alice:capsule:shell", "legacy-only", b"stale".to_vec())
            .await
            .unwrap();
        legacy.close().await.unwrap();

        let reopened = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
        assert_eq!(
            reopened
                .get("alice:capsule:shell", "legacy-only")
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            reopened.get("alice:capsule:shell", "cwd").await.unwrap(),
            Some(b"/workspace".to_vec())
        );
    }

    #[tokio::test]
    async fn live_quota_blocks_growth_but_allows_recovery_and_system_state() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) => Some(27),
            })
        });
        let store = open_runtime_kv(&home, quota).await.unwrap();

        store
            .set("alice:capsule:shell", "one", b"1234".to_vec())
            .await
            .unwrap();
        assert!(matches!(
            store.set("alice:capsule:shell", "two", b"5".to_vec()).await,
            Err(StorageError::Internal(message))
                if message
                    == "storage quota exceeded: mutation would use 51 bytes (limit 27)"
        ));
        store
            .set("alice:capsule:shell", "one", b"123".to_vec())
            .await
            .unwrap();
        assert!(store.delete("alice:capsule:shell", "one").await.unwrap());
        store
            .set("alice:capsule:shell", "two", b"1234".to_vec())
            .await
            .unwrap();
        assert!(matches!(
            store.set("alice:capsule:shell", "empty", Vec::new()).await,
            Err(StorageError::Internal(message))
                if message
                    == "storage quota exceeded: mutation would use 52 bytes (limit 27)"
        ));
        store
            .set("system:identity", "unmetered", vec![0; 64])
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn incomplete_destination_is_quarantined_before_reimport() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        std::fs::create_dir_all(home.principal_store_path()).unwrap();
        std::fs::write(home.principal_store_path().join("partial"), b"incomplete").unwrap();

        let store = open_runtime_kv(&home, unlimited_quota()).await.unwrap();
        assert!(
            home.var_dir()
                .join("principal-store.incomplete.0")
                .join("partial")
                .exists()
        );
        assert!(
            home.principal_store_path()
                .join(migrations::MIGRATION_MARKER_FILE)
                .exists()
        );
        drop(store);
    }

    #[cfg(not(feature = "legacy-surrealkv"))]
    #[tokio::test]
    async fn legacy_source_requires_the_transition_feature() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        std::fs::create_dir_all(home.state_db_path()).unwrap();

        let error = match open_runtime_kv(&home, unlimited_quota()).await {
            Err(error) => error,
            Ok(_) => panic!("legacy source opened without transition support"),
        };
        assert!(
            error
                .to_string()
                .contains("rebuild with the legacy-surrealkv feature")
        );
    }

    #[tokio::test]
    async fn durable_point_update_has_height_bounded_write_amplification() {
        let directory = tempfile::tempdir().unwrap();
        let limits = RecoveryLimits::new(1024 * 1024).unwrap();
        let engine = Arc::new(
            RuntimeEngine::open(
                directory.path(),
                Blake3ObjectIdentityV1,
                StateOwnerCodecV1,
                limits,
            )
            .unwrap(),
        );
        let store = RuntimeStore::from_engine(Arc::clone(&engine), StateOwnerResolver);
        for value in 0..256_u32 {
            store
                .set(
                    "alice:capsule:build",
                    &format!("{value:04}"),
                    value.to_le_bytes().to_vec(),
                )
                .await
                .unwrap();
        }
        let before = engine.object_count().unwrap();
        store
            .set("alice:capsule:build", "0128", b"replacement".to_vec())
            .await
            .unwrap();
        let inserted = engine.object_count().unwrap().saturating_sub(before);
        assert!(
            inserted <= 16,
            "one point update inserted {inserted} objects for a 256-key tree"
        );
        store.close().await.unwrap();
        drop(store);
        drop(engine);

        let reopened = Arc::new(
            RuntimeEngine::open(
                directory.path(),
                Blake3ObjectIdentityV1,
                StateOwnerCodecV1,
                limits,
            )
            .unwrap(),
        );
        let store = RuntimeStore::from_engine(reopened, StateOwnerResolver);
        assert_eq!(
            store.get("alice:capsule:build", "0128").await.unwrap(),
            Some(b"replacement".to_vec())
        );
    }
}
