//! Durable per-owner installed-capsule package registry.
//!
//! Capsule packages are deliberately stored as three fixed names in the
//! owner's Astrid content catalog: the canonical `.capsule` bytes, the exact
//! install metadata bytes, and the exact authority receipt bytes. The package
//! archive remains opaque to storage; capsule-install validates and interprets
//! it. Publishing those names in one content batch makes an install/update a
//! single owner-root transition. Removal uses the matching atomic batch delete
//! primitive, so a partial package is never intentionally published.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Cursor;
use std::sync::Arc;

use crate::content::{
    ContentBatchExpectation, ContentIngest, ContentName, PrincipalContentError,
    PrincipalContentStore,
};
use crate::engine::PrincipalProjectionEngine;

/// Prefix reserved for durable installed-capsule packages.
pub const CAPSULES_PREFIX: &str = "capsules";
const ARCHIVE_BASENAME: &str = "package.capsule";
const META_BASENAME: &str = "meta.json";
const AUTHORITY_BASENAME: &str = "authority.json";

/// The three fixed content files making up one installed package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsulePackage {
    /// Canonical `.capsule` archive bytes.
    pub archive: Vec<u8>,
    /// Exact install metadata bytes.
    pub metadata: Vec<u8>,
    /// Exact authority receipt bytes.
    pub authority: Vec<u8>,
}

impl CapsulePackage {
    /// Construct a package from its canonical bytes.
    #[must_use]
    pub const fn new(archive: Vec<u8>, metadata: Vec<u8>, authority: Vec<u8>) -> Self {
        Self {
            archive,
            metadata,
            authority,
        }
    }

    fn is_empty(&self) -> bool {
        self.archive.is_empty() || self.metadata.is_empty() || self.authority.is_empty()
    }
}

/// Digest and size summary for one durable package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsulePackageSummary {
    id: String,
    archive_digest: [u8; 32],
    metadata_digest: [u8; 32],
    authority_digest: [u8; 32],
    archive_bytes: u64,
    metadata_bytes: u64,
    authority_bytes: u64,
}

/// Immutable object IDs for all fixed files in one package generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapsulePackageGeneration {
    archive: crate::storage_model::ObjectId,
    metadata: crate::storage_model::ObjectId,
    authority: crate::storage_model::ObjectId,
}

impl CapsulePackageGeneration {
    /// Return the archive object ID.
    #[must_use]
    pub const fn archive(&self) -> crate::storage_model::ObjectId {
        self.archive
    }

    /// Return the metadata object ID.
    #[must_use]
    pub const fn metadata(&self) -> crate::storage_model::ObjectId {
        self.metadata
    }

    /// Return the authority object ID.
    #[must_use]
    pub const fn authority(&self) -> crate::storage_model::ObjectId {
        self.authority
    }
}

/// Package bytes and the exact owner-root generation they came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapsulePackageSnapshot {
    package: CapsulePackage,
    generation: CapsulePackageGeneration,
}

impl CapsulePackageSnapshot {
    /// Borrow the package bytes.
    #[must_use]
    pub const fn package(&self) -> &CapsulePackage {
        &self.package
    }

    /// Return the immutable generation token for conditional mutation.
    #[must_use]
    pub const fn generation(&self) -> CapsulePackageGeneration {
        self.generation
    }
}

/// Atomic install/remove expectation for one capsule identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapsuleInstallExpectation {
    /// Permit the operation against any current package generation.
    Any,
    /// Permit only when all fixed package names are currently absent.
    Absent,
    /// Permit only when the current archive has this digest.
    ArchiveDigest([u8; 32]),
    /// Permit only when all fixed names have this exact object generation.
    Generation(CapsulePackageGeneration),
}

impl CapsulePackageSummary {
    /// Return the canonical capsule identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Return the archive digest.
    #[must_use]
    pub const fn archive_digest(&self) -> [u8; 32] {
        self.archive_digest
    }

    /// Return the metadata digest.
    #[must_use]
    pub const fn metadata_digest(&self) -> [u8; 32] {
        self.metadata_digest
    }

    /// Return the authority receipt digest.
    #[must_use]
    pub const fn authority_digest(&self) -> [u8; 32] {
        self.authority_digest
    }

    /// Return the archive byte length.
    #[must_use]
    pub const fn archive_bytes(&self) -> u64 {
        self.archive_bytes
    }

    /// Return the metadata byte length.
    #[must_use]
    pub const fn metadata_bytes(&self) -> u64 {
        self.metadata_bytes
    }

    /// Return the authority byte length.
    #[must_use]
    pub const fn authority_bytes(&self) -> u64 {
        self.authority_bytes
    }
}

/// Failure to inspect or mutate the durable capsule catalog.
#[derive(Debug, thiserror::Error)]
pub enum CapsuleRegistryError {
    /// Capsule identifier is not in the canonical lowercase/hyphen grammar.
    #[error("invalid capsule identifier: {0}")]
    InvalidId(String),
    /// A package had an empty fixed file or an incomplete catalog set.
    #[error("invalid durable capsule package: {0}")]
    InvalidPackage(String),
    /// The caller supplied an old digest that no longer identifies the
    /// currently installed package.
    #[error("capsule package conflict for {id}")]
    Conflict {
        /// Conflicting capsule identifier.
        id: String,
    },
    /// The underlying owner content projection failed.
    #[error("durable capsule content: {0}")]
    Content(#[source] PrincipalContentError),
}

impl From<PrincipalContentError> for CapsuleRegistryError {
    fn from(error: PrincipalContentError) -> Self {
        Self::Content(error)
    }
}

/// Durable installed-capsule registry bound to one principal-content engine.
pub struct CapsuleRegistry<P: Ord, E> {
    content: Arc<PrincipalContentStore<P, E>>,
}

impl<P: Ord, E> Clone for CapsuleRegistry<P, E> {
    fn clone(&self) -> Self {
        Self {
            content: Arc::clone(&self.content),
        }
    }
}

impl<P, E> fmt::Debug for CapsuleRegistry<P, E>
where
    P: Ord,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CapsuleRegistry")
            .finish_non_exhaustive()
    }
}

impl<P, E> CapsuleRegistry<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Bind the registry to an authoritative named-content projection.
    #[must_use]
    pub fn new(content: Arc<PrincipalContentStore<P, E>>) -> Self {
        Self { content }
    }

    /// List complete package summaries for one owner.
    ///
    /// Any malformed or partial `capsules/` set fails closed instead of being
    /// silently ignored. This prevents a tampered package from being treated
    /// as an absent install after restart.
    ///
    /// # Errors
    ///
    /// Returns an error when a reserved catalog name is malformed, a package
    /// is incomplete, or the owner content graph cannot be decoded.
    pub fn list(&self, owner: &P) -> Result<Vec<CapsulePackageSummary>, CapsuleRegistryError> {
        let entries = self.content.list_prefix(owner, "capsules/")?;
        let mut ids = BTreeSet::new();
        for entry in entries {
            if let Some(id) = parse_reserved_name(entry.name().as_str())? {
                ids.insert(id);
            }
        }
        ids.into_iter().map(|id| self.summary(owner, &id)).collect()
    }

    /// Read one complete package, if installed for the owner.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identifier, malformed reserved names,
    /// incomplete package files, or a content-graph read failure.
    pub fn get(&self, owner: &P, id: &str) -> Result<Option<CapsulePackage>, CapsuleRegistryError> {
        Ok(self
            .get_snapshot(owner, id)?
            .map(|snapshot| snapshot.package))
    }

    /// Read one package and capture all three fixed object IDs from one
    /// owner-root snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identifier, malformed reserved names,
    /// incomplete package files, or a content-graph read failure.
    pub fn get_snapshot(
        &self,
        owner: &P,
        id: &str,
    ) -> Result<Option<CapsulePackageSnapshot>, CapsuleRegistryError> {
        validate_id(id)?;
        let names = package_names(id)?;
        let files = self.content.read_batch(owner, &names)?;
        match files.as_slice() {
            [None, None, None] => Ok(None),
            [Some(archive), Some(metadata), Some(authority)] => {
                let package = CapsulePackage::new(
                    archive.bytes().to_vec(),
                    metadata.bytes().to_vec(),
                    authority.bytes().to_vec(),
                );
                if package.is_empty() {
                    return Err(CapsuleRegistryError::InvalidPackage(
                        "fixed package file is empty".to_owned(),
                    ));
                }
                Ok(Some(CapsulePackageSnapshot {
                    package,
                    generation: CapsulePackageGeneration {
                        archive: archive.descriptor().file(),
                        metadata: metadata.descriptor().file(),
                        authority: authority.descriptor().file(),
                    },
                }))
            },
            _ => Err(CapsuleRegistryError::InvalidPackage(format!(
                "package {id} does not contain all fixed files"
            ))),
        }
    }

    /// Install or atomically replace one package.
    ///
    /// The expectation is checked against the same owner-root snapshot used
    /// for publication. A byte-for-byte retry is idempotent and avoids another
    /// root publication.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identifier, empty package file,
    /// expectation conflict, malformed owner content, quota rejection, or a
    /// failed atomic publication.
    pub fn install(
        &self,
        owner: &P,
        id: &str,
        package: &CapsulePackage,
        expectation: CapsuleInstallExpectation,
    ) -> Result<CapsulePackageSummary, CapsuleRegistryError> {
        validate_id(id)?;
        if package.is_empty() {
            return Err(CapsuleRegistryError::InvalidPackage(
                "fixed package file is empty".to_owned(),
            ));
        }
        let existing = self.get_snapshot(owner, id)?;
        match expectation {
            CapsuleInstallExpectation::Absent if existing.is_some() => {
                return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
            },
            CapsuleInstallExpectation::Any | CapsuleInstallExpectation::Absent => {},
            CapsuleInstallExpectation::ArchiveDigest(expected) => {
                let Some(current) = existing.as_ref() else {
                    return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
                };
                if digest(&current.package.archive) != expected {
                    return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
                }
            },
            CapsuleInstallExpectation::Generation(expected) => {
                let Some(current) = existing.as_ref() else {
                    return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
                };
                if current.generation != expected {
                    return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
                }
            },
        }
        if existing
            .as_ref()
            .is_some_and(|current| current.package == *package)
        {
            return Ok(summary_for(id, package));
        }
        let names = package_names(id)?;
        let expected_entries = expected_entries(id, expectation, existing.as_ref())?;
        self.content.put_streaming_batch_with_expectation(
            owner,
            [
                ContentIngest::new(names[0].clone(), Cursor::new(package.archive.clone())),
                ContentIngest::new(names[1].clone(), Cursor::new(package.metadata.clone())),
                ContentIngest::new(names[2].clone(), Cursor::new(package.authority.clone())),
            ],
            &ContentBatchExpectation::exact(expected_entries),
        )?;
        Ok(summary_for(id, package))
    }

    /// Remove one package in one owner-root transition.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identifier, malformed package, or
    /// failed atomic content mutation.
    pub fn remove(&self, owner: &P, id: &str) -> Result<bool, CapsuleRegistryError> {
        self.remove_checked(owner, id, CapsuleInstallExpectation::Any)
    }

    /// Remove one package only when its current generation matches the
    /// supplied expectation.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid identifier, expectation conflict,
    /// malformed package, or failed atomic content mutation.
    pub fn remove_checked(
        &self,
        owner: &P,
        id: &str,
        expectation: CapsuleInstallExpectation,
    ) -> Result<bool, CapsuleRegistryError> {
        validate_id(id)?;
        let names = package_names(id)?;
        let existing = self.get_snapshot(owner, id)?;
        if matches!(expectation, CapsuleInstallExpectation::Absent) && existing.is_some() {
            return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
        }
        if let CapsuleInstallExpectation::ArchiveDigest(expected) = expectation {
            let Some(current) = existing.as_ref() else {
                return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
            };
            if digest(&current.package.archive) != expected {
                return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
            }
        }
        if let CapsuleInstallExpectation::Generation(expected) = expectation {
            let Some(current) = existing.as_ref() else {
                return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
            };
            if current.generation != expected {
                return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
            }
        }
        let expected_entries = expected_entries(id, expectation, existing.as_ref())?;
        self.content
            .delete_batch_if(
                owner,
                &names,
                &ContentBatchExpectation::exact(expected_entries),
            )
            .map_err(Into::into)
    }

    /// Read the current package summary without exposing package bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the package is absent, malformed, or unreadable.
    pub fn summary(
        &self,
        owner: &P,
        id: &str,
    ) -> Result<CapsulePackageSummary, CapsuleRegistryError> {
        let package = self.get(owner, id)?.ok_or_else(|| {
            CapsuleRegistryError::InvalidPackage(format!("package {id} is not installed"))
        })?;
        Ok(summary_for(id, &package))
    }
}

impl<P, E> CapsuleRegistry<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Return the fixed catalog names for one validated identifier.
    ///
    /// # Errors
    ///
    /// Returns an error when `id` is not in the canonical identifier grammar.
    pub fn names(id: &str) -> Result<[ContentName; 3], CapsuleRegistryError> {
        package_names(id)
    }
}

fn expected_entries(
    id: &str,
    expectation: CapsuleInstallExpectation,
    existing: Option<&CapsulePackageSnapshot>,
) -> Result<Vec<(ContentName, Option<crate::storage_model::ObjectId>)>, CapsuleRegistryError> {
    let names = package_names(id)?;
    if matches!(expectation, CapsuleInstallExpectation::Any) {
        return Ok(Vec::new());
    }
    if matches!(expectation, CapsuleInstallExpectation::Absent) {
        return Ok(names.into_iter().map(|name| (name, None)).collect());
    }
    let Some(existing) = existing else {
        return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
    };
    if let CapsuleInstallExpectation::Generation(expected) = expectation
        && existing.generation != expected
    {
        return Err(CapsuleRegistryError::Conflict { id: id.to_owned() });
    }
    names
        .into_iter()
        .map(|name| {
            let index = match name.as_str().rsplit('/').next() {
                Some("package.capsule") => existing.generation.archive,
                Some("meta.json") => existing.generation.metadata,
                Some("authority.json") => existing.generation.authority,
                _ => {
                    return Err(CapsuleRegistryError::InvalidPackage(format!(
                        "package {id} has an unknown fixed name"
                    )));
                },
            };
            Ok((name, Some(index)))
        })
        .collect()
}

fn validate_id(id: &str) -> Result<(), CapsuleRegistryError> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(CapsuleRegistryError::InvalidId(id.to_owned()));
    }
    Ok(())
}

fn package_names(id: &str) -> Result<[ContentName; 3], CapsuleRegistryError> {
    validate_id(id)?;
    let prefix = format!("{CAPSULES_PREFIX}/{id}");
    Ok([
        ContentName::new(format!("{prefix}/{ARCHIVE_BASENAME}"))?,
        ContentName::new(format!("{prefix}/{META_BASENAME}"))?,
        ContentName::new(format!("{prefix}/{AUTHORITY_BASENAME}"))?,
    ])
}

fn parse_reserved_name(name: &str) -> Result<Option<String>, CapsuleRegistryError> {
    let mut pieces = name.split('/');
    let Some(prefix) = pieces.next() else {
        return Ok(None);
    };
    if prefix != CAPSULES_PREFIX {
        return Ok(None);
    }
    let Some(id) = pieces.next() else {
        return Err(CapsuleRegistryError::InvalidPackage(
            "reserved capsule path is missing an identifier".to_owned(),
        ));
    };
    let Some(file) = pieces.next() else {
        return Err(CapsuleRegistryError::InvalidPackage(format!(
            "reserved capsule path {name} is missing a fixed file"
        )));
    };
    if pieces.next().is_some() {
        return Err(CapsuleRegistryError::InvalidPackage(format!(
            "reserved capsule path {name} has extra components"
        )));
    }
    validate_id(id)?;
    if !matches!(file, ARCHIVE_BASENAME | META_BASENAME | AUTHORITY_BASENAME) {
        return Err(CapsuleRegistryError::InvalidPackage(format!(
            "reserved capsule path {name} has an unknown fixed file"
        )));
    }
    Ok(Some(id.to_owned()))
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn summary_for(id: &str, package: &CapsulePackage) -> CapsulePackageSummary {
    CapsulePackageSummary {
        id: id.to_owned(),
        archive_digest: digest(&package.archive),
        metadata_digest: digest(&package.metadata),
        authority_digest: digest(&package.authority),
        archive_bytes: package.archive.len() as u64,
        metadata_bytes: package.metadata.len() as u64,
        authority_bytes: package.authority.len() as u64,
    }
}

impl From<crate::content::ContentNameError> for CapsuleRegistryError {
    fn from(error: crate::content::ContentNameError) -> Self {
        Self::InvalidPackage(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use crate::kv::KvQuotaResolver;
    use crate::{StateOwner, open_runtime_principal_store};
    use astrid_core::dirs::AstridHome;
    use astrid_core::identity::PrincipalUid;

    #[test]
    fn fixed_names_and_id_grammar_are_canonical() {
        let names = package_names("demo-cap").unwrap();
        assert_eq!(names[0].as_str(), "capsules/demo-cap/package.capsule");
        assert_eq!(names[1].as_str(), "capsules/demo-cap/meta.json");
        assert_eq!(names[2].as_str(), "capsules/demo-cap/authority.json");
        assert!(matches!(
            validate_id("Demo"),
            Err(CapsuleRegistryError::InvalidId(_))
        ));
        assert!(matches!(
            validate_id("a/b"),
            Err(CapsuleRegistryError::InvalidId(_))
        ));
    }

    #[test]
    fn reserved_catalog_paths_fail_closed() {
        assert_eq!(parse_reserved_name("other/value").unwrap(), None);
        assert_eq!(
            parse_reserved_name("capsules/demo-cap/meta.json").unwrap(),
            Some("demo-cap".to_owned())
        );
        assert!(parse_reserved_name("capsules/demo-cap/extra").is_err());
        assert!(parse_reserved_name("capsules/demo-cap/meta.json/trailing").is_err());
    }

    fn unlimited_quota() -> Arc<dyn KvQuotaResolver<StateOwner>> {
        Arc::new(|owner: &StateOwner| {
            Ok(match owner {
                StateOwner::System => None,
                StateOwner::Principal(_) | StateOwner::Fleet(_) => Some(u64::MAX),
            })
        })
    }

    fn owner(byte: u8) -> StateOwner {
        StateOwner::Principal(PrincipalUid::from_bytes([byte; 32]))
    }

    fn package(byte: u8) -> CapsulePackage {
        CapsulePackage::new(vec![byte, 1], vec![byte, 2], vec![byte, 3])
    }

    #[tokio::test]
    async fn package_is_idempotent_reopenable_and_uid_isolated() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let registry = store.capsules();
        let alice = owner(1);
        let bob = owner(2);
        let first = registry
            .install(
                &alice,
                "demo-cap",
                &package(7),
                CapsuleInstallExpectation::Absent,
            )
            .unwrap();
        for index in 0..128 {
            let name = ContentName::new(format!("home/unrelated/{index:03}"))
                .expect("canonical unrelated content name");
            store
                .content()
                .put(&alice, &name, b"home")
                .expect("write unrelated content");
        }
        let capsule_entries = store.content().list_prefix(&alice, "capsules/").unwrap();
        assert_eq!(capsule_entries.len(), 3);
        assert!(
            capsule_entries
                .iter()
                .all(|entry| entry.name().as_str().starts_with("capsules/"))
        );
        let retry = registry
            .install(
                &alice,
                "demo-cap",
                &package(7),
                CapsuleInstallExpectation::Any,
            )
            .unwrap();
        assert_eq!(first, retry);
        assert_eq!(registry.get(&bob, "demo-cap").unwrap(), None);
        drop(registry);
        drop(store);

        let reopened = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let reopened_registry = reopened.capsules();
        assert_eq!(
            reopened_registry.get(&alice, "demo-cap").unwrap(),
            Some(package(7))
        );
        assert_eq!(reopened_registry.list(&alice).unwrap().len(), 1);
        assert!(reopened_registry.remove(&alice, "demo-cap").unwrap());
        assert!(!reopened_registry.remove(&alice, "demo-cap").unwrap());
    }

    #[tokio::test]
    async fn stale_expected_digest_is_rejected_without_replacing_package() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let registry = store.capsules();
        let alice = owner(3);
        registry
            .install(
                &alice,
                "demo-cap",
                &package(1),
                CapsuleInstallExpectation::Absent,
            )
            .unwrap();
        let error = registry
            .install(
                &alice,
                "demo-cap",
                &package(2),
                CapsuleInstallExpectation::ArchiveDigest([0; 32]),
            )
            .unwrap_err();
        assert!(matches!(error, CapsuleRegistryError::Conflict { .. }));
        assert_eq!(registry.get(&alice, "demo-cap").unwrap(), Some(package(1)));
    }

    #[tokio::test]
    async fn stale_generation_cannot_overwrite_concurrent_update() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let registry = store.capsules();
        let alice = owner(5);
        registry
            .install(
                &alice,
                "demo-cap",
                &package(1),
                CapsuleInstallExpectation::Absent,
            )
            .unwrap();
        let generation = registry
            .get_snapshot(&alice, "demo-cap")
            .unwrap()
            .unwrap()
            .generation();
        registry
            .install(
                &alice,
                "demo-cap",
                &package(2),
                CapsuleInstallExpectation::Generation(generation),
            )
            .unwrap();
        let error = registry
            .install(
                &alice,
                "demo-cap",
                &package(3),
                CapsuleInstallExpectation::Generation(generation),
            )
            .unwrap_err();
        assert!(matches!(error, CapsuleRegistryError::Conflict { .. }));
        assert_eq!(registry.get(&alice, "demo-cap").unwrap(), Some(package(2)));
    }

    #[tokio::test]
    async fn partial_reserved_package_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(directory.path());
        let store = open_runtime_principal_store(&home, unlimited_quota())
            .await
            .unwrap();
        let owner = owner(4);
        let names = package_names("demo-cap").unwrap();
        store.content().put(&owner, &names[0], b"archive").unwrap();
        assert!(matches!(
            store.capsules().list(&owner),
            Err(CapsuleRegistryError::InvalidPackage(_))
        ));
    }
}
