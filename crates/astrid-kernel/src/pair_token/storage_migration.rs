use std::path::Path;

use super::{PairToken, PersistedFile, STORE_SCHEMA_VERSION, SchemaProbe, canonical_fingerprint};

pub(super) fn read_legacy_source(
    path: &Path,
    principals: &astrid_storage::PrincipalDirectory,
) -> astrid_storage::StorageResult<Option<(Vec<u8>, Vec<PairToken>)>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(astrid_storage::StorageError::Connection(error.to_string())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(astrid_storage::StorageError::InvalidKey(
            "legacy pair-token source is not a regular file".to_owned(),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)
        .and_then(|()| astrid_core::platform_fs::validate_private_file(path))
        .map_err(|_| {
            astrid_storage::StorageError::InvalidKey(
                "legacy pair-token source is not private".to_owned(),
            )
        })?;
    if metadata.len() > super::MAX_LEGACY_BYTES {
        return Err(astrid_storage::StorageError::Serialization(
            "legacy pair-token source exceeds its bounded size".to_owned(),
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| astrid_storage::StorageError::Connection(error.to_string()))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        astrid_storage::StorageError::Serialization(
            "legacy pair-token source is not UTF-8".to_owned(),
        )
    })?;
    let probe: SchemaProbe = toml::from_str(text).map_err(|_| {
        astrid_storage::StorageError::Serialization(
            "legacy pair-token source is malformed".to_owned(),
        )
    })?;
    if probe.schema_version != STORE_SCHEMA_VERSION {
        return Err(astrid_storage::StorageError::Serialization(
            "legacy pair-token source schema is unsupported".to_owned(),
        ));
    }
    let parsed: PersistedFile = toml::from_str(text).map_err(|_| {
        astrid_storage::StorageError::Serialization(
            "legacy pair-token source is malformed".to_owned(),
        )
    })?;
    if parsed.pair_token.len() > super::MAX_RECORDS {
        return Err(astrid_storage::StorageError::Serialization(
            "legacy pair-token source exceeds its bounded record limit".to_owned(),
        ));
    }
    for token in &parsed.pair_token {
        if canonical_fingerprint(&token.token_hash).is_none()
            || token.expires_at_epoch <= token.issued_at_epoch
            || token.expires_at_epoch.saturating_sub(token.issued_at_epoch) > super::MAX_EXPIRY_SECS
            || token.label.as_ref().is_some_and(|label| label.len() > 4096)
            || principals.uid_for(&token.principal).is_err()
        {
            return Err(astrid_storage::StorageError::Serialization(
                "legacy pair-token source contains an invalid or unadmitted record".to_owned(),
            ));
        }
    }
    Ok(Some((bytes, parsed.pair_token)))
}

pub(super) fn retire_legacy_file(
    path: &Path,
    expected_digest: &str,
) -> astrid_storage::StorageResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(astrid_storage::StorageError::InvalidKey(
                    "legacy pair-token source changed during retirement".to_owned(),
                ));
            }
            astrid_core::platform_fs::verify_no_redirects(path)
                .and_then(|()| astrid_core::platform_fs::validate_private_file(path))
                .map_err(|_| {
                    astrid_storage::StorageError::InvalidKey(
                        "legacy pair-token source changed during retirement".to_owned(),
                    )
                })?;
            let bytes = std::fs::read(path)
                .map_err(|error| astrid_storage::StorageError::Connection(error.to_string()))?;
            let digest = format!("blake3:{}", blake3::hash(&bytes).to_hex());
            if digest != expected_digest {
                return Err(astrid_storage::StorageError::Internal(
                    "legacy pair-token source changed during retirement".to_owned(),
                ));
            }
            std::fs::remove_file(path)
                .map_err(|error| astrid_storage::StorageError::Connection(error.to_string()))?;
            #[cfg(unix)]
            if let Some(parent) = path.parent()
                && let Ok(directory) = std::fs::File::open(parent)
            {
                let _ = directory.sync_all();
            }
            Ok(())
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(astrid_storage::StorageError::Connection(error.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use astrid_core::DeviceScope;
    use astrid_core::PrincipalId;
    use astrid_core::dirs::AstridHome;
    use astrid_core::identity::PrincipalUid;
    use astrid_storage::{KvStore, MemoryKvStore};
    use tempfile::TempDir;

    use super::super::{
        DurablePairToken, DurablePairTokenStore, PairToken, PairTokenStore, hash_token, now_epoch,
    };

    #[cfg(unix)]
    fn private_write(path: &std::path::Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[tokio::test]
    async fn concurrent_redeem_has_one_winner() {
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurablePairTokenStore::new(Arc::clone(&backend)).unwrap();
        let token = "astrid_pair_test";
        let record = DurablePairToken {
            token_hash: hash_token(token),
            principal_uid: PrincipalUid::from_bytes([7; 32]),
            expires_at_epoch: now_epoch().saturating_add(300),
            issued_at_epoch: now_epoch(),
            label: Some("test".to_owned()),
            scope: DeviceScope::Full,
        };
        assert!(store.issue(&record).await.unwrap());
        let left = store.clone();
        let right = store.clone();
        let (a, b) = tokio::join!(
            left.redeem(&record.token_hash),
            right.redeem(&record.token_hash)
        );
        let winners = [a.unwrap(), b.unwrap()].into_iter().flatten().count();
        assert_eq!(winners, 1);
    }

    #[tokio::test]
    async fn reservation_has_one_exact_owner_and_releases_redeemably() {
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurablePairTokenStore::new(backend).unwrap();
        let record = DurablePairToken {
            token_hash: hash_token("reservation owner"),
            principal_uid: PrincipalUid::from_bytes([8; 32]),
            expires_at_epoch: now_epoch().saturating_add(300),
            issued_at_epoch: now_epoch(),
            label: Some("owner".to_owned()),
            scope: DeviceScope::Full,
        };
        assert!(store.issue(&record).await.unwrap());
        assert!(store.reserve_if_unchanged(&record).await.unwrap());
        assert_eq!(store.redeemable(&record.token_hash).await.unwrap(), None);
        assert!(!store.reserve_if_unchanged(&record).await.unwrap());
        assert!(store.release_reservation(&record).await.unwrap());
        assert_eq!(
            store.redeemable(&record.token_hash).await.unwrap(),
            Some(record)
        );
    }

    #[tokio::test]
    async fn reservation_commit_and_rollback_do_not_clobber_replacement() {
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurablePairTokenStore::new(backend).unwrap();
        let record = DurablePairToken {
            token_hash: hash_token("reservation replacement"),
            principal_uid: PrincipalUid::from_bytes([9; 32]),
            expires_at_epoch: now_epoch().saturating_add(300),
            issued_at_epoch: now_epoch(),
            label: Some("original".to_owned()),
            scope: DeviceScope::Full,
        };
        assert!(store.issue(&record).await.unwrap());

        // Remove the reserved record and issue a replacement at the same key.
        // A stale owner must not restore its original over the replacement.
        assert!(store.reserve_if_unchanged(&record).await.unwrap());
        assert!(store.revoke(&record.token_hash).await.unwrap());
        let mut replacement = record.clone();
        replacement.label = Some("replacement".to_owned());
        assert!(store.issue(&replacement).await.unwrap());
        assert!(!store.release_reservation(&record).await.unwrap());
        assert!(!store.consume_reservation(&record).await.unwrap());
        assert_eq!(store.list().await.unwrap(), vec![replacement.clone()]);

        // A still-owned reservation commits by deleting exactly that value.
        assert!(store.reserve_if_unchanged(&replacement).await.unwrap());
        assert!(store.consume_reservation(&replacement).await.unwrap());
        assert!(store.list().await.unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_import_binds_uid_retires_and_restarts() {
        let dir = TempDir::new().unwrap();
        let home = AstridHome::from_path(dir.path());
        home.ensure().unwrap();
        let alias = PrincipalId::new("alice").unwrap();
        let uid = PrincipalUid::from_bytes([9; 32]);
        let principals = astrid_storage::PrincipalDirectory::default();
        principals.register(alias.clone(), uid).unwrap();
        let path = PairTokenStore::path_for(&home);
        let token = PairToken {
            token_hash: hash_token("legacy pair"),
            principal: alias,
            expires_at_epoch: now_epoch().saturating_add(300),
            issued_at_epoch: now_epoch(),
            label: Some("phone".to_owned()),
            scope: DeviceScope::Full,
        };
        PairTokenStore::new(path.clone()).save(&[token]).unwrap();
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurablePairTokenStore::new(Arc::clone(&backend)).unwrap();
        store
            .ensure_legacy_import(&home, &principals)
            .await
            .unwrap();
        assert!(!path.exists());
        assert_eq!(store.list().await.unwrap()[0].principal_uid, uid);
        let restarted = DurablePairTokenStore::new(backend).unwrap();
        restarted
            .ensure_legacy_import(&home, &principals)
            .await
            .unwrap();
        assert_eq!(restarted.list().await.unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn malformed_legacy_pair_source_fails_before_mutation() {
        let dir = TempDir::new().unwrap();
        let home = AstridHome::from_path(dir.path());
        home.ensure().unwrap();
        let path = PairTokenStore::path_for(&home);
        private_write(&path, "schema_version = 1\n[[pair_token]]\n");
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurablePairTokenStore::new(Arc::clone(&backend)).unwrap();
        let principals = astrid_storage::PrincipalDirectory::default();
        assert!(
            store
                .ensure_legacy_import(&home, &principals)
                .await
                .is_err()
        );
        assert!(
            backend
                .list_keys(super::super::SYSTEM_KV_NAMESPACE)
                .await
                .unwrap()
                .is_empty()
        );

        fs::remove_file(&path).unwrap();
        fs::write(&path, "schema_version = 1\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            store
                .ensure_legacy_import(&home, &principals)
                .await
                .is_err()
        );
        assert!(
            backend
                .list_keys(super::super::SYSTEM_KV_NAMESPACE)
                .await
                .unwrap()
                .is_empty()
        );

        fs::remove_file(&path).unwrap();
        private_write(&path, &"x".repeat(4 * 1024 * 1024 + 1));
        assert!(
            store
                .ensure_legacy_import(&home, &principals)
                .await
                .is_err()
        );
        assert!(
            backend
                .list_keys(super::super::SYSTEM_KV_NAMESPACE)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
