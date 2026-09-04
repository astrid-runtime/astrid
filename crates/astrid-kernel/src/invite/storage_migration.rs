use std::path::Path;

use super::{DurableInviteStore, Invite, PersistedFile, STORE_SCHEMA_VERSION, SchemaProbe};

pub(super) fn read_legacy_source(
    path: &Path,
) -> astrid_storage::StorageResult<Option<(Vec<u8>, Vec<Invite>)>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(astrid_storage::StorageError::Connection(error.to_string())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(astrid_storage::StorageError::InvalidKey(
            "legacy invite source is not a regular file".to_owned(),
        ));
    }
    astrid_core::platform_fs::verify_no_redirects(path)
        .and_then(|()| astrid_core::platform_fs::validate_private_file(path))
        .map_err(|_| {
            astrid_storage::StorageError::InvalidKey(
                "legacy invite source is not private".to_owned(),
            )
        })?;
    if metadata.len() > super::MAX_LEGACY_BYTES {
        return Err(astrid_storage::StorageError::Serialization(
            "legacy invite source exceeds its bounded size".to_owned(),
        ));
    }
    let bytes = std::fs::read(path)
        .map_err(|error| astrid_storage::StorageError::Connection(error.to_string()))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| {
        astrid_storage::StorageError::Serialization("legacy invite source is not UTF-8".to_owned())
    })?;
    let probe: SchemaProbe = toml::from_str(text).map_err(|_| {
        astrid_storage::StorageError::Serialization("legacy invite source is malformed".to_owned())
    })?;
    if probe.schema_version != STORE_SCHEMA_VERSION {
        return Err(astrid_storage::StorageError::Serialization(
            "legacy invite source schema is unsupported".to_owned(),
        ));
    }
    let parsed: PersistedFile = toml::from_str(text).map_err(|_| {
        astrid_storage::StorageError::Serialization("legacy invite source is malformed".to_owned())
    })?;
    if parsed.invite.len() > super::MAX_RECORDS {
        return Err(astrid_storage::StorageError::Serialization(
            "legacy invite source exceeds its bounded record limit".to_owned(),
        ));
    }
    for invite in &parsed.invite {
        DurableInviteStore::validate_record(invite)?;
    }
    Ok(Some((bytes, parsed.invite)))
}

pub(super) fn retire_legacy_file(
    path: &Path,
    expected_digest: &str,
) -> astrid_storage::StorageResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(astrid_storage::StorageError::InvalidKey(
                    "legacy invite source changed during retirement".to_owned(),
                ));
            }
            astrid_core::platform_fs::verify_no_redirects(path)
                .and_then(|()| astrid_core::platform_fs::validate_private_file(path))
                .map_err(|_| {
                    astrid_storage::StorageError::InvalidKey(
                        "legacy invite source changed during retirement".to_owned(),
                    )
                })?;
            let bytes = std::fs::read(path)
                .map_err(|error| astrid_storage::StorageError::Connection(error.to_string()))?;
            let digest = format!("blake3:{}", blake3::hash(&bytes).to_hex());
            if digest != expected_digest {
                return Err(astrid_storage::StorageError::Internal(
                    "legacy invite source changed during retirement".to_owned(),
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

    use astrid_core::dirs::AstridHome;
    use astrid_storage::{KvStore, MemoryKvStore};
    use tempfile::TempDir;

    use super::super::{DurableInviteStore, Invite, InviteStore, hash_token};

    #[cfg(unix)]
    fn private_write(path: &std::path::Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[tokio::test]
    async fn concurrent_redeem_has_one_winner() {
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurableInviteStore::new(Arc::clone(&backend)).unwrap();
        let token = "astrid_inv_test";
        let record = Invite {
            token_hash: hash_token(token),
            group: "agent".to_owned(),
            remaining_uses: 1,
            expires_at_epoch: None,
            issued_at_epoch: super::super::now_epoch().saturating_add(300),
            metadata: None,
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
    async fn exact_invite_commit_has_one_winner_and_ignores_stale_records() {
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurableInviteStore::new(backend).unwrap();
        let record = Invite {
            token_hash: hash_token("exact invite commit"),
            group: "agent".to_owned(),
            remaining_uses: 2,
            expires_at_epoch: Some(super::super::now_epoch().saturating_add(300)),
            issued_at_epoch: super::super::now_epoch(),
            metadata: None,
        };
        assert!(store.issue(&record).await.unwrap());

        let left = store.clone();
        let right = store.clone();
        let (a, b) = tokio::join!(
            left.consume_if_unchanged(&record),
            right.consume_if_unchanged(&record)
        );
        assert_eq!(
            [a.unwrap(), b.unwrap()]
                .into_iter()
                .filter(|committed| *committed)
                .count(),
            1
        );

        let persisted = store.list().await.unwrap();
        assert_eq!(persisted.len(), 1);
        assert_eq!(persisted[0].remaining_uses, 1);
        assert!(!store.consume_if_unchanged(&record).await.unwrap());
        assert_eq!(store.list().await.unwrap(), persisted);

        assert!(store.consume_if_unchanged(&persisted[0]).await.unwrap());
        assert!(store.list().await.unwrap().is_empty());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_import_is_receipted_retired_and_restart_idempotent() {
        let dir = TempDir::new().unwrap();
        let home = AstridHome::from_path(dir.path());
        home.ensure().unwrap();
        let path = InviteStore::path_for(&home);
        let token = Invite {
            token_hash: hash_token("legacy invite"),
            group: "agent".to_owned(),
            remaining_uses: 1,
            expires_at_epoch: Some(super::super::now_epoch().saturating_add(600)),
            issued_at_epoch: super::super::now_epoch(),
            metadata: Some("legacy".to_owned()),
        };
        InviteStore::new(path.clone())
            .save(std::slice::from_ref(&token))
            .unwrap();
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurableInviteStore::new(Arc::clone(&backend)).unwrap();
        store.ensure_legacy_import(&home).await.unwrap();
        assert!(!path.exists());
        assert_eq!(store.list().await.unwrap(), vec![token]);

        let restarted = DurableInviteStore::new(backend).unwrap();
        restarted.ensure_legacy_import(&home).await.unwrap();
        assert_eq!(restarted.list().await.unwrap().len(), 1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unsafe_legacy_sources_fail_before_durable_mutation() {
        let dir = TempDir::new().unwrap();
        let home = AstridHome::from_path(dir.path());
        home.ensure().unwrap();
        let path = InviteStore::path_for(&home);
        std::fs::create_dir_all(home.etc_dir()).unwrap();
        let outside = dir.path().join("outside.toml");
        private_write(&outside, "schema_version = 1\n");
        std::os::unix::fs::symlink(&outside, &path).unwrap();
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = DurableInviteStore::new(Arc::clone(&backend)).unwrap();
        assert!(store.ensure_legacy_import(&home).await.is_err());
        assert!(
            backend
                .list_keys(super::super::SYSTEM_KV_NAMESPACE)
                .await
                .unwrap()
                .is_empty()
        );

        fs::remove_file(&path).unwrap();
        private_write(&path, "schema_version = 1\n[[invite]]\n");
        assert!(store.ensure_legacy_import(&home).await.is_err());
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
        assert!(store.ensure_legacy_import(&home).await.is_err());
        assert!(
            backend
                .list_keys(super::super::SYSTEM_KV_NAMESPACE)
                .await
                .unwrap()
                .is_empty()
        );

        fs::remove_file(&path).unwrap();
        private_write(&path, &"x".repeat(4 * 1024 * 1024 + 1));
        assert!(store.ensure_legacy_import(&home).await.is_err());
        assert!(
            backend
                .list_keys(super::super::SYSTEM_KV_NAMESPACE)
                .await
                .unwrap()
                .is_empty()
        );
    }
}
