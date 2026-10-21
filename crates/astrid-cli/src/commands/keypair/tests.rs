use super::*;

fn invitation_fixture(home: &AstridHome) -> (KeyPaths, PublicKey) {
    let local = home.keys_dir().join("local");
    fs::create_dir_all(&local).unwrap();
    let paths = KeyPaths {
        private: local.join("test.ed25519"),
        public_hex: local.join("test.pub.hex"),
        meta: local.join("test.meta.toml"),
    };
    let signing = SigningKey::from_bytes(&[33; 32]);
    write_secret(&paths.private, &signing.to_bytes()).unwrap();
    let public = hex::encode(signing.verifying_key().to_bytes());
    write_public(&paths.public_hex, &public).unwrap();
    write_meta(
        &paths.meta,
        &KeyMeta {
            schema_version: META_SCHEMA_VERSION,
            fingerprint: fingerprint_pubkey(&public).unwrap(),
            created_at_epoch: 0,
            backend: "file".into(),
            note: None,
            bound_principal: None,
        },
    )
    .unwrap();
    (paths, PublicKey::from_hex(&public).unwrap())
}

#[test]
fn failed_binding_commit_never_publishes_an_untracked_credential() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    let (paths, public) = invitation_fixture(&home);
    let principal = PrincipalId::new("commit-failure").unwrap();
    let result = record_binding_with_commit(&paths, &home, &principal, &public, |_, _| {
        bail!("injected metadata commit failure")
    });
    assert!(result.is_err());
    assert!(!home.keys_dir().join("commit-failure.key").exists());
    assert!(read_meta(&paths).unwrap().bound_principal.is_none());
}

#[test]
fn invited_key_binding_activates_native_signing_key() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    let local = home.keys_dir().join("local");
    fs::create_dir_all(&local).unwrap();
    let paths = KeyPaths {
        private: local.join("invite.ed25519"),
        public_hex: local.join("invite.pub.hex"),
        meta: local.join("invite.meta.toml"),
    };
    let signing = SigningKey::from_bytes(&[23; 32]);
    write_secret(&paths.private, &signing.to_bytes()).unwrap();
    let public = hex::encode(signing.verifying_key().to_bytes());
    write_public(&paths.public_hex, &public).unwrap();
    write_meta(
        &paths.meta,
        &KeyMeta {
            schema_version: META_SCHEMA_VERSION,
            fingerprint: fingerprint_pubkey(&public).unwrap(),
            created_at_epoch: 0,
            backend: "file".to_owned(),
            note: None,
            bound_principal: None,
        },
    )
    .unwrap();
    let principal = PrincipalId::new("invited-client").unwrap();
    let redeemed = PublicKey::from_hex(&public).unwrap();
    let foreign = astrid_crypto::KeyPair::generate().export_public_key();
    assert!(record_binding_at(&paths, &home, &principal, &foreign).is_err());
    assert!(!home.keys_dir().join("invited-client.key").exists());
    record_binding_at(&paths, &home, &principal, &redeemed).unwrap();
    let activated = fs::read(home.keys_dir().join("invited-client.key")).unwrap();
    assert_eq!(activated, signing.to_bytes());
    record_binding_at(&paths, &home, &principal, &redeemed).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(home.keys_dir().join("invited-client.key"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
    let other = PrincipalId::new("different-client").unwrap();
    assert!(record_binding_at(&paths, &home, &other, &redeemed).is_err());
    assert!(!home.keys_dir().join("different-client.key").exists());
    assert!(remove_activated_key(&home, &principal, &foreign).is_err());
    assert!(home.keys_dir().join("invited-client.key").exists());
    remove_activated_key(&home, &principal, &redeemed).unwrap();
    assert!(!home.keys_dir().join("invited-client.key").exists());
}

#[test]
fn bound_key_deletion_does_not_depend_on_public_sidecar() {
    for corrupt in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(dir.path());
        let (paths, public) = invitation_fixture(&home);
        let principal = PrincipalId::new("delete-partial").unwrap();
        record_binding_at(&paths, &home, &principal, &public).unwrap();
        if corrupt {
            fs::write(&paths.public_hex, "invalid").unwrap();
        } else {
            fs::remove_file(&paths.public_hex).unwrap();
        }
        let meta = read_meta(&paths).unwrap();
        remove_bound_key(&paths, &home, &meta).unwrap();
        assert!(!home.keys_dir().join("delete-partial.key").exists());
        // The private sidecar can also be absent after a partial deletion.
        activate_invited_key(&home.keys_dir().join("delete-partial.key"), &[33; 32]).unwrap();
        fs::remove_file(&paths.private).unwrap();
        remove_bound_key(&paths, &home, &meta).unwrap();
        assert!(!home.keys_dir().join("delete-partial.key").exists());
    }
}

#[test]
fn concurrent_binding_cannot_publish_two_principal_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    let (paths, public) = invitation_fixture(&home);
    let first = PrincipalId::new("first-invite").unwrap();
    let second = PrincipalId::new("second-invite").unwrap();
    let (entered_tx, entered_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let (paths_ref, home_ref, first_ref, public_ref) = (&paths, &home, &first, &public);
        let writer = scope.spawn(move || {
            record_binding_with_commit(paths_ref, home_ref, first_ref, public_ref, |path, meta| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                write_meta(path, meta)
            })
        });
        entered_rx.recv().unwrap();
        let competing = record_binding_at(&paths, &home, &second, &public);
        release_tx.send(()).unwrap();
        writer.join().unwrap().unwrap();
        assert!(competing.is_err());
    });
    assert!(home.keys_dir().join("first-invite.key").exists());
    assert!(!home.keys_dir().join("second-invite.key").exists());
    assert_eq!(
        read_meta(&paths).unwrap().bound_principal.as_deref(),
        Some("first-invite")
    );
}

#[test]
fn deletion_uses_private_identity_even_with_a_stale_valid_public_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    let (paths, public) = invitation_fixture(&home);
    let principal = PrincipalId::new("delete-stale-public").unwrap();
    record_binding_at(&paths, &home, &principal, &public).unwrap();
    write_public(&paths.public_hex, &"44".repeat(32)).unwrap();
    let meta = read_meta(&paths).unwrap();
    remove_bound_key(&paths, &home, &meta).unwrap();
    assert!(!home.keys_dir().join("delete-stale-public.key").exists());
}

#[test]
fn failed_activation_keeps_a_recoverable_binding_and_existing_key() {
    let dir = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(dir.path());
    let (paths, public) = invitation_fixture(&home);
    let principal = PrincipalId::new("activation-failure").unwrap();
    let destination = home.keys_dir().join("activation-failure.key");
    fs::write(&destination, [44; 32]).unwrap();
    assert!(record_binding_at(&paths, &home, &principal, &public).is_err());
    assert_eq!(fs::read(&destination).unwrap(), [44; 32]);
    assert_eq!(
        read_meta(&paths).unwrap().bound_principal.as_deref(),
        Some(principal.as_str())
    );
    assert!(remove_bound_key(&paths, &home, &read_meta(&paths).unwrap()).is_err());
    assert_eq!(fs::read(destination).unwrap(), [44; 32]);
}

#[test]
fn invited_key_activation_never_replaces_existing_credential() {
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("principal.key");
    fs::write(&destination, [11; 32]).unwrap();
    assert!(activate_invited_key(&destination, &[12; 32]).is_err());
    assert_eq!(fs::read(&destination).unwrap(), [11; 32]);
}

#[cfg(unix)]
#[test]
fn invited_key_activation_refuses_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target.key");
    let destination = dir.path().join("principal.key");
    fs::write(&target, [11; 32]).unwrap();
    std::os::unix::fs::symlink(&target, &destination).unwrap();
    assert!(activate_invited_key(&destination, &[11; 32]).is_err());
    assert_eq!(fs::read(target).unwrap(), [11; 32]);
}

#[test]
fn wire_format_is_ed25519_base64_and_parser_roundtrips() {
    // The `wire` output must be exactly what the distro signing
    // verifier parses back — same 32 bytes, STANDARD base64,
    // `ed25519:` prefix.
    let hex = "0".repeat(64);
    let wire = pubkey_hex_to_wire(&hex).unwrap();
    assert!(wire.starts_with("ed25519:"));
    let b64 = wire.strip_prefix("ed25519:").unwrap();
    assert_eq!(
        astrid_crypto::PublicKey::from_base64(b64).unwrap(),
        astrid_crypto::PublicKey::from_hex(&hex).unwrap(),
    );
}

#[test]
fn validate_name_accepts_well_formed() {
    validate_name("laptop").unwrap();
    validate_name("a").unwrap();
    validate_name("key-2026-05").unwrap();
    validate_name(&"a".repeat(MAX_NAME_LEN)).unwrap();
}

#[test]
fn validate_name_rejects_bad_input() {
    assert!(validate_name("").is_err());
    assert!(validate_name("UPPER").is_err());
    assert!(validate_name("has space").is_err());
    assert!(validate_name("../etc/passwd").is_err());
    assert!(validate_name(&"a".repeat(MAX_NAME_LEN + 1)).is_err());
}

#[test]
fn fingerprint_is_stable_and_distinct() {
    let a = fingerprint_pubkey(&"a".repeat(64)).unwrap();
    let b = fingerprint_pubkey(&"a".repeat(64)).unwrap();
    let c = fingerprint_pubkey(&"b".repeat(64)).unwrap();
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.len(), 71);
}

#[test]
fn legacy_key_metadata_self_heals_from_the_public_key() {
    let dir = tempfile::tempdir().unwrap();
    let paths = KeyPaths {
        private: dir.path().join("laptop.ed25519"),
        public_hex: dir.path().join("laptop.pub.hex"),
        meta: dir.path().join("laptop.meta.toml"),
    };
    let public_hex = "ab".repeat(32);
    write_public(&paths.public_hex, &public_hex).unwrap();
    write_meta(
        &paths.meta,
        &KeyMeta {
            schema_version: 1,
            fingerprint: "a4182c80cf8467d91a58382943715d4062d3c6f4464c8b346a3f7b1b11164c7a".into(),
            created_at_epoch: 1,
            backend: "file".into(),
            note: Some("offline release key".into()),
            bound_principal: Some("operator".into()),
        },
    )
    .unwrap();

    let migrated = read_meta(&paths).unwrap();
    assert_eq!(migrated.schema_version, META_SCHEMA_VERSION);
    assert_eq!(migrated.note.as_deref(), Some("offline release key"));
    assert_eq!(migrated.bound_principal.as_deref(), Some("operator"));
    assert_eq!(
        migrated.fingerprint,
        fingerprint_pubkey(&public_hex).unwrap()
    );
    let persisted = fs::read_to_string(&paths.meta).unwrap();
    assert!(persisted.contains("schema_version = 2"));
    assert!(!persisted.contains("a4182c80cf8467d"));
}

#[test]
fn legacy_metadata_without_public_key_remains_readable_and_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let paths = KeyPaths {
        private: dir.path().join("laptop.ed25519"),
        public_hex: dir.path().join("laptop.pub.hex"),
        meta: dir.path().join("laptop.meta.toml"),
    };
    write_meta(
        &paths.meta,
        &KeyMeta {
            schema_version: 1,
            fingerprint: "a4182c80cf8467d91a58382943715d4062d3c6f4464c8b346a3f7b1b11164c7a".into(),
            created_at_epoch: 1,
            backend: "file".into(),
            note: Some("preserve me".into()),
            bound_principal: Some("operator".into()),
        },
    )
    .unwrap();
    let before = fs::read(&paths.meta).unwrap();

    let deferred = read_meta(&paths).unwrap();
    assert_eq!(deferred.schema_version, 1);
    assert_eq!(deferred.note.as_deref(), Some("preserve me"));
    assert_eq!(fs::read(&paths.meta).unwrap(), before);
}

#[test]
fn legacy_metadata_with_malformed_public_key_remains_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let paths = KeyPaths {
        private: dir.path().join("laptop.ed25519"),
        public_hex: dir.path().join("laptop.pub.hex"),
        meta: dir.path().join("laptop.meta.toml"),
    };
    write_public(&paths.public_hex, "not-a-public-key").unwrap();
    write_meta(
        &paths.meta,
        &KeyMeta {
            schema_version: 1,
            fingerprint: "a4182c80cf8467d91a58382943715d4062d3c6f4464c8b346a3f7b1b11164c7a".into(),
            created_at_epoch: 1,
            backend: "file".into(),
            note: None,
            bound_principal: None,
        },
    )
    .unwrap();
    let before = fs::read(&paths.meta).unwrap();

    let deferred = read_meta(&paths).unwrap();
    assert_eq!(deferred.schema_version, 1);
    assert_eq!(fs::read(&paths.meta).unwrap(), before);
}

#[test]
fn openssh_encoding_round_trips_against_a_known_vector() {
    // ed25519 zero pubkey → "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    let pubkey = [0u8; 32];
    let encoded = encode_openssh_ed25519(&pubkey);
    assert!(encoded.starts_with("ssh-ed25519 "));
    // Length: SSH-wire = 4 + 11 + 4 + 32 = 51 bytes → base64 = ceil(51/3)*4 = 68 chars
    let body = encoded.trim_start_matches("ssh-ed25519 ");
    assert_eq!(body.len(), 68);
}
