//! Signed pre-authority installs retain provenance without acquiring approval.

use std::fs;
use std::sync::Arc;

use astrid_build::artifact::{self, ArtifactVerification};
use astrid_core::{PrincipalId, dirs::AstridHome, identity::PrincipalUid};
use astrid_crypto::KeyPair;
use astrid_storage::{
    KvQuotaResolver, PrincipalDirectory, RuntimePrincipalStore, StateOwner, StorageError,
    open_runtime_principal_store_with_directory,
};

use super::{migrate_native_capsules_with_report, read_installed_authority};
use crate::authority::{AuthorityReceiptTransaction, AuthoritySource, InstalledAuthority};
use crate::meta::CapsuleMeta;
use crate::storage::{canonical_capsule_archive, read_verified_durable_package_for_owner};

const ID: &str = "signed-released-capsule";

struct Fixture {
    _temp: tempfile::TempDir,
    home: AstridHome,
    target: std::path::PathBuf,
    principal: PrincipalId,
    uid: PrincipalUid,
    store: Arc<RuntimePrincipalStore>,
    provenance: ArtifactVerification,
}

fn open_fixture_store(
    home: &AstridHome,
    principal: &PrincipalId,
    uid: PrincipalUid,
) -> Arc<RuntimePrincipalStore> {
    let directory = PrincipalDirectory::default();
    directory.register(principal.clone(), uid).unwrap();
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|owner: &StateOwner| match owner {
        StateOwner::System => Ok(None),
        StateOwner::Principal(_) | StateOwner::Fleet(_) => Ok(Some(u64::MAX)),
        StateOwner::User(_) => Err(StorageError::Internal("unsupported test owner".into())),
    });
    let store = Arc::new(
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(open_runtime_principal_store_with_directory(
                home, quota, directory,
            ))
            .unwrap(),
    );
    store
        .principal_directory()
        .register(principal.clone(), uid)
        .unwrap();
    store
}

impl Fixture {
    fn new(signed: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = AstridHome::from_path(temp.path().join("home"));
        home.ensure().unwrap();
        let principal = PrincipalId::default();
        let uid = PrincipalUid::from_bytes([0x41; 32]);
        let store = open_fixture_store(&home, &principal, uid);
        let target = home.principal_home(&principal).capsules_dir().join(ID);
        astrid_core::platform_fs::ensure_private_directory(&target).unwrap();
        fs::write(target.join("Capsule.toml"), format!(
            "[package]\nname = \"{ID}\"\nversion = \"1.0.0\"\n[[component]]\nid = \"main\"\nfile = \"main.wasm\"\ntype = \"executable\"\n"
        )).unwrap();
        let wasm = b"\0asm\x01\0\0\0";
        fs::write(target.join("main.wasm"), wasm).unwrap();
        let hash = blake3::hash(wasm).to_hex().to_string();
        fs::create_dir_all(home.bin_dir()).unwrap();
        fs::write(home.bin_dir().join(format!("{hash}.wasm")), wasm).unwrap();
        let wit = b"package test:released;\ninterface marker {}\n";
        let wit_hash = blake3::hash(wit).to_hex().to_string();
        fs::create_dir(target.join("wit")).unwrap();
        fs::write(target.join("wit/marker.wit"), wit).unwrap();
        fs::create_dir_all(home.wit_store_dir()).unwrap();
        fs::write(home.wit_store_dir().join(format!("{wit_hash}.wit")), wit).unwrap();
        let archive = temp.path().join("source.capsule");
        fs::write(&archive, canonical_capsule_archive(&target).unwrap()).unwrap();
        if signed {
            artifact::sign_archive(&archive, &KeyPair::generate()).unwrap();
            let envelope =
                artifact::read_archive_text(&archive, artifact::PROVENANCE_FILE).unwrap();
            fs::write(target.join(artifact::PROVENANCE_FILE), envelope).unwrap();
        }
        let provenance = artifact::verify_archive(&archive).unwrap();
        let metadata = CapsuleMeta {
            version: "1.0.0".into(),
            wasm_hash: Some(hash),
            wit_files: std::collections::HashMap::from([("marker.wit".into(), wit_hash)]),
            ..CapsuleMeta::default()
        };
        fs::write(
            target.join("meta.json"),
            serde_json::to_vec_pretty(&metadata).unwrap(),
        )
        .unwrap();
        Self {
            _temp: temp,
            home,
            target,
            principal,
            uid,
            store,
            provenance,
        }
    }

    fn capture_legacy_receipt(&self) -> InstalledAuthority {
        let manifest =
            astrid_capsule::discovery::load_manifest(&self.target.join("Capsule.toml")).unwrap();
        crate::authority::verify_installed_authority(&self.home, &self.target, &manifest).unwrap();
        read_installed_authority(&self.home, &self.target)
            .unwrap()
            .unwrap()
    }

    fn assert_refused_before_publication(&self) {
        let before =
            crate::authority::read_installed_authority_bytes(&self.home, &self.target).unwrap();
        assert!(
            migrate_native_capsules_with_report(&self.store, &self.home, &self.principal, &[])
                .is_err()
        );
        assert!(
            self.store
                .capsules()
                .get_snapshot(&StateOwner::Principal(self.uid), ID)
                .unwrap()
                .is_none(),
            "invalid migration package was published"
        );
        assert!(self.target.exists());
        assert_eq!(
            crate::authority::read_installed_authority_bytes(&self.home, &self.target).unwrap(),
            before
        );
    }
}

#[test]
fn signed_pre_authority_migration_preserves_verified_provenance_and_legacy_ceiling() {
    let fixture = Fixture::new(true);
    let legacy = fixture.capture_legacy_receipt();
    assert!(legacy.signer.is_none() && legacy.signature.is_none());
    migrate_native_capsules_with_report(&fixture.store, &fixture.home, &fixture.principal, &[])
        .unwrap();
    let durable = read_verified_durable_package_for_owner(
        &fixture.store,
        &StateOwner::Principal(fixture.uid),
        ID,
    )
    .unwrap()
    .unwrap();
    let ArtifactVerification::Signed(provenance) = &fixture.provenance else {
        panic!("signed fixture");
    };
    assert_eq!(durable.authority().source, AuthoritySource::LegacyMigration);
    assert_eq!(
        durable.authority().signer.as_deref(),
        Some(provenance.signer.to_string().as_str())
    );
    assert_eq!(
        durable.authority().signature.as_deref(),
        Some(provenance.signature.to_string().as_str())
    );
    assert_eq!(
        durable.authority().approved_capabilities,
        legacy.approved_capabilities
    );
    assert_eq!(
        durable.authority().approved_wasm_hash,
        legacy.approved_wasm_hash
    );
    assert_eq!(durable.authority().manifest_digest, legacy.manifest_digest);
    assert!(!fixture.target.exists());
    assert!(
        migrate_native_capsules_with_report(&fixture.store, &fixture.home, &fixture.principal, &[])
            .unwrap()
            .retired_authorities
            .is_empty()
    );
    let package = durable.snapshot().package().clone();
    drop(durable);
    let Fixture {
        _temp,
        home,
        principal,
        uid,
        store,
        ..
    } = fixture;
    drop(store);
    // This direct storage fixture re-registers its exact test UID after reopen;
    // production released-home identity migration is exercised separately.
    let reopened = open_fixture_store(&home, &principal, uid);
    let readback =
        read_verified_durable_package_for_owner(&reopened, &StateOwner::Principal(uid), ID)
            .unwrap()
            .unwrap();
    assert_eq!(readback.snapshot().package(), &package);
}

#[test]
fn explicit_and_partial_provenance_mismatch_never_publish() {
    for (source, signer, signature) in [
        (AuthoritySource::ExplicitApproval, None, None),
        (AuthoritySource::LegacyMigration, Some("different"), None),
        (AuthoritySource::LegacyMigration, None, Some("different")),
        (
            AuthoritySource::LegacyMigration,
            Some("different"),
            Some("different"),
        ),
    ] {
        let fixture = Fixture::new(true);
        let mut receipt = fixture.capture_legacy_receipt();
        receipt.source = source;
        receipt.signer = signer.map(str::to_owned);
        receipt.signature = signature.map(str::to_owned);
        AuthorityReceiptTransaction::stage(&fixture.home, &fixture.target, &receipt)
            .unwrap()
            .commit()
            .unwrap();
        fixture.assert_refused_before_publication();
    }
}

#[test]
fn unsigned_pre_authority_migration_remains_unsigned() {
    let fixture = Fixture::new(false);
    migrate_native_capsules_with_report(&fixture.store, &fixture.home, &fixture.principal, &[])
        .unwrap();
    let durable = read_verified_durable_package_for_owner(
        &fixture.store,
        &StateOwner::Principal(fixture.uid),
        ID,
    )
    .unwrap()
    .unwrap();
    assert_eq!(durable.authority().source, AuthoritySource::LegacyMigration);
    assert!(durable.authority().signer.is_none() && durable.authority().signature.is_none());
}

#[test]
fn corrupted_signed_native_content_never_publishes() {
    for field in ["signature", "manifest", "executable"] {
        let fixture = Fixture::new(true);
        fixture.capture_legacy_receipt();
        match field {
            "signature" => {
                let path = fixture.target.join(artifact::PROVENANCE_FILE);
                let mut envelope: serde_json::Value =
                    serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
                let signature = envelope["signature"].as_str().unwrap();
                let replacement = if signature.starts_with('A') { "B" } else { "A" };
                envelope["signature"] =
                    serde_json::Value::String(format!("{replacement}{}", &signature[1..]));
                fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
            },
            "manifest" => {
                let path = fixture.target.join("Capsule.toml");
                let mut body = fs::read_to_string(&path).unwrap();
                body.push_str("\n[capabilities]\nnet = [\"example.org\"]\n");
                fs::write(path, body).unwrap();
            },
            "executable" => {
                let hash = fixture.capture_legacy_receipt().approved_wasm_hash.unwrap();
                fs::write(
                    fixture.home.bin_dir().join(format!("{hash}.wasm")),
                    b"tampered",
                )
                .unwrap();
            },
            _ => unreachable!(),
        }
        fixture.assert_refused_before_publication();
    }
}

#[test]
fn unsigned_legacy_wit_digest_failure_never_publishes() {
    let fixture = Fixture::new(false);
    fixture.capture_legacy_receipt();
    let metadata: CapsuleMeta =
        serde_json::from_slice(&fs::read(fixture.target.join("meta.json")).unwrap()).unwrap();
    let hash = &metadata.wit_files["marker.wit"];
    fs::write(
        fixture.home.wit_store_dir().join(format!("{hash}.wit")),
        b"different WIT bytes",
    )
    .unwrap();
    fixture.assert_refused_before_publication();
}

#[test]
fn invalid_package_replacement_preserves_the_existing_registry_generation() {
    let fixture = Fixture::new(true);
    migrate_native_capsules_with_report(&fixture.store, &fixture.home, &fixture.principal, &[])
        .unwrap();
    let owner = StateOwner::Principal(fixture.uid);
    let before = fixture
        .store
        .capsules()
        .get_snapshot(&owner, ID)
        .unwrap()
        .unwrap();
    let mut invalid = before.package().clone();
    let mut authority: InstalledAuthority = serde_json::from_slice(&invalid.authority).unwrap();
    authority.signer = Some("different signer".into());
    invalid.authority = serde_json::to_vec_pretty(&authority).unwrap();
    assert!(
        crate::storage::publish_package_with_expected_generation(
            &fixture.store,
            fixture.uid,
            ID,
            &invalid,
            Some(before.generation()),
        )
        .is_err()
    );
    let after = fixture
        .store
        .capsules()
        .get_snapshot(&owner, ID)
        .unwrap()
        .unwrap();
    assert_eq!(after.generation(), before.generation());
    assert_eq!(after.package(), before.package());
    assert!(
        read_verified_durable_package_for_owner(&fixture.store, &owner, ID)
            .unwrap()
            .is_some()
    );
}
