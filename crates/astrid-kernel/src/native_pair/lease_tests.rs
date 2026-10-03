use super::lease::*;
use astrid_core::{PrincipalId, identity::PrincipalUid, kernel_api::*};
use uuid::Uuid;

fn actor() -> NativePairActor {
    NativePairActor {
        caller: PrincipalId::default(),
        caller_uid: PrincipalUid::from_bytes([1; 32]),
        target: PrincipalId::default(),
        uid: PrincipalUid::from_bytes([1; 32]),
        incarnation: Uuid::nil(),
    }
}
fn identity(id: &str) -> InstalledCapsuleIdentity {
    InstalledCapsuleIdentity {
        id: id.into(),
        generation: InstalledCapsuleGeneration {
            archive: "a".repeat(64),
            metadata: "b".repeat(64),
            authority: "c".repeat(64),
        },
        archive_digest: "d".repeat(64),
        wasm_hash: Some("e".repeat(64)),
    }
}
fn request() -> BeginNativePairUpgrade {
    BeginNativePairUpgrade {
        target_principal: PrincipalId::default(),
        principal_uid: actor().uid,
        daemon_incarnation: Uuid::nil(),
        expected_old: NativePairIdentityV1 {
            enforcer: identity("codewall-enforcer"),
            protocol: identity("codewall-protocol"),
            enforcer_source: Uuid::new_v4(),
            protocol_source: Uuid::new_v4(),
        },
        members: ["codewall-enforcer", "codewall-protocol"].map(|id| NativePairMemberV1 {
            id: id.into(),
            source_digest: blake3::hash(b"abcd").to_hex().to_string(),
            source_bytes: 4,
            authority: CapsuleInstallAuthority::ExplicitApproval,
            env: vec![],
        }),
        expires_at_unix_ms: 1100,
        nonce: Uuid::new_v4(),
        installation_id: Uuid::new_v4(),
        journal_id: Uuid::new_v4(),
    }
}
#[test]
fn native_pair_lease_admission() {
    let mut store = LeaseStore::default();
    let request = request();
    let lease = store.begin(&actor(), request.clone(), 1000).unwrap();
    assert!(lease.policy_snapshot_digest.is_none());
    assert!(store.begin(&actor(), request.clone(), 1000).is_err());
    let mut other = actor();
    other.caller_uid = PrincipalUid::from_bytes([2; 32]);
    assert!(store.get(&other, lease.lease_id, 1000).is_err());
    other = actor();
    other.incarnation = Uuid::new_v4();
    assert!(store.get(&other, lease.lease_id, 1000).is_err());
    assert!(store.get(&actor(), lease.lease_id, 1100).is_err());
    for change in [0, 1, 2, 3] {
        let mut bad = request.clone();
        match change {
            0 => bad.members[0].source_bytes = 64 * 1024 * 1024 + 1,
            1 => bad.members[0].id = "other".into(),
            2 => bad.members[0].env.push(CapsuleInstallEnv {
                key: "CODEWALL_ENROLMENT_TOKEN".into(),
                value: String::new(),
                kind: EnvValueKind::Secret,
            }),
            _ => bad.principal_uid = PrincipalUid::from_bytes([4; 32]),
        }
        assert!(LeaseStore::default().begin(&actor(), bad, 1000).is_err());
    }
}
#[test]
fn native_pair_lease_chunks_abort_and_replay() {
    let mut store = LeaseStore::default();
    let request = request();
    let lease = store.begin(&actor(), request.clone(), 1000).unwrap();
    let mut chunk = StageNativePairMember {
        lease: NativePairLeaseRefV1 {
            lease_id: lease.lease_id,
            target_principal: actor().target,
            principal_uid: actor().uid,
            daemon_incarnation: actor().incarnation,
        },
        member_id: "codewall-enforcer".into(),
        offset: 1,
        total_bytes: 4,
        chunk: b"ab".to_vec(),
        final_chunk: false,
    };
    assert!(store.append(&actor(), &chunk, 1000).is_err());
    chunk.offset = 0;
    assert!(store.append(&actor(), &chunk, 1000).unwrap().is_none());
    assert!(store.append(&actor(), &chunk, 1000).is_err());
    chunk.offset = 2;
    chunk.chunk = b"cd".to_vec();
    chunk.final_chunk = true;
    assert_eq!(
        store.append(&actor(), &chunk, 1000).unwrap().unwrap(),
        b"abcd"
    );
    assert!(store.append(&actor(), &chunk, 1000).is_err());
    let aborted = store.abort(&actor(), lease.lease_id, 1000).unwrap();
    assert_eq!(aborted.phase, NativePairPhaseV1::Aborted);
    assert_eq!(
        store.abort(&actor(), lease.lease_id, 1000).unwrap(),
        aborted
    );
    assert!(store.begin(&actor(), request, 1000).is_err());
}

struct LiveCapsule {
    id: astrid_capsule::capsule::CapsuleId,
    manifest: astrid_capsule::manifest::CapsuleManifest,
}
#[async_trait::async_trait]
impl astrid_capsule::capsule::Capsule for LiveCapsule {
    fn id(&self) -> &astrid_capsule::capsule::CapsuleId {
        &self.id
    }
    fn manifest(&self) -> &astrid_capsule::manifest::CapsuleManifest {
        &self.manifest
    }
    fn state(&self) -> astrid_capsule::capsule::CapsuleState {
        astrid_capsule::capsule::CapsuleState::Ready
    }
    async fn load(
        &mut self,
        _: &astrid_capsule::context::CapsuleContext,
    ) -> astrid_capsule::error::CapsuleResult<()> {
        Ok(())
    }
    async fn unload(&mut self) -> astrid_capsule::error::CapsuleResult<()> {
        Ok(())
    }
}

async fn installed_pair(kernel: &crate::Kernel) -> Vec<astrid_storage::CapsulePackage> {
    let uid = kernel
        .principal_directory
        .uid_for(&PrincipalId::default())
        .unwrap();
    let mut packages = Vec::new();
    for name in ["codewall-enforcer", "codewall-protocol"] {
        let directory = tempfile::tempdir().unwrap();
        let manifest = format!(
            "[package]\nname='{name}'\nversion='1.0.0'\n[[component]]\nid='main'\nfile='main.wasm'\n[env.PIN]\ntype='text'\n"
        );
        std::fs::write(directory.path().join("Capsule.toml"), &manifest).unwrap();
        std::fs::write(directory.path().join("main.wasm"), b"\0asm\x01\0\0\0").unwrap();
        let archive = astrid_capsule_install::canonical_capsule_archive(directory.path()).unwrap();
        let verified = astrid_capsule_install::native_pair::verify_native_pair_member(
            &archive,
            name,
            CapsuleInstallAuthority::ExplicitApproval,
            vec![],
            kernel.runtime_key.public_key_bytes(),
        )
        .unwrap();
        let metadata = astrid_capsule_install::meta::CapsuleMeta {
            version: "1.0.0".into(),
            wasm_hash: verified.authority().approved_wasm_hash.clone(),
            ..Default::default()
        };
        let hash = metadata.wasm_hash.clone().unwrap();
        let package = astrid_storage::CapsulePackage::new(
            archive,
            serde_json::to_vec(&metadata).unwrap(),
            serde_json::to_vec(verified.authority()).unwrap(),
        );
        kernel
            .principal_store
            .as_ref()
            .unwrap()
            .capsules()
            .install(
                &astrid_storage::StateOwner::Principal(uid),
                name,
                &package,
                astrid_storage::CapsuleInstallExpectation::Absent,
            )
            .unwrap();
        kernel
            .capsules
            .write()
            .await
            .register_principal_runtime(
                Box::new(LiveCapsule {
                    id: astrid_capsule::capsule::CapsuleId::new(name).unwrap(),
                    manifest: toml::from_str(&manifest).unwrap(),
                }),
                astrid_capsule::registry::WasmHash::from_raw(hash),
                &PrincipalId::default(),
                uid,
            )
            .unwrap();
        packages.push(package);
    }
    let profile = astrid_core::profile::PrincipalProfile {
        capsules: vec!["codewall-enforcer".into(), "codewall-protocol".into()],
        grants: vec!["self:capsule:install".into()],
        ..Default::default()
    };
    profile
        .save_to_path(&astrid_core::profile::PrincipalProfile::path_for(
            &kernel.astrid_home,
            &PrincipalId::default(),
        ))
        .unwrap();
    kernel.profile_cache.invalidate(&PrincipalId::default());
    packages
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "one complete source-changing pair staging and no-publication lifecycle"
)]
async fn native_pair_lease_staging_preserves_packages_env_and_views() {
    use super::NativePairCoordinator;
    let directory = tempfile::tempdir().unwrap();
    let kernel =
        crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(directory.path()))
            .await;
    let packages = installed_pair(&kernel).await;
    let candidate = tempfile::tempdir().unwrap();
    std::fs::write(candidate.path().join("Capsule.toml"), "[package]\nname='codewall-enforcer'\nversion='2.0.0'\n[[component]]\nid='main'\nfile='main.wasm'\n[env.PIN]\ntype='text'\n").unwrap();
    std::fs::write(
        candidate.path().join("main.wasm"),
        b"\0asm\x01\0\0\0\0\x02\x01x",
    )
    .unwrap();
    // Change one executable while pinning the unchanged peer as well.
    let candidate_archives = [
        astrid_capsule_install::canonical_capsule_archive(candidate.path()).unwrap(),
        packages[1].archive.clone(),
    ];
    let mut actor = actor();
    actor.uid = kernel.principal_directory.uid_for(&actor.target).unwrap();
    actor.caller_uid = actor.uid;
    actor.incarnation = kernel.native_protection_incarnation;
    let coordinator = NativePairCoordinator::new(&kernel);
    let old = coordinator.capture(&actor).await.unwrap();
    super::snapshot::tests::seed(
        kernel.kv.as_ref(),
        &format!("{}:capsule:codewall-enforcer", actor.target),
        1,
    )
    .await;
    let env_namespace =
        astrid_storage::env::principal_capsule_namespace(actor.uid, "codewall-enforcer");
    let env_key = astrid_storage::env::env_key("PIN");
    kernel
        .kv
        .set(&env_namespace, &env_key, b"old-pin".to_vec())
        .await
        .unwrap();
    let mut request = request();
    request.principal_uid = actor.uid;
    request.daemon_incarnation = actor.incarnation;
    request.expected_old = old.identity.clone();
    request.expires_at_unix_ms = super::now().unwrap() + 300_000;
    for (index, member) in request.members.iter_mut().enumerate() {
        member.source_bytes = candidate_archives[index].len() as u64;
        member.source_digest = blake3::hash(&candidate_archives[index])
            .to_hex()
            .to_string();
        member.env = vec![CapsuleInstallEnv {
            key: "PIN".into(),
            value: "new-pin".into(),
            kind: EnvValueKind::Text,
        }];
    }
    let mut wrong = request.clone();
    wrong.expected_old.enforcer.generation.authority = "f".repeat(64);
    let before_rejection = LiveSnapshot::capture(&kernel, &actor).await;
    assert!(coordinator.begin(&actor, wrong).await.is_err());
    before_rejection
        .assert_unchanged(&kernel, &actor, "wrong-old-generation")
        .await;
    let lease = coordinator.begin(&actor, request.clone()).await.unwrap();
    for (index, archive) in candidate_archives.iter().enumerate() {
        let chunk = StageNativePairMember {
            lease: NativePairLeaseRefV1 {
                lease_id: lease.lease_id,
                target_principal: actor.target.clone(),
                principal_uid: actor.uid,
                daemon_incarnation: actor.incarnation,
            },
            member_id: request.members[index].id.clone(),
            offset: 0,
            total_bytes: archive.len() as u64,
            chunk: archive.clone(),
            final_chunk: true,
        };
        coordinator.stage_member(&actor, chunk).await.unwrap();
        assert_eq!(
            kernel.kv.get(&env_namespace, &env_key).await.unwrap(),
            Some(b"old-pin".to_vec())
        );
        let fresh = coordinator.capture(&actor).await.unwrap();
        assert_eq!(fresh.identity, old.identity);
        assert_eq!(fresh.runtimes, old.runtimes);
        for (old, new) in packages.iter().zip(fresh.packages.iter()) {
            assert_eq!(old, new.snapshot().package());
        }
    }
    let leases = kernel.native_pair_leases.lock().await;
    let staged = &leases.leases[&lease.lease_id];
    assert!(staged.verified.iter().all(Option::is_some));
    assert_eq!(
        staged.verified[0].as_ref().unwrap().env()[0].value,
        "new-pin"
    );
    assert_eq!(staged.state.phase, NativePairPhaseV1::Staging);
    assert!(staged.state.lease.policy_snapshot_digest.is_some());
    assert!(staged.state.lease.candidate.is_none());
    assert!(staged.snapshot.is_some());
    assert!(staged.host_contexts.is_some());
    drop(leases);
    // A concurrent durable metadata publication invalidates the exact package CAS.
    let mut changed = packages[0].clone();
    changed.metadata.push(b' ');
    kernel
        .principal_store
        .as_ref()
        .unwrap()
        .capsules()
        .install(
            &astrid_storage::StateOwner::Principal(actor.uid),
            "codewall-enforcer",
            &changed,
            astrid_storage::CapsuleInstallExpectation::Any,
        )
        .unwrap();
    assert_eq!(
        coordinator
            .status(&actor, lease.lease_id)
            .await
            .unwrap()
            .phase,
        NativePairPhaseV1::Aborted
    );
    assert_eq!(
        kernel.kv.get(&env_namespace, &env_key).await.unwrap(),
        Some(b"old-pin".to_vec())
    );
}

#[test]
fn native_pair_lease_digest_overflow_and_wire_bounds() {
    let mut store = LeaseStore::default();
    let lease = store.begin(&actor(), request(), 1000).unwrap();
    let mut chunk = StageNativePairMember {
        lease: NativePairLeaseRefV1 {
            lease_id: lease.lease_id,
            target_principal: actor().target,
            principal_uid: actor().uid,
            daemon_incarnation: actor().incarnation,
        },
        member_id: "codewall-enforcer".into(),
        offset: u64::MAX,
        total_bytes: 4,
        chunk: vec![255; MAX_CHUNK],
        final_chunk: true,
    };
    let wire = serde_json::to_vec(&KernelRequest::StageNativePairMember(chunk.clone())).unwrap();
    assert!(wire.len() + 64 * 1024 < 2 * 1024 * 1024);
    assert!(store.append(&actor(), &chunk, 1000).is_err());
    chunk.offset = 0;
    chunk.chunk = b"abce".to_vec();
    assert!(store.append(&actor(), &chunk, 1000).is_err());
    assert_eq!(
        store
            .get(&actor(), lease.lease_id, 1000)
            .unwrap()
            .state
            .phase,
        NativePairPhaseV1::Aborted
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_pair_lease_reload_and_retirement_invalidate_pins() {
    for retired in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let kernel = crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(
            directory.path(),
        ))
        .await;
        installed_pair(&kernel).await;
        let mut actor = actor();
        actor.uid = kernel.principal_directory.uid_for(&actor.target).unwrap();
        actor.caller_uid = actor.uid;
        actor.incarnation = kernel.native_protection_incarnation;
        let coordinator = super::NativePairCoordinator::new(&kernel);
        let old = coordinator.capture(&actor).await.unwrap();
        let mut request = request();
        request.principal_uid = actor.uid;
        request.daemon_incarnation = actor.incarnation;
        request.expected_old = old.identity.clone();
        request.expires_at_unix_ms = super::now().unwrap() + 300_000;
        let lease = coordinator.begin(&actor, request).await.unwrap();
        if retired {
            kernel
                .capabilities
                .begin_principal_retirement(actor.target.clone())
                .await;
        } else {
            let id = astrid_capsule::capsule::CapsuleId::new("codewall-enforcer").unwrap();
            let mut registry = kernel.capsules.write().await;
            registry.unregister_for(&actor.target, &id).unwrap();
            registry
                .register_principal_runtime(
                    Box::new(LiveCapsule {
                        id,
                        manifest: old.packages[0].manifest().clone(),
                    }),
                    astrid_capsule::registry::WasmHash::from_raw(
                        old.identity.enforcer.wasm_hash.clone().unwrap(),
                    ),
                    &actor.target,
                    actor.uid,
                )
                .unwrap();
        }
        let chunk = StageNativePairMember {
            lease: NativePairLeaseRefV1 {
                lease_id: lease.lease_id,
                target_principal: actor.target.clone(),
                principal_uid: actor.uid,
                daemon_incarnation: actor.incarnation,
            },
            member_id: "codewall-enforcer".into(),
            offset: 0,
            total_bytes: 4,
            chunk: b"abcd".to_vec(),
            final_chunk: true,
        };
        assert!(coordinator.stage_member(&actor, chunk).await.is_err());
        assert_eq!(
            coordinator
                .status(&actor, lease.lease_id)
                .await
                .unwrap()
                .phase,
            NativePairPhaseV1::Aborted
        );
        for package in &old.packages {
            assert_eq!(
                kernel
                    .principal_store
                    .as_ref()
                    .unwrap()
                    .capsules()
                    .get_snapshot(
                        &astrid_storage::StateOwner::Principal(actor.uid),
                        package.id()
                    )
                    .unwrap()
                    .unwrap()
                    .generation(),
                package.snapshot().generation()
            );
        }
    }
}

#[test]
fn native_pair_lease_resource_limit_and_abort_release() {
    let mut store = LeaseStore::default();
    let mut leases = Vec::new();
    for n in 1..=5 {
        let mut owner = actor();
        owner.uid = PrincipalUid::from_bytes([n; 32]);
        owner.caller_uid = owner.uid;
        let mut request = request();
        request.principal_uid = owner.uid;
        let result = store.begin(&owner, request, 1000);
        if n == 5 {
            assert!(result.is_err());
        } else {
            leases.push((owner, result.unwrap().lease_id));
        }
    }
    store.abort(&leases[0].0, leases[0].1, 1000).unwrap();
    assert!(store.begin(&actor(), request(), 1000).is_ok());
}

pub(super) struct CoordinatorFixture {
    _directory: tempfile::TempDir,
    pub(super) kernel: std::sync::Arc<crate::Kernel>,
    pub(super) actor: NativePairActor,
    pub(super) request: BeginNativePairUpgrade,
    pub(super) archives: [Vec<u8>; 2],
}
impl CoordinatorFixture {
    pub(super) async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let kernel = crate::test_kernel_with_home(astrid_core::dirs::AstridHome::from_path(
            directory.path(),
        ))
        .await;
        let packages = installed_pair(&kernel).await;
        let mut actor = actor();
        actor.uid = kernel.principal_directory.uid_for(&actor.target).unwrap();
        actor.caller_uid = actor.uid;
        actor.incarnation = kernel.native_protection_incarnation;
        let mut request = request();
        request.principal_uid = actor.uid;
        request.daemon_incarnation = actor.incarnation;
        request.expected_old = super::NativePairCoordinator::new(&kernel)
            .capture(&actor)
            .await
            .unwrap()
            .identity;
        request.expires_at_unix_ms = super::now().unwrap().checked_add(300_000).unwrap();
        let archives = [packages[0].archive.clone(), packages[1].archive.clone()];
        for (index, member) in request.members.iter_mut().enumerate() {
            member.source_bytes = archives[index].len() as u64;
            member.source_digest = blake3::hash(&archives[index]).to_hex().to_string();
            member.env = vec![CapsuleInstallEnv {
                key: "PIN".into(),
                value: "proposed-pin".into(),
                kind: EnvValueKind::Text,
            }];
            kernel
                .kv
                .set(
                    &astrid_storage::env::principal_capsule_namespace(actor.uid, &member.id),
                    &astrid_storage::env::env_key("PIN"),
                    format!("old-{index}").into_bytes(),
                )
                .await
                .unwrap();
        }
        Self {
            _directory: directory,
            kernel,
            actor,
            request,
            archives,
        }
    }
    pub(super) fn chunk(&self, lease: &NativePairLeaseV1, index: usize) -> StageNativePairMember {
        StageNativePairMember {
            lease: NativePairLeaseRefV1 {
                lease_id: lease.lease_id,
                target_principal: self.actor.target.clone(),
                principal_uid: self.actor.uid,
                daemon_incarnation: self.actor.incarnation,
            },
            member_id: self.request.members[index].id.clone(),
            offset: 0,
            total_bytes: self.archives[index].len() as u64,
            chunk: self.archives[index].clone(),
            final_chunk: true,
        }
    }
}

struct LiveSnapshot {
    pair: super::OldPair,
    env: [Option<Vec<u8>>; 2],
}
impl LiveSnapshot {
    async fn capture(kernel: &crate::Kernel, actor: &NativePairActor) -> Self {
        let pair = super::NativePairCoordinator::new(kernel)
            .capture(actor)
            .await
            .unwrap();
        let mut env = [None, None];
        for (index, package) in pair.packages.iter().enumerate() {
            env[index] = kernel
                .kv
                .get(
                    &astrid_storage::env::principal_capsule_namespace(actor.uid, package.id()),
                    &astrid_storage::env::env_key("PIN"),
                )
                .await
                .unwrap();
        }
        Self { pair, env }
    }
    async fn assert_unchanged(&self, kernel: &crate::Kernel, actor: &NativePairActor, case: &str) {
        let after = Self::capture(kernel, actor).await;
        assert_eq!(
            self.pair.identity, after.pair.identity,
            "{case}: package identities/sources"
        );
        assert_eq!(
            self.pair.runtimes, after.pair.runtimes,
            "{case}: runtime views"
        );
        assert_eq!(self.env, after.env, "{case}: live environment");
        for (old, new) in self.pair.packages.iter().zip(after.pair.packages.iter()) {
            assert_eq!(
                old.snapshot(),
                new.snapshot(),
                "{case}: package bytes and generations"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_pair_lease_begin_rejection_matrix_preserves_live_state() {
    let fixture = CoordinatorFixture::new().await;
    let coordinator = super::NativePairCoordinator::new(&fixture.kernel);
    for case in [
        "wrong-generation",
        "wrong-incarnation",
        "wrong-uid",
        "expired",
        "unknown-member",
        "oversize",
        "secret-env",
        "duplicate-active",
    ] {
        let mut request = fixture.request.clone();
        let active = if case == "duplicate-active" {
            Some(
                coordinator
                    .begin(&fixture.actor, request.clone())
                    .await
                    .unwrap(),
            )
        } else {
            None
        };
        match case {
            "wrong-generation" => {
                request.expected_old.enforcer.generation.authority = "f".repeat(64);
            },
            "wrong-incarnation" => request.daemon_incarnation = Uuid::new_v4(),
            "wrong-uid" => request.principal_uid = PrincipalUid::from_bytes([99; 32]),
            "expired" => request.expires_at_unix_ms = super::now().unwrap(),
            "unknown-member" => request.members[0].id = "other".into(),
            "oversize" => request.members[0].source_bytes = MAX_ARCHIVE + 1,
            "secret-env" => request.members[0].env[0].kind = EnvValueKind::Secret,
            "duplicate-active" => {},
            _ => unreachable!(),
        }
        let before = LiveSnapshot::capture(&fixture.kernel, &fixture.actor).await;
        assert!(
            coordinator.begin(&fixture.actor, request).await.is_err(),
            "{case}"
        );
        before
            .assert_unchanged(&fixture.kernel, &fixture.actor, case)
            .await;
        if let Some(active) = active {
            coordinator
                .abort(&fixture.actor, active.lease_id)
                .await
                .unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_pair_lease_stage_rejection_matrix_preserves_live_state() {
    let fixture = CoordinatorFixture::new().await;
    let coordinator = super::NativePairCoordinator::new(&fixture.kernel);
    for case in [
        "wrong-owner",
        "wrong-incarnation",
        "wrong-uid",
        "expired",
        "unknown-member",
        "gap",
        "overlap",
        "oversized-chunk",
        "wrong-total",
        "wrong-final",
        "digest",
        "invalid-authority",
    ] {
        let mut request = fixture.request.clone();
        request.nonce = Uuid::new_v4();
        if case == "invalid-authority" {
            request.members[0].authority = CapsuleInstallAuthority::Automatic;
        }
        let lease = coordinator.begin(&fixture.actor, request).await.unwrap();
        let mut chunk = fixture.chunk(&lease, 0);
        let mut actor = fixture.actor.clone();
        match case {
            "wrong-owner" => actor.caller_uid = PrincipalUid::from_bytes([99; 32]),
            "wrong-incarnation" => actor.incarnation = Uuid::new_v4(),
            "wrong-uid" => actor.uid = PrincipalUid::from_bytes([99; 32]),
            "expired" => {
                fixture
                    .kernel
                    .native_pair_leases
                    .lock()
                    .await
                    .leases
                    .get_mut(&lease.lease_id)
                    .unwrap()
                    .state
                    .lease
                    .expires_at_unix_ms = 0;
            },
            "unknown-member" => chunk.member_id = "other".into(),
            "gap" => chunk.offset = 1,
            "overlap" => {
                let mut first = chunk.clone();
                first.chunk.truncate(1);
                first.final_chunk = false;
                coordinator
                    .stage_member(&fixture.actor, first)
                    .await
                    .unwrap();
            },
            "oversized-chunk" => chunk.chunk = vec![0; MAX_CHUNK + 1],
            "wrong-total" => chunk.total_bytes += 1,
            "wrong-final" => chunk.final_chunk = false,
            "digest" => chunk.chunk[0] ^= 1,
            "invalid-authority" => {},
            _ => unreachable!(),
        }
        let before = LiveSnapshot::capture(&fixture.kernel, &fixture.actor).await;
        assert!(
            coordinator.stage_member(&actor, chunk).await.is_err(),
            "{case}"
        );
        before
            .assert_unchanged(&fixture.kernel, &fixture.actor, case)
            .await;
        if case != "expired" {
            coordinator
                .abort(&fixture.actor, lease.lease_id)
                .await
                .unwrap();
        }
    }
}
