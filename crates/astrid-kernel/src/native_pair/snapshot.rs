//! Consistent native policy/environment capture. Detached writes are disposable.

use anyhow::{Context as _, ensure};
use astrid_capsule::engine::wasm::native_candidate::{
    NATIVE_CANDIDATE_CONFIG, NativeCandidateAudit, NativeCandidateHostContext,
};
use astrid_capsule_install::native_pair::VerifiedNativePairMember;
use astrid_core::{PrincipalId, PrincipalUid, kernel_api::NativePairIdentityV1};
use astrid_storage::{KvStore, RuntimePrincipalStore, engine::native_pair::DetachedNativePair};
use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

pub(super) struct NativeCandidateSnapshot {
    uid: PrincipalUid,
    principal: PrincipalId,
    pair: NativePairIdentityV1,
    members: [Arc<VerifiedNativePairMember>; 2],
    digest: String,
    state: Arc<DetachedNativePair>,
    env: HashMap<String, HashMap<String, String>>,
    env_dependencies: BTreeMap<(String, String), Option<Vec<u8>>>,
    bus: Arc<astrid_events::EventBus>,
    audit: Arc<NativeCandidateAudit>,
}

impl NativeCandidateSnapshot {
    #[allow(clippy::too_many_lines)] // One fence covers capture and every exact Text dependency.
    pub(super) async fn capture(
        store: &RuntimePrincipalStore,
        principal: &PrincipalId,
        uid: PrincipalUid,
        pair: &NativePairIdentityV1,
        members: &[Arc<VerifiedNativePairMember>; 2],
    ) -> anyhow::Result<Self> {
        ensure!(
            pair.enforcer.id == "codewall-enforcer" && pair.protocol.id == "codewall-protocol",
            "native snapshot pair invalid"
        );
        let names: std::collections::BTreeSet<_> = members
            .iter()
            .map(|member| member.manifest().package.name.as_str())
            .collect();
        ensure!(
            names
                == ["codewall-enforcer", "codewall-protocol"]
                    .into_iter()
                    .collect(),
            "native snapshot verified pair invalid"
        );
        ensure!(
            store.principal_directory().uid_for(principal)? == uid,
            "native snapshot UID mismatch"
        );
        let fence = store.native_policy_fence();
        let _guard = fence.lock().await;
        let root = store.native_candidate_snapshot(uid).await?;
        let alias = principal.to_string();
        let state = tokio::task::spawn_blocking(move || {
            DetachedNativePair::from_snapshot(uid, &alias, root.as_ref())
        })
        .await??;
        let digest = policy_digest(
            state.kv().as_ref(),
            &format!("{principal}:capsule:codewall-enforcer"),
        )
        .await?;
        let mut env = HashMap::new();
        let mut env_dependencies = BTreeMap::new();
        for member in members {
            let id = &member.manifest().package.name;
            let principal_values = state.generation_env(id).await?;
            let mut values = HashMap::new();
            ensure!(
                member.manifest().env.len() <= 64,
                "native environment entry limit"
            );
            let mut bytes = 0_usize;
            for (field, declaration) in &member.manifest().env {
                ensure!(
                    field != NATIVE_CANDIDATE_CONFIG,
                    "reserved native environment declaration"
                );
                if declaration.env_type.eq_ignore_ascii_case("secret") {
                    ensure!(
                        id == "codewall-protocol" && field == "CODEWALL_ENROLMENT_TOKEN",
                        "native candidate secret dependency unsupported"
                    );
                    continue;
                }
                if member.env().iter().any(|proposed| proposed.key == *field) {
                    continue;
                }
                let key = astrid_storage::env::env_key(field);
                let principal_namespace = astrid_storage::env::principal_capsule_namespace(uid, id);
                let primary = principal_values
                    .get(field)
                    .map(|value| value.as_bytes().to_vec());
                env_dependencies.insert((principal_namespace, key.clone()), primary.clone());
                let value = if primary.is_some() {
                    primary
                } else {
                    let shared_namespace = astrid_storage::env::system_capsule_namespace(id);
                    let shared = store.kv().get(&shared_namespace, &key).await?;
                    env_dependencies.insert((shared_namespace, key), shared.clone());
                    shared
                };
                if let Some(value) = value {
                    bytes = bytes
                        .checked_add(value.len())
                        .context("native environment overflow")?;
                    ensure!(bytes <= 64 * 1024, "native environment byte limit");
                    values.insert(
                        field.clone(),
                        String::from_utf8(value).context("native environment encoding")?,
                    );
                }
            }
            env.insert(id.clone(), values);
        }
        ensure!(
            store.principal_directory().uid_for(principal)? == uid,
            "native snapshot principal changed"
        );
        Ok(Self {
            uid,
            principal: principal.clone(),
            pair: pair.clone(),
            members: members.clone(),
            digest,
            state: Arc::new(state),
            env,
            env_dependencies,
            bus: Arc::new(astrid_events::EventBus::new()),
            audit: Arc::new(NativeCandidateAudit::default()),
        })
    }

    pub(super) fn digest(&self) -> String {
        self.digest.clone()
    }

    /// Commit caller MUST hold `store.native_policy_fence()` through this comparison
    /// and publication. Absence is authority too: adding a primary override or
    /// previously missing Shared fallback invalidates the captured selection.
    #[allow(dead_code)] // Consumed by the Task 5 guarded publication path.
    pub(super) async fn environment_matches(
        &self,
        store: &RuntimePrincipalStore,
    ) -> anyhow::Result<bool> {
        for ((namespace, key), expected) in &self.env_dependencies {
            if store.kv().get(namespace, key).await? != *expected {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Caller supplies a member verified by Task 2; both contexts share custody/bus.
    pub(super) async fn detached_host_context(
        &self,
        member: Arc<VerifiedNativePairMember>,
    ) -> anyhow::Result<Arc<NativeCandidateHostContext>> {
        let id = member.manifest().package.name.clone();
        ensure!(
            id == self.pair.enforcer.id || id == self.pair.protocol.id,
            "native snapshot member mismatch"
        );
        ensure!(
            self.members
                .iter()
                .any(|captured| Arc::ptr_eq(captured, &member)),
            "native snapshot verified member changed"
        );
        let captured = self
            .env
            .get(&id)
            .context("native member environment missing")?;
        let mut env = HashMap::new();
        for (key, declaration) in &member.manifest().env {
            ensure!(
                key != NATIVE_CANDIDATE_CONFIG,
                "reserved native environment declaration"
            );
            if declaration.env_type.eq_ignore_ascii_case("secret") {
                ensure!(
                    id == "codewall-protocol" && key == "CODEWALL_ENROLMENT_TOKEN",
                    "native candidate secret dependency unsupported"
                );
                // Same enrollment is retained in detached protocol KV; never read or resend its consumed token.
                continue;
            }
            let value = member
                .env()
                .iter()
                .find(|value| value.key == *key)
                .map(|value| value.value.clone())
                .or_else(|| captured.get(key).cloned())
                .or_else(|| {
                    declaration.default.as_ref().and_then(|value| match value {
                        serde_json::Value::Null => None,
                        serde_json::Value::String(value) => Some(value.clone()),
                        value => Some(value.to_string()),
                    })
                })
                .or_else(|| {
                    (declaration.enum_values.len() == 1).then(|| declaration.enum_values[0].clone())
                });
            if let Some(value) = value {
                env.insert(key.clone(), value);
            }
        }
        let wasm = tokio::task::spawn_blocking(move || member.executable()).await??;
        NativeCandidateHostContext::new(
            self.principal.clone(),
            self.uid,
            id,
            env,
            wasm.into(),
            Arc::clone(&self.state),
            Arc::clone(&self.bus),
            Arc::clone(&self.audit),
        )
        .map(Arc::new)
        .map_err(anyhow::Error::msg)
    }
}

/// Codewall's narrow persisted v1 policy references. Full signature verification
/// stays in the real enforcer. Unknown fields remain in the raw digest.
#[derive(serde::Deserialize)]
struct Active {
    artifact_hash: String,
    generation: Option<u64>,
    key_epoch: u32,
    tenant: String,
}
#[derive(serde::Deserialize)]
struct HighWater {
    artifact_hash: String,
    generation: u64,
}
#[derive(serde::Deserialize)]
struct Trust {
    current_epoch: u32,
    current_key_hex: String,
    tenant: String,
}

pub(super) async fn policy_digest(kv: &dyn KvStore, namespace: &str) -> anyhow::Result<String> {
    let mut values = BTreeMap::new();
    for key in ["policy/active", "policy/high-water", "policy/trust"] {
        let bytes = kv.get(namespace, key).await?;
        ensure!(
            bytes.as_ref().is_none_or(|bytes| bytes.len() <= 64 * 1024),
            "native policy pointer limit"
        );
        values.insert(key.to_owned(), bytes);
    }
    let active: Active = serde_json::from_slice(
        values["policy/active"]
            .as_deref()
            .context("native active policy absent")?,
    )?;
    let trust: Trust = serde_json::from_slice(
        values["policy/trust"]
            .as_deref()
            .context("native policy trust absent")?,
    )?;
    ensure!(
        active.artifact_hash.len() == 71
            && active.artifact_hash.starts_with("sha256:")
            && active.artifact_hash[7..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "native policy artifact reference invalid"
    );
    ensure!(
        active.key_epoch > 0
            && active.key_epoch <= trust.current_epoch
            && active.tenant == trust.tenant,
        "native policy trust changed"
    );
    let high_water = values["policy/high-water"]
        .as_deref()
        .map(serde_json::from_slice::<HighWater>)
        .transpose()?;
    ensure!(
        match (active.generation, high_water) {
            (Some(generation), Some(mark)) =>
                generation > 0
                    && generation == mark.generation
                    && active.artifact_hash == mark.artifact_hash,
            (None, None) => true,
            _ => false,
        },
        "native policy activation incomplete"
    );
    for key in [
        format!("policy/artifacts/{}", active.artifact_hash),
        format!("policy/keys/{}", active.key_epoch),
    ] {
        let bytes = kv
            .get(namespace, &key)
            .await?
            .context("native policy dependency missing")?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "native policy dependency limit"
        );
        if key.starts_with("policy/keys/") {
            ensure!(
                bytes.len() == 64
                    && bytes
                        .iter()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
                "native policy key invalid"
            );
            if active.key_epoch == trust.current_epoch {
                ensure!(
                    bytes == trust.current_key_hex.as_bytes(),
                    "native trust key changed"
                );
            }
        }
        values.insert(key, Some(bytes));
    }
    let mut hash = blake3::Hasher::new_derive_key("astrid native policy snapshot v1");
    for (key, value) in values {
        hash.update(&(key.len() as u64).to_le_bytes());
        hash.update(key.as_bytes());
        hash.update(&[u8::from(value.is_some())]);
        if let Some(value) = value {
            hash.update(&(value.len() as u64).to_le_bytes());
            hash.update(&value);
        }
    }
    Ok(hash.finalize().to_hex().to_string())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    fn members() -> [Arc<VerifiedNativePairMember>; 2] {
        ["codewall-enforcer", "codewall-protocol"].map(|name| {
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join("Capsule.toml"), format!("[package]\nname='{name}'\nversion='1.0.0'\n[[component]]\nid='main'\nfile='main.wasm'\n[env.PIN]\ntype='text'\n")).unwrap();
            std::fs::write(dir.path().join("main.wasm"), b"\0asm\x01\0\0\0").unwrap();
            let archive = astrid_capsule_install::canonical_capsule_archive(dir.path()).unwrap();
            Arc::new(astrid_capsule_install::native_pair::verify_native_pair_member(&archive, name, astrid_core::kernel_api::CapsuleInstallAuthority::ExplicitApproval, vec![], &[0; 32]).unwrap())
        })
    }

    pub(in crate::native_pair) async fn seed(kv: &dyn KvStore, ns: &str, generation: u64) {
        let hash = format!("sha256:{}", "a".repeat(64));
        kv.set(ns, "policy/active", serde_json::to_vec(&serde_json::json!({"artifact_hash": hash, "generation": generation, "key_epoch": 1, "tenant": "tenant"})).unwrap()).await.unwrap();
        kv.set(
            ns,
            "policy/high-water",
            serde_json::to_vec(
                &serde_json::json!({"artifact_hash": hash, "generation": generation}),
            )
            .unwrap(),
        )
        .await
        .unwrap();
        kv.set(ns, "policy/trust", serde_json::to_vec(&serde_json::json!({"current_epoch": 1, "current_key_hex": "b".repeat(64), "tenant": "tenant"})).unwrap()).await.unwrap();
        kv.set(
            ns,
            &format!("policy/artifacts/{hash}"),
            b"signed policy bytes checked by guest".to_vec(),
        )
        .await
        .unwrap();
        kv.set(ns, "policy/keys/1", "b".repeat(64).into_bytes())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn native_candidate_policy_snapshot_rejects_intermediate_activation() {
        let kv = astrid_storage::MemoryKvStore::new();
        let ns = "alice:capsule:codewall-enforcer";
        seed(&kv, ns, 1).await;
        let digest = policy_digest(&kv, ns).await.unwrap();
        kv.set(ns, "policy/high-water", serde_json::to_vec(&serde_json::json!({"artifact_hash": format!("sha256:{}", "a".repeat(64)), "generation": 2})).unwrap()).await.unwrap();
        assert!(policy_digest(&kv, ns).await.is_err());
        seed(&kv, ns, 2).await;
        assert_ne!(policy_digest(&kv, ns).await.unwrap(), digest);
        kv.set(ns, "policy/keys/1", "c".repeat(64).into_bytes())
            .await
            .unwrap();
        assert!(policy_digest(&kv, ns).await.is_err());
    }

    #[tokio::test]
    async fn native_candidate_digest_pins_only_active_dependencies() {
        let kv = astrid_storage::MemoryKvStore::new();
        let ns = "alice:capsule:codewall-enforcer";
        seed(&kv, ns, 1).await;
        let digest = policy_digest(&kv, ns).await.unwrap();
        kv.set(ns, "audit/outbox/next", vec![1]).await.unwrap();
        assert_eq!(policy_digest(&kv, ns).await.unwrap(), digest);
        kv.set(
            ns,
            &format!("policy/artifacts/sha256:{}", "a".repeat(64)),
            b"changed".to_vec(),
        )
        .await
        .unwrap();
        assert_ne!(policy_digest(&kv, ns).await.unwrap(), digest);
    }

    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one durable snapshot and live mutation lifecycle"
    )]
    async fn native_candidate_owner_snapshot_keeps_live_policy_and_custody_separate() {
        use astrid_storage::IdentityStore;
        let temporary = tempfile::tempdir().unwrap();
        let home = astrid_core::dirs::AstridHome::from_path(temporary.path());
        let store = astrid_storage::open_runtime_principal_store(
            &home,
            Arc::new(|_: &astrid_storage::StateOwner| Ok(Some(128 * 1024 * 1024))),
        )
        .await
        .unwrap();
        let identities = astrid_storage::KvIdentityStore::with_principal_directory(
            astrid_storage::ScopedKvStore::new(store.kv(), "system:identity").unwrap(),
            store.principal_directory(),
        );
        let principal = PrincipalId::new("alice").unwrap();
        let user = identities
            .create_principal(principal.clone(), [7; 32])
            .await
            .unwrap();
        let uid = identities
            .get_principal_identity(user.id)
            .await
            .unwrap()
            .unwrap()
            .uid;
        let identity = |id: &str| astrid_core::kernel_api::InstalledCapsuleIdentity {
            id: id.into(),
            generation: astrid_core::kernel_api::InstalledCapsuleGeneration {
                archive: "a".repeat(64),
                metadata: "b".repeat(64),
                authority: "c".repeat(64),
            },
            archive_digest: "d".repeat(64),
            wasm_hash: Some("e".repeat(64)),
        };
        let pair = NativePairIdentityV1 {
            enforcer: identity("codewall-enforcer"),
            protocol: identity("codewall-protocol"),
            enforcer_source: uuid::Uuid::new_v4(),
            protocol_source: uuid::Uuid::new_v4(),
        };
        let ns = "alice:capsule:codewall-enforcer";
        seed(store.kv().as_ref(), ns, 1).await;
        let members = members();
        let shared_namespace = astrid_storage::env::system_capsule_namespace("codewall-enforcer");
        store
            .kv()
            .set(&shared_namespace, "__env:PIN", b"shared".to_vec())
            .await
            .unwrap();
        let snapshot = NativeCandidateSnapshot::capture(&store, &principal, uid, &pair, &members)
            .await
            .unwrap();
        assert_eq!(snapshot.env["codewall-enforcer"]["PIN"], "shared");
        let fence = store.native_policy_fence();
        let guard = fence.lock().await;
        assert!(snapshot.environment_matches(&store).await.unwrap());
        drop(guard);
        let primary_namespace =
            astrid_storage::env::principal_capsule_namespace(uid, "codewall-enforcer");
        store
            .kv()
            .set(&primary_namespace, "__env:PIN", b"new-primary".to_vec())
            .await
            .unwrap();
        let guard = fence.lock().await;
        assert!(!snapshot.environment_matches(&store).await.unwrap());
        drop(guard);
        let candidate = snapshot
            .detached_host_context(Arc::clone(&members[0]))
            .await
            .unwrap();
        let context = candidate.capsule_context().unwrap();
        assert!(context.kv.set("policy/active", vec![1]).await.is_err());
        seed(store.kv().as_ref(), ns, 2).await;
        assert_ne!(
            policy_digest(store.kv().as_ref(), ns).await.unwrap(),
            snapshot.digest()
        );
        assert_eq!(
            policy_digest(snapshot.state.kv().as_ref(), ns)
                .await
                .unwrap(),
            snapshot.digest()
        );
        snapshot
            .state
            .kv()
            .set(
                "alice:capsule:codewall-protocol",
                "outbox/native",
                b"private".to_vec(),
            )
            .await
            .unwrap();
        assert!(
            store
                .kv()
                .get("alice:capsule:codewall-protocol", "outbox/native")
                .await
                .unwrap()
                .is_none()
        );
        store
            .kv()
            .set(ns, "policy/active", b"malformed".to_vec())
            .await
            .unwrap();
        assert!(
            NativeCandidateSnapshot::capture(&store, &principal, uid, &pair, &members)
                .await
                .is_err()
        );
        assert_eq!(
            store.kv().get(ns, "policy/active").await.unwrap(),
            Some(b"malformed".to_vec())
        );
        assert_eq!(
            policy_digest(snapshot.state.kv().as_ref(), ns)
                .await
                .unwrap(),
            snapshot.digest()
        );
    }
}
