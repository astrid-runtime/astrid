//! Read-only daemon and installed adapter prerequisite attestation.

use astrid_capsule::capsule::CapsuleId;
use astrid_capsule::registry::RuntimeScope;
use astrid_capsule_install::authority::AuthoritySource;
use astrid_core::PrincipalId;
use astrid_core::kernel_api::{
    InstalledCapsuleGeneration, InstalledCapsuleIdentity, NativeAdapterApprovalV1,
    NativeProtectionCapabilitiesV1,
};
use astrid_storage::StateOwner;

const ADAPTER: &str = "aos-hook-adapter-oracle";
const SOURCE_NAMESPACE: uuid::Uuid = uuid::Uuid::from_u128(0x310714d5_9c6d_4c94_8187_75258f393bb6);

impl crate::Kernel {
    /// Attest implemented native prerequisites and current adapter authority.
    ///
    /// This does not load capsules, repair receipts, or modify principal state.
    /// Management callers must pass the ordinary capsule-list authorization gate.
    ///
    /// # Errors
    /// Returns an error when the durable principal identity cannot be resolved.
    pub async fn native_protection_capabilities(
        &self,
        principal: &PrincipalId,
    ) -> anyhow::Result<NativeProtectionCapabilitiesV1> {
        let uid = self.principal_directory.uid_for(principal)?;
        let context_digest = self.native_protection_context.clone();
        let mut response = NativeProtectionCapabilitiesV1 {
            schema_version: 1,
            daemon_incarnation: self.native_protection_incarnation,
            context_digest,
            principal_uid: uid,
            features: ["interrupted_instance_recovery_v1".to_owned()].into(),
            adapter: None,
        };
        let Some(store) = &self.principal_store else {
            return Ok(response);
        };
        let owner = StateOwner::Principal(uid);
        // Corrupt or missing receipts cannot produce a verified installed identity.
        // Do not return verifier diagnostics that could contain package metadata.
        let Ok(Some(package)) =
            astrid_capsule_install::read_verified_durable_package_for_owner(store, &owner, ADAPTER)
        else {
            return Ok(response);
        };
        let id = CapsuleId::new(ADAPTER)?;
        let registry = self.capsules.read().await;
        let Some(loaded) = registry.get_for(principal, &id) else {
            return Ok(response);
        };
        let Some(source_id) = registry.source_id_for(principal, &id) else {
            return Ok(response);
        };
        let wasm = package.metadata().wasm_hash.as_deref();
        let authority = package.authority();
        let generation = package.snapshot().generation();
        let source_class = match authority.source {
            AuthoritySource::LocalRuntimeBuild => "local-runtime-build",
            AuthoritySource::ExplicitApproval => "explicit-approval",
            AuthoritySource::OperatorDistribution => "operator-distribution",
            AuthoritySource::LegacyMigration => "legacy-migration",
        };
        let catalog_matches = wasm.is_some_and(|hash| {
            astrid_capsule_install::wasm::catalog_wasm_hash(store, hash)
                .is_ok_and(|actual| actual == hash)
        });
        let artifact_matches = wasm.is_some_and(|hash| {
            registry
                .hash_for(principal, &id)
                .is_some_and(|loaded| loaded.as_str() == hash)
        });
        let source_matches = wasm.is_some_and(|hash| {
            source_id
                == uuid::Uuid::new_v5(&SOURCE_NAMESPACE, format!("{ADAPTER}\0{hash}").as_bytes())
        });
        let runtime_owner_matches = registry
            .runtime_id_for(principal, &id)
            .is_some_and(|runtime| runtime.key().scope() == RuntimeScope::Principal(uid));
        let manifest_matches = serde_json::to_value(loaded.manifest()).is_ok_and(|live| {
            serde_json::to_value(package.manifest()).is_ok_and(|durable| live == durable)
        });
        let resolver = astrid_capsule::CapsuleAccessResolver::new(
            std::sync::Arc::clone(&self.profile_cache),
            std::sync::Arc::clone(&self.groups),
        );
        let approved = authority.source != AuthoritySource::LegacyMigration
            && authority.wasm_hash_pinned
            && authority.approved_wasm_hash.as_deref() == wasm
            && catalog_matches
            && artifact_matches
            && source_matches
            && runtime_owner_matches
            && manifest_matches
            && hook_manifest_contract(package.manifest())
            && resolver.is_capsule_allowed(Some(principal.as_str()), &id)
            && !self.capabilities.is_principal_retiring(principal).await
            && self.principal_directory.uid_for(principal).ok() == Some(uid)
            && store
                .capsules()
                .get_snapshot(&owner, ADAPTER)?
                .is_some_and(|current| current.generation() == generation);
        response.adapter = Some(NativeAdapterApprovalV1 {
            identity: InstalledCapsuleIdentity {
                id: ADAPTER.to_owned(),
                generation: InstalledCapsuleGeneration {
                    archive: hex::encode(generation.archive().as_bytes()),
                    metadata: hex::encode(generation.metadata().as_bytes()),
                    authority: hex::encode(generation.authority().as_bytes()),
                },
                archive_digest: blake3::hash(package.archive()).to_hex().to_string(),
                wasm_hash: package.metadata().wasm_hash.clone(),
            },
            source_id,
            authority_class: source_class.to_owned(),
            authority_digest: authority
                .content_digest
                .strip_prefix("blake3:")
                .unwrap_or(&authority.content_digest)
                .to_owned(),
            approved_for_native_hook: approved,
        });
        Ok(response)
    }
}

fn hook_manifest_contract(manifest: &astrid_capsule::manifest::CapsuleManifest) -> bool {
    ["hook.v1.event.*", "oracle.v1.hook.response.*"]
        .iter()
        .all(|topic| manifest.publishes.contains_key(*topic))
        && ["codex", "claude", "grok"].iter().all(|frontend| {
            manifest
                .subscribes
                .get(&format!("oracle.v1.hook.validated.{frontend}"))
                .is_some_and(|entry| {
                    entry
                        .handler
                        .as_ref()
                        .is_some_and(|handler| !handler.is_empty())
                })
        })
}
