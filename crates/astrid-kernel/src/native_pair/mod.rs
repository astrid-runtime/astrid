//! Private native pair staging. No capability bit is advertised here.
mod lease;
#[cfg(test)]
mod lease_tests;
mod snapshot;

use anyhow::{Context as _, ensure};
use astrid_capsule::{
    capsule::CapsuleId,
    registry::{RuntimeId, RuntimeScope},
};
use astrid_capsule_install::{
    VerifiedDurableCapsulePackage, native_pair::verify_native_pair_member,
};
use astrid_core::kernel_api::{
    BeginNativePairUpgrade, InstalledCapsuleGeneration, InstalledCapsuleIdentity,
    NativePairIdentityV1, NativePairLeaseV1, NativePairPhaseV1, NativePairStateV1,
    StageNativePairMember,
};
use astrid_storage::StateOwner;
pub(crate) use lease::{LeaseStore, NativePairActor};
use std::sync::Arc;

struct OldPair {
    identity: NativePairIdentityV1,
    runtimes: [RuntimeId; 2],
    // Owning immutable package snapshots survive concurrent replacement and GC.
    packages: [VerifiedDurableCapsulePackage; 2],
}

pub(crate) struct NativePairCoordinator<'a> {
    kernel: &'a crate::Kernel,
}
impl<'a> NativePairCoordinator<'a> {
    pub(crate) fn new(kernel: &'a crate::Kernel) -> Self {
        Self { kernel }
    }
    pub(crate) async fn begin(
        &self,
        actor: &NativePairActor,
        request: BeginNativePairUpgrade,
    ) -> anyhow::Result<NativePairLeaseV1> {
        lease::validate_begin(actor, &request, now()?)?;
        let _load = self.kernel.capsule_load_lock.lock().await;
        let old = self.capture(actor).await?;
        ensure!(
            old.identity == request.expected_old,
            "native pair old generation mismatch"
        );
        let mut leases = self.kernel.native_pair_leases.lock().await;
        let result = leases.begin(actor, request, now()?)?;
        leases.get(actor, result.lease_id, now()?)?.old = Some(old);
        Ok(result)
    }
    pub(crate) async fn stage_member(
        &self,
        actor: &NativePairActor,
        chunk: StageNativePairMember,
    ) -> anyhow::Result<NativePairLeaseV1> {
        let _load = self.kernel.capsule_load_lock.lock().await;
        let mut leases = self.kernel.native_pair_leases.lock().await;
        self.check_live(&mut leases, actor, chunk.lease.lease_id)
            .await?;
        if let Some(bytes) = leases.append(actor, &chunk, now()?)? {
            let member = leases
                .get(actor, chunk.lease.lease_id, now()?)?
                .request
                .members
                .iter()
                .find(|member| member.id == chunk.member_id)
                .context("native member absent")?
                .clone();
            let verified = verify_native_pair_member(
                &bytes,
                &member.id,
                member.authority,
                member.env,
                self.kernel.runtime_key.public_key_bytes(),
            );
            let Ok(verified) = verified else {
                leases.abort(actor, chunk.lease.lease_id, now()?)?;
                anyhow::bail!("native pair member verification failed");
            };
            // Same-enrollment source upgrades cannot widen installed capability authority.
            let old = leases
                .get(actor, chunk.lease.lease_id, now()?)?
                .old
                .as_ref()
                .context("native pair pin absent")?;
            let index = old
                .packages
                .iter()
                .position(|package| package.id() == member.id)
                .context("native member absent")?;
            if !verified
                .authority()
                .approved_capabilities
                .expansions_from(&old.packages[index].authority().approved_capabilities)
                .is_empty()
            {
                leases.abort(actor, chunk.lease.lease_id, now()?)?;
                anyhow::bail!("native pair capability expansion requires ordinary approval");
            }
            let lease = leases.get(actor, chunk.lease.lease_id, now()?)?;
            let index = lease
                .request
                .members
                .iter()
                .position(|member| member.id == chunk.member_id)
                .context("native member absent")?;
            lease.verified[index] = Some(Arc::new(verified));
        }
        self.check_live(&mut leases, actor, chunk.lease.lease_id)
            .await?;
        let lease = leases.get(actor, chunk.lease.lease_id, now()?)?;
        self.prepare_snapshot(actor, lease).await?;
        self.check_live(&mut leases, actor, chunk.lease.lease_id)
            .await?;
        Ok(leases
            .get(actor, chunk.lease.lease_id, now()?)?
            .state
            .lease
            .clone())
    }

    async fn prepare_snapshot(
        &self,
        actor: &NativePairActor,
        lease: &mut lease::Lease,
    ) -> anyhow::Result<()> {
        if lease.verified.iter().all(Option::is_some) && lease.snapshot.is_none() {
            let pair = &lease
                .old
                .as_ref()
                .context("native pair pin absent")?
                .identity;
            let snapshot = snapshot::NativeCandidateSnapshot::capture(
                self.kernel
                    .principal_store
                    .as_ref()
                    .context("native pair storage absent")?,
                &actor.target,
                actor.uid,
                pair,
                &[
                    Arc::clone(
                        lease.verified[0]
                            .as_ref()
                            .context("native enforcer verification missing")?,
                    ),
                    Arc::clone(
                        lease.verified[1]
                            .as_ref()
                            .context("native protocol verification missing")?,
                    ),
                ],
            )
            .await?;
            let host_contexts = [
                snapshot
                    .detached_host_context(Arc::clone(
                        lease.verified[0]
                            .as_ref()
                            .context("native member verification missing")?,
                    ))
                    .await?,
                snapshot
                    .detached_host_context(Arc::clone(
                        lease.verified[1]
                            .as_ref()
                            .context("native member verification missing")?,
                    ))
                    .await?,
            ];
            lease.state.lease.policy_snapshot_digest = Some(snapshot.digest());
            lease.snapshot = Some(Arc::new(snapshot));
            lease.host_contexts = Some(host_contexts);
        }
        Ok(())
    }
    pub(crate) async fn abort(
        &self,
        actor: &NativePairActor,
        id: uuid::Uuid,
    ) -> anyhow::Result<NativePairStateV1> {
        // Cancellation also works after old generation invalidation or retirement.
        self.kernel
            .native_pair_leases
            .lock()
            .await
            .abort(actor, id, now()?)
    }
    pub(crate) async fn status(
        &self,
        actor: &NativePairActor,
        id: uuid::Uuid,
    ) -> anyhow::Result<NativePairStateV1> {
        let _load = self.kernel.capsule_load_lock.lock().await;
        let mut leases = self.kernel.native_pair_leases.lock().await;
        if leases.get(actor, id, now()?)?.state.phase != NativePairPhaseV1::Aborted {
            let _ = self.check_live(&mut leases, actor, id).await;
        }
        Ok(leases.get(actor, id, now()?)?.state.clone())
    }
    async fn check_live(
        &self,
        leases: &mut LeaseStore,
        actor: &NativePairActor,
        id: uuid::Uuid,
    ) -> anyhow::Result<()> {
        let lease = leases.get(actor, id, now()?)?;
        let valid = self
            .live_matches(actor, lease.old.as_ref())
            .await
            .unwrap_or(false);
        if !valid {
            leases.abort(actor, id, now()?)?;
            anyhow::bail!("native pair old generation changed");
        }
        Ok(())
    }
    async fn live_matches(
        &self,
        actor: &NativePairActor,
        old: Option<&OldPair>,
    ) -> anyhow::Result<bool> {
        let Some(old) = old else {
            return Ok(false);
        };
        if self.kernel.principal_directory.uid_for(&actor.target)? != actor.uid
            || self.kernel.principal_directory.uid_for(&actor.caller)? != actor.caller_uid
            || self
                .kernel
                .capabilities
                .is_principal_retiring(&actor.target)
                .await
            || self
                .kernel
                .capabilities
                .is_principal_retiring(&actor.caller)
                .await
        {
            return Ok(false);
        }
        let store = self
            .kernel
            .principal_store
            .as_ref()
            .context("native pair storage absent")?;
        let registry = self.kernel.capsules.read().await;
        let resolver = astrid_capsule::CapsuleAccessResolver::new(
            Arc::clone(&self.kernel.profile_cache),
            Arc::clone(&self.kernel.groups),
        );
        for (index, package) in old.packages.iter().enumerate() {
            let id = CapsuleId::new(package.id())?;
            if registry.runtime_id_for(&actor.target, &id).as_ref() != Some(&old.runtimes[index])
                || !resolver.is_capsule_allowed(Some(actor.target.as_str()), &id)
                || !store
                    .capsules()
                    .get_snapshot(&StateOwner::Principal(actor.uid), package.id())?
                    .is_some_and(|snapshot| {
                        snapshot.generation() == package.snapshot().generation()
                    })
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
    async fn validate_actor(&self, actor: &NativePairActor) -> anyhow::Result<()> {
        ensure!(
            actor.incarnation == self.kernel.native_protection_incarnation
                && self.kernel.principal_directory.uid_for(&actor.target)? == actor.uid
                && self.kernel.principal_directory.uid_for(&actor.caller)? == actor.caller_uid
                && !self
                    .kernel
                    .capabilities
                    .is_principal_retiring(&actor.target)
                    .await
                && !self
                    .kernel
                    .capabilities
                    .is_principal_retiring(&actor.caller)
                    .await,
            "native pair principal invalid"
        );
        Ok(())
    }
    async fn capture(&self, actor: &NativePairActor) -> anyhow::Result<OldPair> {
        self.validate_actor(actor).await?;
        let store = self
            .kernel
            .principal_store
            .as_ref()
            .context("native pair durable store unavailable")?;
        let owner = StateOwner::Principal(actor.uid);
        let mut packages = Vec::new();
        let mut identities = Vec::new();
        let mut runtimes = Vec::new();
        let mut sources = Vec::new();
        let registry = self.kernel.capsules.read().await;
        let resolver = astrid_capsule::CapsuleAccessResolver::new(
            Arc::clone(&self.kernel.profile_cache),
            Arc::clone(&self.kernel.groups),
        );
        for name in ["codewall-enforcer", "codewall-protocol"] {
            let package = astrid_capsule_install::read_verified_durable_package_for_owner(
                store, &owner, name,
            )
            .map_err(|_| anyhow::anyhow!("native pair installed authority invalid"))?
            .context("native pair package missing")?;
            let id = CapsuleId::new(name)?;
            let runtime = registry
                .runtime_id_for(&actor.target, &id)
                .context("native pair runtime missing")?;
            let source = registry
                .source_id_for(&actor.target, &id)
                .context("native pair source missing")?;
            let wasm = package
                .metadata()
                .wasm_hash
                .as_deref()
                .context("native pair executable missing")?;
            let loaded = registry
                .get_for(&actor.target, &id)
                .context("native pair view missing")?;
            ensure!(
                runtime.key().scope() == RuntimeScope::Principal(actor.uid)
                    && resolver.is_capsule_allowed(Some(actor.target.as_str()), &id)
                    && package.authority().source
                        != astrid_capsule_install::AuthoritySource::LegacyMigration
                    && package.authority().wasm_hash_pinned
                    && package.authority().approved_wasm_hash.as_deref() == Some(wasm)
                    && registry
                        .hash_for(&actor.target, &id)
                        .is_some_and(|hash| hash.as_str() == wasm)
                    && source
                        == uuid::Uuid::new_v5(
                            &uuid::Uuid::from_u128(0x310714d5_9c6d_4c94_8187_75258f393bb6),
                            format!("{name}\0{wasm}").as_bytes()
                        )
                    && serde_json::to_value(loaded.manifest())?
                        == serde_json::to_value(package.manifest())?,
                "native pair live authority mismatch"
            );
            identities.push(package_identity(&package));
            runtimes.push(runtime);
            sources.push(source);
            packages.push(package);
        }
        // Detect an ordinary install publishing while the immutable pair was read.
        for package in &packages {
            ensure!(
                store
                    .capsules()
                    .get_snapshot(&owner, package.id())?
                    .is_some_and(
                        |snapshot| snapshot.generation() == package.snapshot().generation()
                    ),
                "native pair package changed"
            );
        }
        ensure!(
            self.kernel.principal_directory.uid_for(&actor.target)? == actor.uid
                && !self
                    .kernel
                    .capabilities
                    .is_principal_retiring(&actor.target)
                    .await,
            "native pair principal retired"
        );
        let [enforcer, protocol]: [_; 2] = identities
            .try_into()
            .map_err(|_| anyhow::anyhow!("native pair identity count"))?;
        Ok(OldPair {
            identity: NativePairIdentityV1 {
                enforcer,
                protocol,
                enforcer_source: sources[0],
                protocol_source: sources[1],
            },
            runtimes: runtimes
                .try_into()
                .map_err(|_| anyhow::anyhow!("native pair runtime count"))?,
            packages: packages
                .try_into()
                .map_err(|_| anyhow::anyhow!("native pair package count"))?,
        })
    }
}
fn now() -> anyhow::Result<u64> {
    Ok(u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis(),
    )?)
}

fn package_identity(package: &VerifiedDurableCapsulePackage) -> InstalledCapsuleIdentity {
    let generation = package.snapshot().generation();
    InstalledCapsuleIdentity {
        id: package.id().to_owned(),
        generation: InstalledCapsuleGeneration {
            archive: hex::encode(generation.archive().as_bytes()),
            metadata: hex::encode(generation.metadata().as_bytes()),
            authority: hex::encode(generation.authority().as_bytes()),
        },
        archive_digest: blake3::hash(package.archive()).to_hex().to_string(),
        wasm_hash: package.metadata().wasm_hash.clone(),
    }
}
