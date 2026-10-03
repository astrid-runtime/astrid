//! Bounded, caller/UID/incarnation-bound private lease storage.
use anyhow::{bail, ensure};
use astrid_capsule_install::native_pair::VerifiedNativePairMember;
use astrid_core::{
    PrincipalId,
    identity::PrincipalUid,
    kernel_api::{
        BeginNativePairUpgrade, EnvValueKind, NativePairLeaseV1, NativePairPhaseV1,
        NativePairStateV1, StageNativePairMember,
    },
};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

pub(super) const MAX_ARCHIVE: u64 = 64 * 1024 * 1024;
pub(super) const MAX_CHUNK: usize = 256 * 1024;
const MAX_LEASES: usize = 4;
const MAX_REPLAYS: usize = 1024;

/// Created only after router authorization, from authenticated principal identity.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct NativePairActor {
    pub(crate) caller: PrincipalId,
    pub(crate) caller_uid: PrincipalUid,
    pub(crate) target: PrincipalId,
    pub(crate) uid: PrincipalUid,
    pub(crate) incarnation: Uuid,
}

pub(super) struct Lease {
    pub(super) actor: NativePairActor,
    pub(super) request: BeginNativePairUpgrade,
    pub(super) state: NativePairStateV1,
    deadline: Instant,
    buffers: [Vec<u8>; 2],
    completed: [bool; 2],
    pub(super) verified: [Option<Arc<VerifiedNativePairMember>>; 2],
    pub(super) old: Option<super::OldPair>,
}

#[derive(Default)]
pub(crate) struct LeaseStore {
    pub(super) leases: HashMap<Uuid, Lease>,
    replay: HashMap<(PrincipalUid, Uuid), Instant>,
}
impl LeaseStore {
    fn prune(&mut self, now: u64) {
        self.leases.retain(|_, lease| {
            now < lease.state.lease.expires_at_unix_ms && Instant::now() < lease.deadline
        });
        self.replay.retain(|_, deadline| Instant::now() < *deadline);
    }
    pub(super) fn begin(
        &mut self,
        actor: &NativePairActor,
        request: BeginNativePairUpgrade,
        now: u64,
    ) -> anyhow::Result<NativePairLeaseV1> {
        self.prune(now);
        validate_begin(actor, &request, now)?;
        ensure!(
            self.leases
                .values()
                .filter(|lease| lease.state.phase != NativePairPhaseV1::Aborted)
                .count()
                < MAX_LEASES
                && self.leases.len() < MAX_REPLAYS
                && self.replay.len() < MAX_REPLAYS,
            "native pair lease capacity reached"
        );
        ensure!(
            !self
                .leases
                .values()
                .any(|lease| lease.actor.uid == actor.uid
                    && lease.state.phase != NativePairPhaseV1::Aborted),
            "native pair lease already active"
        );
        ensure!(
            !self.replay.contains_key(&(actor.caller_uid, request.nonce)),
            "native pair nonce already used"
        );
        let lease = NativePairLeaseV1 {
            lease_id: Uuid::new_v4(),
            daemon_incarnation: actor.incarnation,
            principal_uid: actor.uid,
            expires_at_unix_ms: request.expires_at_unix_ms,
            old: request.expected_old.clone(),
            candidate: None,
            policy_snapshot_digest: None,
        };
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(
                request.expires_at_unix_ms.saturating_sub(now),
            ))
            .ok_or_else(|| anyhow::anyhow!("native pair deadline overflow"))?;
        self.replay.insert(
            (actor.caller_uid, request.nonce),
            Instant::now()
                .checked_add(Duration::from_mins(5))
                .ok_or_else(|| anyhow::anyhow!("native pair deadline overflow"))?,
        );
        self.leases.insert(
            lease.lease_id,
            Lease {
                actor: actor.clone(),
                request,
                state: NativePairStateV1 {
                    lease: lease.clone(),
                    phase: NativePairPhaseV1::Staging,
                },
                deadline,
                buffers: Default::default(),
                completed: [false; 2],
                verified: Default::default(),
                old: None,
            },
        );
        Ok(lease)
    }
    pub(super) fn get(
        &mut self,
        actor: &NativePairActor,
        id: Uuid,
        now: u64,
    ) -> anyhow::Result<&mut Lease> {
        self.prune(now);
        let lease = self
            .leases
            .get_mut(&id)
            .ok_or_else(|| anyhow::anyhow!("native pair lease absent or expired"))?;
        ensure!(&lease.actor == actor, "native pair lease owner mismatch");
        Ok(lease)
    }
    pub(super) fn append(
        &mut self,
        actor: &NativePairActor,
        chunk: &StageNativePairMember,
        now: u64,
    ) -> anyhow::Result<Option<Vec<u8>>> {
        ensure!(
            chunk.chunk.len() <= MAX_CHUNK && !chunk.chunk.is_empty(),
            "native pair chunk size invalid"
        );
        // JSON serializes Vec<u8> as decimal arrays (up to four bytes per byte).
        // Reserve a full 64 KiB for the authenticated native transport envelope.
        ensure!(
            serde_json::to_vec(chunk)?.len() <= 2 * 1024 * 1024 - 64 * 1024,
            "native pair wire frame too large"
        );
        ensure!(
            chunk.lease.target_principal == actor.target
                && chunk.lease.principal_uid == actor.uid
                && chunk.lease.daemon_incarnation == actor.incarnation,
            "native pair assertion mismatch"
        );
        let lease = self.get(actor, chunk.lease.lease_id, now)?;
        ensure!(
            lease.state.phase == NativePairPhaseV1::Staging,
            "native pair lease is not staging"
        );
        let index = lease
            .request
            .members
            .iter()
            .position(|member| member.id == chunk.member_id)
            .ok_or_else(|| anyhow::anyhow!("native pair member not declared"))?;
        let member = &lease.request.members[index];
        ensure!(
            !lease.completed[index]
                && chunk.total_bytes == member.source_bytes
                && chunk.offset == lease.buffers[index].len() as u64,
            "native pair chunk offset or size mismatch"
        );
        let end = chunk
            .offset
            .checked_add(chunk.chunk.len() as u64)
            .ok_or_else(|| anyhow::anyhow!("native pair chunk overflow"))?;
        ensure!(
            end <= member.source_bytes && chunk.final_chunk == (end == member.source_bytes),
            "native pair chunk completion mismatch"
        );
        lease.buffers[index].extend_from_slice(&chunk.chunk);
        if !chunk.final_chunk {
            return Ok(None);
        }
        lease.completed[index] = true;
        let bytes = std::mem::take(&mut lease.buffers[index]);
        if blake3::hash(&bytes).to_hex().as_str() != member.source_digest {
            lease.state.phase = NativePairPhaseV1::Aborted;
            lease.buffers = Default::default();
            lease.verified = Default::default();
            lease.old = None;
            for member in &mut lease.request.members {
                member.env.clear();
            }
            bail!("native pair archive digest mismatch");
        }
        Ok(Some(bytes))
    }
    pub(super) fn abort(
        &mut self,
        actor: &NativePairActor,
        id: Uuid,
        now: u64,
    ) -> anyhow::Result<NativePairStateV1> {
        let lease = self.get(actor, id, now)?;
        ensure!(
            matches!(
                lease.state.phase,
                NativePairPhaseV1::Staging | NativePairPhaseV1::Aborted
            ),
            "native pair lease cannot abort"
        );
        lease.state.phase = NativePairPhaseV1::Aborted;
        lease.buffers = Default::default();
        lease.verified = Default::default();
        lease.old = None;
        for member in &mut lease.request.members {
            member.env.clear();
        }
        Ok(lease.state.clone())
    }
}
fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(super) fn validate_begin(
    actor: &NativePairActor,
    request: &BeginNativePairUpgrade,
    now: u64,
) -> anyhow::Result<()> {
    ensure!(
        request.target_principal == actor.target
            && request.principal_uid == actor.uid
            && request.daemon_incarnation == actor.incarnation,
        "native pair assertion mismatch"
    );
    ensure!(
        request.expires_at_unix_ms > now
            && request.expires_at_unix_ms.saturating_sub(now) <= 300_000,
        "native pair deadline invalid"
    );
    ensure!(
        !request.nonce.is_nil()
            && !request.installation_id.is_nil()
            && !request.journal_id.is_nil(),
        "native pair binding invalid"
    );
    ensure!(
        request.expected_old.enforcer.id == "codewall-enforcer"
            && request.expected_old.protocol.id == "codewall-protocol",
        "native pair old identity invalid"
    );
    let mut ids = std::collections::BTreeSet::new();
    for member in &request.members {
        ensure!(
            matches!(
                member.id.as_str(),
                "codewall-enforcer" | "codewall-protocol"
            ) && ids.insert(&member.id),
            "native pair member invalid"
        );
        ensure!(
            member.source_bytes > 0
                && member.source_bytes <= MAX_ARCHIVE
                && digest(&member.source_digest),
            "native pair archive declaration invalid"
        );
        ensure!(member.env.len() <= 64, "native pair environment limit");
        let mut total = 0_usize;
        let mut keys = std::collections::BTreeSet::new();
        for value in &member.env {
            total = total
                .checked_add(value.value.len())
                .ok_or_else(|| anyhow::anyhow!("native pair environment limit"))?;
            ensure!(
                total <= 64 * 1024
                    && value.key.len() <= 128
                    && !value.key.is_empty()
                    && !value.key.contains(['\0', ':'])
                    && keys.insert(&value.key),
                "native pair environment limit"
            );
            ensure!(
                value.kind == EnvValueKind::Text && value.key != "CODEWALL_ENROLMENT_TOKEN",
                "native pair shared or enrollment mutation forbidden"
            );
        }
    }
    ensure!(
        serde_json::to_vec(request)?.len() < 2 * 1024 * 1024 - 64 * 1024,
        "native pair wire frame too large"
    );
    Ok(())
}
