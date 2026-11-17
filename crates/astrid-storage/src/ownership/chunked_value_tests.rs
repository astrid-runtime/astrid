//! Exercise the ownership caller through the native durable KV path.
use super::*;
use astrid_core::{
    FleetGenesis, FleetIdentity, FleetMembership, FleetRole, PrincipalId, PrincipalOwnership,
    PrincipalUid, UserGenesis, UserIdentity, dirs::AstridHome,
};
use chrono::{TimeZone, Utc};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

use crate::{
    KvBatchCondition, KvBatchMutation, KvEntryKey, KvMutationBatch, KvStore,
    MAX_KV_BATCH_OPERATIONS,
};

const FLEET_SCALE_PRINCIPALS: u32 = 10_000;
const DELETE_PROBE_COUNT: u32 = 3;
const OPERATOR_DEVICE_KEY: [u8; 32] = [9; 32];
const SYSTEM_AUX_NAMESPACE: &str = "system:probe-aux";
const SYSTEM_AUX_PREFIXES: [&str; 3] = ["a/", "m/", "z/"];
const SYSTEM_AUX_VALUE_LEN: usize = 16;

fn user(index: u128) -> UserIdentity {
    UserIdentity::from_genesis(UserGenesis::from_parts(
        Uuid::from_u128(index),
        Utc.timestamp_opt(1_700_000_000, 0).unwrap(),
        [7; 32],
    ))
    .unwrap()
}

fn principal_uid(index: u32) -> PrincipalUid {
    // Real immutable UIDs are hash-distributed; long zero-filled synthetic
    // identifiers would bias content-defined chunk boundaries in this probe.
    PrincipalUid::from_bytes(*blake3::hash(&index.to_be_bytes()).as_bytes())
}

fn principal_alias(index: u32) -> PrincipalId {
    PrincipalId::new(format!("a{index:05}")).unwrap()
}

fn volume_len(home: &AstridHome) -> u64 {
    std::fs::metadata(home.storage_volume_path())
        .expect("initialized native volume must remain present")
        .len()
}

async fn graph_wire(kv: &Arc<dyn KvStore>) -> Vec<u8> {
    kv.get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
        .await
        .expect("ownership graph get")
        .expect("seeded ownership graph")
}

fn seeded_scale_graph(
    owner: &UserIdentity,
    fleet: &FleetIdentity,
    operator_uid: PrincipalUid,
) -> OwnershipSnapshot {
    let mut graph = OwnershipSnapshot::default();
    graph.users.insert(owner.uid, owner.clone());
    graph.fleets.insert(
        fleet.uid,
        FleetRecord {
            identity: fleet.clone(),
            memberships: BTreeMap::from([(
                owner.uid,
                FleetMembership {
                    fleet_uid: fleet.uid,
                    user_uid: owner.uid,
                    role: FleetRole::Owner,
                    granted_by: owner.uid,
                },
            )]),
        },
    );
    graph.principal_ownership.insert(
        operator_uid,
        PrincipalOwnership {
            principal_uid: operator_uid,
            fleet_uid: fleet.uid,
            assigned_by: owner.uid,
        },
    );
    graph.accountable_users.insert(operator_uid, owner.uid);
    for index in 1..=FLEET_SCALE_PRINCIPALS {
        let uid = principal_uid(index);
        graph.principal_ownership.insert(
            uid,
            PrincipalOwnership {
                principal_uid: uid,
                fleet_uid: fleet.uid,
                assigned_by: owner.uid,
            },
        );
        graph.accountable_users.insert(uid, owner.uid);
    }
    graph
}

fn system_aux_key(prefix: &str, index: u32) -> String {
    let mut material = Vec::with_capacity(prefix.len().strict_add(4));
    material.extend_from_slice(prefix.as_bytes());
    material.extend_from_slice(&index.to_be_bytes());
    format!("{prefix}{}", blake3::hash(&material).to_hex())
}

fn system_aux_value(index: u32, prefix_ordinal: u8) -> Vec<u8> {
    let mut value = vec![0_u8; SYSTEM_AUX_VALUE_LEN];
    value[..4].copy_from_slice(&index.to_be_bytes());
    value[4] = prefix_ordinal;
    value[5] = 0xa5;
    value
}

async fn flush_system_aux_batch(kv: &Arc<dyn KvStore>, mutations: &mut Vec<KvBatchMutation>) {
    if mutations.is_empty() {
        return;
    }
    let batch = KvMutationBatch::new(
        std::iter::empty::<KvBatchCondition>(),
        std::mem::take(mutations),
    )
    .expect("system aux seed batch");
    assert!(
        kv.apply_batch(&batch)
            .await
            .expect("system aux seed apply")
            .applied
    );
}

async fn seed_system_aux_rows(kv: &Arc<dyn KvStore>, principal_count: u32) {
    let total = usize::try_from(principal_count)
        .unwrap()
        .strict_mul(SYSTEM_AUX_PREFIXES.len());
    let mut mutations = Vec::with_capacity(MAX_KV_BATCH_OPERATIONS.min(total));
    for index in 1..=principal_count {
        for (prefix_ordinal, prefix) in SYSTEM_AUX_PREFIXES.iter().copied().enumerate() {
            if mutations.len() == MAX_KV_BATCH_OPERATIONS {
                flush_system_aux_batch(kv, &mut mutations).await;
            }
            mutations.push(KvBatchMutation::Set {
                key: KvEntryKey::new(SYSTEM_AUX_NAMESPACE, system_aux_key(prefix, index)).unwrap(),
                value: system_aux_value(
                    index,
                    u8::try_from(prefix_ordinal).expect("three prefixes"),
                ),
            });
        }
    }
    flush_system_aux_batch(kv, &mut mutations).await;
}

async fn delete_system_aux_for_principal(kv: &Arc<dyn KvStore>, index: u32) {
    let mutations = SYSTEM_AUX_PREFIXES
        .iter()
        .copied()
        .map(|prefix| KvBatchMutation::Delete {
            key: KvEntryKey::new(SYSTEM_AUX_NAMESPACE, system_aux_key(prefix, index)).unwrap(),
        })
        .collect::<Vec<_>>();
    let started = Instant::now();
    let batch = KvMutationBatch::new(std::iter::empty::<KvBatchCondition>(), mutations).unwrap();
    assert!(kv.apply_batch(&batch).await.expect("aux delete").applied);
    eprintln!(
        "ownership_amplification_probe aux_delete index={index} elapsed_ms={}",
        started.elapsed().as_millis()
    );
}

async fn assert_system_aux_presence(kv: &Arc<dyn KvStore>, present: &[u32], absent: &[u32]) {
    for index in present {
        for prefix in SYSTEM_AUX_PREFIXES {
            let key = system_aux_key(prefix, *index);
            assert!(
                kv.get(SYSTEM_AUX_NAMESPACE, &key).await.unwrap().is_some(),
                "expected preserved system aux {key}"
            );
        }
    }
    for index in absent {
        for prefix in SYSTEM_AUX_PREFIXES {
            let key = system_aux_key(prefix, *index);
            assert!(
                kv.get(SYSTEM_AUX_NAMESPACE, &key).await.unwrap().is_none(),
                "expected deleted system aux {key}"
            );
        }
    }
}

struct ScaleFixture {
    _directory: tempfile::TempDir,
    home: AstridHome,
    principals: PrincipalDirectory,
    operator_uid: PrincipalUid,
    initialized_wire: Vec<u8>,
    initialized_wire_len: u64,
}

async fn prepare_scale_fixture(with_system_aux: bool) -> ScaleFixture {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let owner_identity = user(1);
    let fleet_identity = FleetIdentity::from_genesis(FleetGenesis::from_parts(
        Uuid::from_u128(2),
        Utc.timestamp_opt(1_700_000_001, 0).unwrap(),
        owner_identity.uid,
    ))
    .unwrap();
    let operator_uid = principal_uid(0);
    let principals = PrincipalDirectory::default();
    principals
        .register(PrincipalId::default(), operator_uid)
        .unwrap();
    for index in 1..=FLEET_SCALE_PRINCIPALS {
        principals
            .register(principal_alias(index), principal_uid(index))
            .unwrap();
    }
    let seeded = seeded_scale_graph(&owner_identity, &fleet_identity, operator_uid);
    assert_eq!(
        seeded.principal_ownership.len(),
        usize::try_from(FLEET_SCALE_PRINCIPALS)
            .unwrap()
            .strict_add(1)
    );
    let runtime = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &crate::principal_state::StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    let kv = runtime.kv();
    kv.set(
        OWNERSHIP_NAMESPACE,
        GRAPH_KEY,
        serde_json::to_vec(&seeded).unwrap(),
    )
    .await
    .unwrap();
    let bootstrap = OwnershipStore::new(kv.clone(), principals.clone()).unwrap();
    assert_eq!(bootstrap.load().await.unwrap(), seeded);
    bootstrap
        .initialize_local_user_device(
            operator_uid,
            OPERATOR_DEVICE_KEY,
            owner_identity.uid,
            fleet_identity.uid,
        )
        .await
        .expect("initialize local operator device");
    let initialized = bootstrap.load().await.unwrap();
    assert_eq!(
        initialized.user_for_device(operator_uid, &OPERATOR_DEVICE_KEY),
        Some(owner_identity.uid)
    );
    let initialized_wire = graph_wire(&kv).await;
    let initialized_wire_len = u64::try_from(initialized_wire.len()).unwrap();
    assert_eq!(serde_json::to_vec(&initialized).unwrap(), initialized_wire);
    if with_system_aux {
        seed_system_aux_rows(&kv, FLEET_SCALE_PRINCIPALS).await;
    }
    kv.close().await.unwrap();
    drop(bootstrap);
    drop(kv);
    drop(runtime);
    ScaleFixture {
        _directory: directory,
        home,
        principals,
        operator_uid,
        initialized_wire,
        initialized_wire_len,
    }
}

struct DeleteStepReport {
    index: u32,
    reserve: Duration,
    aux_delete: Duration,
    finish: Duration,
    wire_before: usize,
    wire_reserved: usize,
    wire_finished: usize,
    live_volume_delta: u64,
}

async fn run_finished_delete_steps(
    store: &OwnershipStore,
    kv: &Arc<dyn KvStore>,
    home: &AstridHome,
    operator_uid: PrincipalUid,
    delete_system_aux: bool,
) -> Vec<DeleteStepReport> {
    let mut step_reports = Vec::with_capacity(usize::try_from(DELETE_PROBE_COUNT).unwrap());
    for index in 1..=DELETE_PROBE_COUNT {
        let target = principal_uid(index);
        let alias = principal_alias(index);
        let wire_before = graph_wire(kv).await;
        let volume_before = volume_len(home);
        let reserve_started = Instant::now();
        let guard = store
            .guard_principal_deletion_for_device(
                target,
                alias.clone(),
                operator_uid,
                &OPERATOR_DEVICE_KEY,
            )
            .await
            .expect("reserve deletion");
        let reserve = reserve_started.elapsed();
        let reserved = store.load().await.unwrap();
        assert!(reserved.principal_owner(target).is_none());
        assert!(reserved.principal_deletions.contains_key(&target));
        assert_eq!(
            reserved
                .principal_deletions
                .get(&target)
                .and_then(|reservation| reservation.alias.clone()),
            Some(alias)
        );
        let wire_reserved = graph_wire(kv).await;
        let aux_started = Instant::now();
        if delete_system_aux {
            // Storage-only stand-in for identity key removal between reserve/finish.
            delete_system_aux_for_principal(kv, index).await;
        }
        let aux_delete = aux_started.elapsed();
        let finish_started = Instant::now();
        guard.finish().await.expect("finish deletion reservation");
        let finish = finish_started.elapsed();
        let finished = store.load().await.unwrap();
        assert!(!finished.principal_deletions.contains_key(&target));
        assert!(finished.principal_owner(target).is_none());
        let wire_finished = graph_wire(kv).await;
        let volume_finished = volume_len(home);
        let live_volume_delta = volume_finished.saturating_sub(volume_before);
        eprintln!(
            "ownership_amplification_probe step={index} reserve_ms={} aux_delete_ms={} finish_ms={} wire_before={} wire_reserved={} wire_finished={} volume_before={volume_before} volume_finished={volume_finished} live_volume_delta={live_volume_delta}",
            reserve.as_millis(),
            aux_delete.as_millis(),
            finish.as_millis(),
            wire_before.len(),
            wire_reserved.len(),
            wire_finished.len()
        );
        step_reports.push(DeleteStepReport {
            index,
            reserve,
            aux_delete,
            finish,
            wire_before: wire_before.len(),
            wire_reserved: wire_reserved.len(),
            wire_finished: wire_finished.len(),
            live_volume_delta,
        });
    }
    step_reports
}

async fn prove_abort_reservation_durable(
    store: &OwnershipStore,
    kv: &Arc<dyn KvStore>,
    operator_uid: PrincipalUid,
) -> Vec<u8> {
    let abort_target = principal_uid(DELETE_PROBE_COUNT.strict_add(1));
    let abort_alias = principal_alias(DELETE_PROBE_COUNT.strict_add(1));
    let abort_guard = store
        .guard_principal_deletion_for_device(
            abort_target,
            abort_alias.clone(),
            operator_uid,
            &OPERATOR_DEVICE_KEY,
        )
        .await
        .expect("reserve abort target");
    drop(abort_guard);
    let aborted = store.load().await.unwrap();
    assert!(aborted.principal_deletions.contains_key(&abort_target));
    assert_eq!(
        aborted
            .principal_deletions
            .get(&abort_target)
            .and_then(|reservation| reservation.alias.clone()),
        Some(abort_alias)
    );
    graph_wire(kv).await
}

async fn reopen_and_check_graph(
    home: &AstridHome,
    principals: PrincipalDirectory,
    exact_after_abort: Vec<u8>,
    expect_system_aux: bool,
) {
    let reopened = crate::principal_state::open_runtime_principal_store(
        home,
        Arc::new(|_: &crate::principal_state::StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    let kv = reopened.kv();
    assert_eq!(
        kv.get(OWNERSHIP_NAMESPACE, GRAPH_KEY).await.unwrap(),
        Some(exact_after_abort)
    );
    let store = OwnershipStore::new(kv.clone(), principals).unwrap();
    let graph = store.load().await.unwrap();
    let abort_target = principal_uid(DELETE_PROBE_COUNT.strict_add(1));
    assert!(graph.principal_deletions.contains_key(&abort_target));
    for index in 1..=DELETE_PROBE_COUNT {
        let target = principal_uid(index);
        assert!(graph.principal_owner(target).is_none());
        assert!(!graph.principal_deletions.contains_key(&target));
    }
    if expect_system_aux {
        let absent = (1..=DELETE_PROBE_COUNT).collect::<Vec<_>>();
        assert_system_aux_presence(&kv, &[100, 5_000, 9_999], &absent).await;
    }
    kv.close().await.unwrap();
}

async fn measure_deletion_amplification(with_system_aux: bool) {
    let fixture = prepare_scale_fixture(with_system_aux).await;
    let runtime = crate::principal_state::open_runtime_principal_store(
        &fixture.home,
        Arc::new(|_: &crate::principal_state::StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    let kv = runtime.kv();
    let store = OwnershipStore::new(kv.clone(), fixture.principals.clone()).unwrap();
    assert_eq!(graph_wire(&kv).await, fixture.initialized_wire);
    let baseline_volume = volume_len(&fixture.home);
    eprintln!(
        "ownership_amplification_probe mode={} seed principals={FLEET_SCALE_PRINCIPALS} wire_len={} volume_len={baseline_volume}",
        if with_system_aux {
            "mixed_system_kv"
        } else {
            "ownership_only"
        },
        fixture.initialized_wire_len
    );
    let step_reports = run_finished_delete_steps(
        &store,
        &kv,
        &fixture.home,
        fixture.operator_uid,
        with_system_aux,
    )
    .await;
    if with_system_aux {
        assert_system_aux_presence(&kv, &[100, 5_000, 9_999], &[1, 2, 3]).await;
    }
    kv.close().await.unwrap();
    drop(store);
    drop(kv);
    drop(runtime);
    let settled_volume = volume_len(&fixture.home);
    let settled_growth = settled_volume.saturating_sub(baseline_volume);
    let growth_per_finished_delete = settled_growth.strict_div(u64::from(DELETE_PROBE_COUNT));
    eprintln!(
        "ownership_amplification_probe settled mode={} baseline_volume={baseline_volume} settled_volume={settled_volume} settled_growth={settled_growth} growth_per_finished_delete={growth_per_finished_delete} wire_len={} steps={:?}",
        if with_system_aux {
            "mixed_system_kv"
        } else {
            "ownership_only"
        },
        fixture.initialized_wire_len,
        step_reports
            .iter()
            .map(|step| {
                (
                    step.index,
                    step.reserve,
                    step.aux_delete,
                    step.finish,
                    step.wire_before,
                    step.wire_reserved,
                    step.wire_finished,
                    step.live_volume_delta,
                )
            })
            .collect::<Vec<_>>()
    );
    let runtime = crate::principal_state::open_runtime_principal_store(
        &fixture.home,
        Arc::new(|_: &crate::principal_state::StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    let kv = runtime.kv();
    let store = OwnershipStore::new(kv.clone(), fixture.principals.clone()).unwrap();
    let exact_after_abort =
        prove_abort_reservation_durable(&store, &kv, fixture.operator_uid).await;
    kv.close().await.unwrap();
    drop(store);
    drop(kv);
    drop(runtime);
    reopen_and_check_graph(
        &fixture.home,
        fixture.principals.clone(),
        exact_after_abort,
        with_system_aux,
    )
    .await;
    // Settle all three operations before charging their shared asynchronous
    // checkpoint work; no individual step is assumed to own the initial fold.
    assert!(
        growth_per_finished_delete < fixture.initialized_wire_len.strict_mul(3).strict_div(4),
        "ownership deletion amplified settled volume by {growth_per_finished_delete} B/delete against initialized graph wire {} B (mode={}, baseline_volume={baseline_volume}, settled_volume={settled_volume}, settled_growth={settled_growth})",
        fixture.initialized_wire_len,
        if with_system_aux {
            "mixed_system_kv"
        } else {
            "ownership_only"
        }
    );
}

#[tokio::test]
async fn large_ownership_mutation_recovers_exact_graph() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let runtime = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &crate::principal_state::StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    let kv = runtime.kv();
    let mut expected = OwnershipSnapshot::default();
    for index in 1..=2048 {
        let identity = user(index);
        expected.users.insert(identity.uid, identity);
    }
    let original = serde_json::to_vec(&expected).unwrap();
    assert!(original.len() > 256 * 1024);
    kv.set(OWNERSHIP_NAMESPACE, GRAPH_KEY, original)
        .await
        .unwrap();
    let owner = OwnershipStore::new(kv.clone(), PrincipalDirectory::default()).unwrap();
    let added = user(4096);
    owner.create_user(added.clone()).await.unwrap();
    expected.users.insert(added.uid, added);
    assert_eq!(owner.load().await.unwrap(), expected);
    let exact = serde_json::to_vec(&expected).unwrap();
    assert_eq!(
        kv.get(OWNERSHIP_NAMESPACE, GRAPH_KEY).await.unwrap(),
        Some(exact.clone())
    );
    kv.close().await.unwrap();
    drop(owner);
    drop(kv);
    drop(runtime);
    let reopened = crate::principal_state::open_runtime_principal_store(
        &home,
        Arc::new(|_: &crate::principal_state::StateOwner| Ok(None)),
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .kv()
            .get(OWNERSHIP_NAMESPACE, GRAPH_KEY)
            .await
            .unwrap(),
        Some(exact)
    );
    let owner = OwnershipStore::new(reopened.kv(), PrincipalDirectory::default()).unwrap();
    assert_eq!(owner.load().await.unwrap(), expected);
    reopened.kv().close().await.unwrap();
}

#[tokio::test]
async fn three_retirements_from_ten_k_ownership_fixture() {
    measure_deletion_amplification(false).await;
}

/// Mixed System-owner workload: 10k ownership graph plus 30k unrelated inline
/// System KV rows. Between reserve and finish, deletes the three aux keys for
/// that principal as a storage-only stand-in for identity key removal.
#[tokio::test]
async fn three_retirements_from_ten_k_mixed_system_fixture() {
    measure_deletion_amplification(true).await;
}
