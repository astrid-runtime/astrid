use std::sync::{Arc, Barrier};

use super::*;

fn authority(limit: u64) -> ResidentMemoryAuthority<String> {
    let authority = ResidentMemoryAuthority::new(limit);
    authority
        .register_principal("alice".to_owned(), None, 100)
        .expect("register alice");
    authority
        .register_principal("bob".to_owned(), None, 100)
        .expect("register bob");
    authority
}

#[test]
fn physical_pool_never_overcommits_and_last_clone_releases() {
    let authority = authority(100);
    let first = authority
        .reserve_physical(
            Some("alice".to_owned()),
            MemorySubsystem::Wasm,
            MemoryClass::NonEvictable,
            70,
        )
        .expect("reserve");
    let clone = first.clone();
    assert_eq!(
        authority
            .reserve_physical(
                Some("bob".to_owned()),
                MemorySubsystem::LinuxRealm,
                MemoryClass::NonEvictable,
                31,
            )
            .expect_err("pool must reject overcommit"),
        MemoryAuthorityError::PhysicalExhausted {
            requested: 31,
            available: 30,
        }
    );
    drop(first);
    assert_eq!(authority.snapshot().physical_reserved_bytes, 70);
    drop(clone);
    assert_eq!(authority.snapshot().physical_reserved_bytes, 0);
}

#[test]
fn shared_physical_bytes_charge_each_principal_in_full() {
    let authority = authority(100);
    let shared = authority
        .reserve_physical(
            None,
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            40,
        )
        .expect("reserve shared cache");
    let alice = authority
        .reserve_logical(
            "alice".to_owned(),
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            40,
        )
        .expect("charge alice");
    let bob = authority
        .reserve_logical(
            "bob".to_owned(),
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            40,
        )
        .expect("charge bob");

    let snapshot = authority.snapshot();
    assert_eq!(snapshot.physical_reserved_bytes, 40);
    assert_eq!(alice.charged_bytes(), 40);
    assert_eq!(bob.charged_bytes(), 40);
    assert_eq!(
        snapshot
            .principals
            .iter()
            .map(|principal| principal.direct_logical_bytes)
            .sum::<u64>(),
        80
    );
    drop((shared, alice, bob));
    assert_eq!(authority.snapshot().physical_reserved_bytes, 0);
}

#[test]
fn descendants_attenuate_from_every_ancestor() {
    let authority = ResidentMemoryAuthority::new(1_000);
    authority
        .register_principal("root".to_owned(), None, 100)
        .expect("root");
    authority
        .register_principal("child".to_owned(), Some("root".to_owned()), 80)
        .expect("child");
    authority
        .register_principal("grandchild".to_owned(), Some("child".to_owned()), 70)
        .expect("grandchild");

    let root = authority
        .reserve_logical(
            "root".to_owned(),
            MemorySubsystem::Wasm,
            MemoryClass::NonEvictable,
            40,
        )
        .expect("root charge");
    let child = authority
        .reserve_logical(
            "child".to_owned(),
            MemorySubsystem::Compiler,
            MemoryClass::NonEvictable,
            50,
        )
        .expect("child charge");
    assert_eq!(
        authority
            .reserve_logical(
                "grandchild".to_owned(),
                MemorySubsystem::Gpu,
                MemoryClass::NonEvictable,
                11,
            )
            .expect_err("ancestor must attenuate the child"),
        MemoryAuthorityError::LogicalExhausted {
            requested: 11,
            available: 10,
        }
    );

    let snapshot = authority.snapshot();
    let root_usage = snapshot
        .principals
        .iter()
        .find(|account| account.principal == "root")
        .expect("root snapshot");
    assert_eq!(root_usage.direct_logical_bytes, 40);
    assert_eq!(root_usage.subtree_logical_bytes, 90);
    drop((root, child));
}

#[test]
fn pressure_requests_reclaim_without_prematurely_releasing_bytes() {
    let authority = authority(100);
    let fixed = authority
        .reserve_physical(
            Some("alice".to_owned()),
            MemorySubsystem::Wasm,
            MemoryClass::NonEvictable,
            60,
        )
        .expect("fixed");
    let cache = authority
        .reserve_physical(
            None,
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            40,
        )
        .expect("cache");

    assert_eq!(
        authority.set_physical_limit(70),
        MemoryPressure {
            excess_bytes: 30,
            reclaim_requested_bytes: 30,
            unreclaimable_bytes: 0,
        }
    );
    assert_eq!(cache.requested_bytes(), 10);
    assert_eq!(authority.snapshot().physical_reserved_bytes, 100);
    assert_eq!(
        authority
            .reserve_physical(None, MemorySubsystem::Filesystem, MemoryClass::Evictable, 1,)
            .expect_err("unacknowledged reclaim must not free capacity"),
        MemoryAuthorityError::PhysicalExhausted {
            requested: 1,
            available: 0,
        }
    );
    cache.acknowledge_reclaim(10).expect("ack reclaim");
    assert_eq!(authority.snapshot().physical_reserved_bytes, 70);
    drop((fixed, cache));
}

#[test]
fn mixed_consumers_reconcile_and_principal_removal_waits_for_release() {
    let authority = ResidentMemoryAuthority::new(500);
    authority
        .register_principal("alice".to_owned(), None, 300)
        .expect("alice");
    authority
        .register_principal("worker".to_owned(), Some("alice".to_owned()), 100)
        .expect("worker");

    let wasm = authority
        .reserve(
            "alice".to_owned(),
            MemorySubsystem::Wasm,
            MemoryClass::NonEvictable,
            80,
            80,
        )
        .expect("wasm");
    let realm = authority
        .reserve(
            "worker".to_owned(),
            MemorySubsystem::LinuxRealm,
            MemoryClass::NonEvictable,
            120,
            90,
        )
        .expect("realm");
    let cache = authority
        .reserve_physical(
            None,
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            50,
        )
        .expect("cache");
    let cache_charge = authority
        .reserve_logical(
            "alice".to_owned(),
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            50,
        )
        .expect("cache charge");
    let compiler = authority
        .reserve(
            "worker".to_owned(),
            MemorySubsystem::Compiler,
            MemoryClass::Evictable,
            30,
            10,
        )
        .expect("compiler");
    let gpu = authority
        .reserve(
            "alice".to_owned(),
            MemorySubsystem::Gpu,
            MemoryClass::Evictable,
            40,
            40,
        )
        .expect("gpu");

    let snapshot = authority.snapshot();
    assert_eq!(snapshot.physical_reserved_bytes, 320);
    let alice = snapshot
        .principals
        .iter()
        .find(|account| account.principal == "alice")
        .expect("alice snapshot");
    assert_eq!(alice.subtree_logical_bytes, 270);
    assert_eq!(
        authority.remove_principal(&"worker".to_owned()),
        Err(MemoryAuthorityError::PrincipalInUse)
    );

    drop((realm, compiler));
    authority
        .remove_principal(&"worker".to_owned())
        .expect("remove released child");
    drop((wasm, cache, cache_charge, gpu));
}

#[test]
fn concurrent_physical_admission_cannot_cross_the_pool() {
    let authority = Arc::new(authority(100));
    let barrier = Arc::new(Barrier::new(32));
    let mut workers = Vec::new();
    for _ in 0..32 {
        let authority = Arc::clone(&authority);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            authority.reserve_physical(
                None,
                MemorySubsystem::Extension("race"),
                MemoryClass::NonEvictable,
                10,
            )
        }));
    }
    let leases: Vec<_> = workers
        .into_iter()
        .filter_map(|worker| worker.join().expect("worker").ok())
        .collect();
    assert_eq!(leases.len(), 10);
    assert_eq!(authority.snapshot().physical_reserved_bytes, 100);
    drop(leases);
    assert_eq!(authority.snapshot().physical_reserved_bytes, 0);
}

#[test]
fn combined_admission_rolls_back_before_observing_failure() {
    let authority = authority(100);
    authority
        .set_principal_limit(&"alice".to_owned(), 10)
        .expect("lower alice limit");

    assert_eq!(
        authority
            .reserve(
                "alice".to_owned(),
                MemorySubsystem::Wasm,
                MemoryClass::NonEvictable,
                80,
                11,
            )
            .expect_err("logical admission must reject the combined lease"),
        MemoryAuthorityError::LogicalExhausted {
            requested: 11,
            available: 10,
        }
    );
    let snapshot = authority.snapshot();
    assert_eq!(snapshot.physical_reserved_bytes, 0);
    assert!(snapshot.physical_leases.is_empty());
    assert!(snapshot.logical_leases.is_empty());
}

#[test]
fn physical_resize_and_release_refresh_reclaim_targets() {
    let authority = authority(100);
    let fixed = authority
        .reserve_physical(
            Some("alice".to_owned()),
            MemorySubsystem::Wasm,
            MemoryClass::NonEvictable,
            60,
        )
        .expect("fixed");
    let cache = authority
        .reserve_physical(
            None,
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            40,
        )
        .expect("cache");
    assert_eq!(
        authority.set_physical_limit(70),
        MemoryPressure {
            excess_bytes: 30,
            reclaim_requested_bytes: 30,
            unreclaimable_bytes: 0,
        }
    );
    assert_eq!(cache.requested_bytes(), 10);

    drop(fixed);
    assert_eq!(authority.snapshot().physical_reserved_bytes, 40);
    assert_eq!(cache.requested_bytes(), 40);
    cache.resize(60).expect("grow under the live pool");
    assert_eq!(cache.reserved_bytes(), 60);
    assert_eq!(cache.requested_bytes(), 60);
    cache.resize(20).expect("shrink");
    assert_eq!(authority.snapshot().physical_reserved_bytes, 20);
}

#[test]
fn logical_limit_reduction_reclaims_evictable_descendants_first() {
    let authority = ResidentMemoryAuthority::new(1_000);
    authority
        .register_principal("root".to_owned(), None, 100)
        .expect("root");
    authority
        .register_principal("child".to_owned(), Some("root".to_owned()), 80)
        .expect("child");
    let fixed = authority
        .reserve_logical(
            "root".to_owned(),
            MemorySubsystem::Wasm,
            MemoryClass::NonEvictable,
            40,
        )
        .expect("fixed");
    let cache = authority
        .reserve_logical(
            "child".to_owned(),
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            50,
        )
        .expect("cache");

    assert_eq!(
        authority
            .set_principal_limit(&"root".to_owned(), 30)
            .expect("lower root limit"),
        MemoryPressure {
            excess_bytes: 60,
            reclaim_requested_bytes: 50,
            unreclaimable_bytes: 10,
        }
    );
    assert_eq!(cache.requested_bytes(), 0);
    assert_eq!(fixed.requested_bytes(), 40);
    let root = authority
        .snapshot()
        .principals
        .into_iter()
        .find(|account| account.principal == "root")
        .expect("root snapshot");
    assert_eq!(root.subtree_logical_bytes, 90);
    assert_eq!(root.requested_subtree_logical_bytes, 40);

    cache.acknowledge_reclaim(0).expect("ack reclaim");
    assert_eq!(
        authority
            .reserve_logical(
                "child".to_owned(),
                MemorySubsystem::Compiler,
                MemoryClass::Evictable,
                1,
            )
            .expect_err("over-limit ancestor must reject new growth"),
        MemoryAuthorityError::LogicalExhausted {
            requested: 1,
            available: 0,
        }
    );
    drop((fixed, cache));
}

#[test]
fn raising_a_logical_limit_clears_obsolete_reclaim() {
    let authority = authority(100);
    let cache = authority
        .reserve_logical(
            "alice".to_owned(),
            MemorySubsystem::StorageCache,
            MemoryClass::Evictable,
            80,
        )
        .expect("cache");
    authority
        .set_principal_limit(&"alice".to_owned(), 20)
        .expect("lower");
    assert_eq!(cache.requested_bytes(), 20);
    authority
        .set_principal_limit(&"alice".to_owned(), 100)
        .expect("raise");
    assert_eq!(cache.requested_bytes(), 80);
}

#[test]
fn authority_teardown_invalidates_outliving_handles_without_panicking() {
    let lease = {
        let authority = authority(100);
        authority
            .reserve_physical(
                None,
                MemorySubsystem::StorageCache,
                MemoryClass::Evictable,
                50,
            )
            .expect("lease")
    };
    assert_eq!(
        lease
            .resize(40)
            .expect_err("authority has already been released"),
        MemoryAuthorityError::LeaseReleased
    );
}

#[test]
fn concurrent_logical_admission_cannot_cross_principal_authority() {
    let authority = Arc::new(authority(1_000));
    let barrier = Arc::new(Barrier::new(32));
    let mut workers = Vec::new();
    for _ in 0..32 {
        let authority = Arc::clone(&authority);
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            authority.reserve_logical(
                "alice".to_owned(),
                MemorySubsystem::Compiler,
                MemoryClass::Evictable,
                10,
            )
        }));
    }
    let leases = workers
        .into_iter()
        .filter_map(|worker| worker.join().expect("worker").ok())
        .collect::<Vec<_>>();
    assert_eq!(leases.len(), 10);
    let alice = authority
        .snapshot()
        .principals
        .into_iter()
        .find(|account| account.principal == "alice")
        .expect("alice snapshot");
    assert_eq!(alice.subtree_logical_bytes, 100);
}

#[test]
fn zero_sized_live_leases_still_block_principal_removal_and_reparenting() {
    let authority = ResidentMemoryAuthority::new(100);
    authority
        .register_principal("root-a".to_owned(), None, 100)
        .expect("root a");
    authority
        .register_principal("root-b".to_owned(), None, 100)
        .expect("root b");
    authority
        .register_principal("child".to_owned(), Some("root-a".to_owned()), 100)
        .expect("child");
    let physical = authority
        .reserve_physical(
            Some("child".to_owned()),
            MemorySubsystem::Filesystem,
            MemoryClass::Evictable,
            10,
        )
        .expect("physical");
    let logical = authority
        .reserve_logical(
            "child".to_owned(),
            MemorySubsystem::Filesystem,
            MemoryClass::Evictable,
            10,
        )
        .expect("logical");
    physical.resize(0).expect("reclaim physical");
    logical.resize(0).expect("reclaim logical");

    assert_eq!(
        authority
            .remove_principal(&"child".to_owned())
            .expect_err("live zero-sized leases retain their owner"),
        MemoryAuthorityError::PrincipalInUse
    );
    assert_eq!(
        authority
            .register_principal("child".to_owned(), Some("root-b".to_owned()), 100)
            .expect_err("live zero-sized leases prevent reparenting"),
        MemoryAuthorityError::PrincipalBusy
    );
    drop((physical, logical));
    authority
        .remove_principal(&"child".to_owned())
        .expect("released child");
}
