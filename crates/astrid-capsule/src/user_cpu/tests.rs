use super::*;
use astrid_core::{
    FleetGenesis, FleetIdentity, PrincipalOwnership, PrincipalUid, UserGenesis, UserIdentity,
};

mod execution_tests;
mod prepaid_guest_tests;
mod throttle_tests;
mod wasm_throttle_tests;

async fn accounting() -> UserCpuAccounting {
    let directory = PrincipalDirectory::default();
    let storage = Arc::new(
        OwnershipStore::new(
            Arc::new(astrid_storage::MemoryKvStore::new()),
            directory.clone(),
        )
        .unwrap(),
    );
    for index in [1_u8, 2] {
        let user = UserIdentity::from_genesis(UserGenesis::from_parts(
            uuid::Uuid::from_u128(u128::from(index)),
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            [index; 32],
        ))
        .unwrap();
        storage.create_user(user.clone()).await.unwrap();
        let fleet = FleetIdentity::from_genesis(FleetGenesis::from_parts(
            uuid::Uuid::from_u128(u128::from(index)),
            chrono::DateTime::from_timestamp(1_700_000_001, 0).unwrap(),
            user.uid,
        ))
        .unwrap();
        storage.create_fleet(fleet.clone()).await.unwrap();
        for child in [1_u8, 2, 3] {
            let principal = PrincipalId::new(format!("user-{index}-agent-{child}")).unwrap();
            let uid = PrincipalUid::from_bytes([index * 10 + child; 32]);
            directory.register(principal, uid).unwrap();
            storage
                .assign_principal(PrincipalOwnership {
                    principal_uid: uid,
                    fleet_uid: fleet.uid,
                    assigned_by: user.uid,
                })
                .await
                .unwrap();
        }
    }
    UserCpuAccounting::new(storage, directory, NonZeroU64::new(100), BTreeMap::new())
}

#[tokio::test]
async fn three_principals_share_one_ceiling_and_other_user_is_independent() {
    let accounting = accounting().await;
    let mut allocations = Vec::new();
    for alias in [
        "user-1-agent-1",
        "user-1-agent-2",
        "user-1-agent-3",
        "user-2-agent-1",
    ] {
        allocations.push(
            accounting
                .resolve(&PrincipalId::new(alias).unwrap())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    let mut first = allocations[0].try_reserve(60).unwrap();
    let second = allocations[1].try_reserve(40).unwrap();
    assert!(allocations[2].try_reserve(1).is_none());
    let independent = allocations[3].try_reserve(100).unwrap();
    first.settle(20, std::time::Instant::now());
    assert!(allocations[2].try_reserve(41).is_none());
    let third = allocations[2].try_reserve(40).unwrap();
    drop((second, third, independent));
    assert!(
        allocations[0].try_reserve(1).is_none(),
        "cancellation cannot refund executed work"
    );
}

#[tokio::test]
async fn unknown_attribution_is_denied_only_when_limits_are_configured() {
    let mut accounting = accounting().await;
    let unknown = PrincipalId::new("legacy").unwrap();
    let uid = PrincipalUid::from_bytes([99; 32]);
    accounting.directory.register(unknown.clone(), uid).unwrap();
    assert!(accounting.resolve(&unknown).await.is_err());
    accounting.default_limit = None;
    assert!(accounting.resolve(&unknown).await.unwrap().is_none());
}

#[tokio::test]
async fn simultaneous_principals_cannot_multiply_user_allocation() {
    let accounting = accounting().await;
    let allocation = accounting
        .resolve(&PrincipalId::new("user-1-agent-1").unwrap())
        .await
        .unwrap()
        .unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let allocation = allocation.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                allocation.try_reserve(100)
            })
        })
        .collect();
    let reservations: Vec<_> = handles
        .into_iter()
        .filter_map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(reservations.len(), 1);
}

#[tokio::test]
async fn exhausted_user_waits_and_resumes_without_blocking_another_user() {
    let accounting = accounting().await;
    let allocation = accounting
        .resolve(&PrincipalId::new("user-1-agent-1").unwrap())
        .await
        .unwrap()
        .unwrap();
    let sibling = accounting
        .resolve(&PrincipalId::new("user-1-agent-2").unwrap())
        .await
        .unwrap()
        .unwrap();
    let other = accounting
        .resolve(&PrincipalId::new("user-2-agent-1").unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut spent = allocation.try_reserve(100).unwrap();
    spent.settle(100, std::time::Instant::now());

    // The actual task-local state survives the pending allowance, unlike a
    // trap/restart scheme. This tests admission only, not WASM scheduling.
    let mut wait = std::pin::pin!(async {
        let state = String::from("service state");
        let reservation = sibling
            .reserve_when_available(NonZeroU64::new(100).unwrap())
            .await
            .unwrap();
        (state, reservation)
    });
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut wait)
            .await
            .is_err()
    );
    assert!(
        other.try_reserve(100).is_some(),
        "other users remain runnable"
    );
    let (state, reservation) = tokio::time::timeout(std::time::Duration::from_secs(3), wait)
        .await
        .expect("window replenishes");
    assert_eq!(state, "service state");
    assert!(
        allocation.try_reserve(1).is_none(),
        "sibling uses the same ceiling"
    );
    drop(reservation);
}

#[tokio::test]
async fn impossible_allowance_is_rejected_without_waiting() {
    let accounting = accounting().await;
    let allocation = accounting
        .resolve(&PrincipalId::new("user-1-agent-1").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert!(
        allocation
            .reserve_when_available(NonZeroU64::new(101).unwrap())
            .await
            .is_err()
    );
    assert!(allocation.try_reserve(100).is_some());
}

#[tokio::test]
async fn cancelled_waiter_does_not_reserve_future_capacity() {
    let accounting = accounting().await;
    let allocation = accounting
        .resolve(&PrincipalId::new("user-1-agent-1").unwrap())
        .await
        .unwrap()
        .unwrap();
    let mut occupied = allocation.try_reserve(100).unwrap();
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            allocation.reserve_when_available(NonZeroU64::new(100).unwrap()),
        )
        .await
        .is_err()
    );
    occupied.settle(0, std::time::Instant::now());
    assert!(
        allocation.try_reserve(100).is_some(),
        "cancelled wait acquired nothing"
    );
}
