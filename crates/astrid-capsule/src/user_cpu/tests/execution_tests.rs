use super::*;
use crate::user_cpu::execution::{ExecutionAllocation, ExecutionDenied};

#[tokio::test]
async fn admission_timeout_does_not_charge_or_reserve_queued_work() {
    let allocation = ExecutionAllocation::new(
        PrincipalId::new("discovery").unwrap(),
        100,
        FuelRateLimiter::default(),
        None,
    );
    let mut occupied = allocation.try_reserve(100).unwrap();
    assert!(matches!(
        allocation
            .reserve_with_timeout(
                NonZeroU64::new(100).unwrap(),
                std::time::Duration::from_millis(20),
            )
            .await,
        Err(ExecutionDenied::TimedOut),
    ));
    occupied.settle(0, std::time::Instant::now());
    assert!(allocation.try_reserve(100).is_ok());
}

#[tokio::test]
async fn provider_fanout_queues_without_dropping_calls_or_exceeding_budget() {
    let principal = PrincipalId::new("discovery").unwrap();
    let allocation = Arc::new(ExecutionAllocation::new(
        principal,
        100,
        FuelRateLimiter::default(),
        None,
    ));
    // The caller is still executing while its providers answer on the bus.
    let mut caller = allocation.try_reserve(25).unwrap();
    let mut calls = tokio::task::JoinSet::new();
    for _ in 0..22 {
        let allocation = Arc::clone(&allocation);
        calls.spawn(async move {
            let mut permit = allocation
                .reserve_with_timeout(
                    NonZeroU64::new(25).unwrap(),
                    std::time::Duration::from_millis(300),
                )
                .await
                .unwrap();
            tokio::task::yield_now().await;
            permit.settle(1, std::time::Instant::now());
        });
    }
    let mut completed = 0;
    while let Some(result) = calls.join_next().await {
        result.unwrap();
        completed += 1;
    }
    assert_eq!(completed, 22);
    // 22 consumed + 25 still reserved; a 54-unit allowance cannot fit.
    assert!(matches!(
        allocation.try_reserve(54),
        Err(ExecutionDenied::Principal)
    ));
    caller.settle(1, std::time::Instant::now());
    assert!(allocation.try_reserve(77).is_ok());
}

#[tokio::test]
async fn waiting_execution_resumes_when_another_principal_settles_user_budget() {
    let accounting = accounting().await;
    let occupied_user = accounting
        .resolve(&PrincipalId::new("user-1-agent-1").unwrap())
        .await
        .unwrap()
        .unwrap();
    let waiting_principal = PrincipalId::new("user-1-agent-2").unwrap();
    let waiting_user = accounting
        .resolve(&waiting_principal)
        .await
        .unwrap()
        .unwrap();
    let allocation = ExecutionAllocation::new(
        waiting_principal,
        100,
        FuelRateLimiter::default(),
        Some(waiting_user),
    );
    let mut occupied = occupied_user.try_reserve(100).unwrap();
    let waiting = allocation.reserve_with_timeout(
        NonZeroU64::new(90).unwrap(),
        std::time::Duration::from_millis(300),
    );
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    occupied.settle(10, std::time::Instant::now());
    let mut resumed = waiting.await.unwrap();
    assert!(matches!(
        allocation.try_reserve(1),
        Err(ExecutionDenied::User)
    ));
    resumed.settle(0, std::time::Instant::now());
}

#[tokio::test]
async fn waiting_execution_resumes_on_settlement_before_window_rollover() {
    let principal = PrincipalId::new("discovery").unwrap();
    let allocation = ExecutionAllocation::new(principal, 100, FuelRateLimiter::default(), None);
    let mut occupied = allocation.try_reserve(100).unwrap();
    let waiting = allocation.reserve_when_available(NonZeroU64::new(90).unwrap());
    tokio::pin!(waiting);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(20), &mut waiting)
            .await
            .is_err()
    );
    occupied.settle(10, std::time::Instant::now());
    let mut resumed = tokio::time::timeout(std::time::Duration::from_millis(300), waiting)
        .await
        .expect("settlement must wake the same pending invocation before window rollover")
        .unwrap();
    assert!(matches!(
        allocation.try_reserve(1),
        Err(ExecutionDenied::Principal)
    ));
    resumed.settle(0, std::time::Instant::now());
    assert!(allocation.try_reserve(90).is_ok());
}

#[tokio::test]
async fn user_denial_returns_the_unspent_principal_reservation() {
    let accounting = accounting().await;
    let principal = PrincipalId::new("user-1-agent-1").unwrap();
    let user = accounting.resolve(&principal).await.unwrap().unwrap();
    let mut occupied = user.try_reserve(100).unwrap();
    let ledger = FuelRateLimiter::default();
    let allocation = ExecutionAllocation::new(principal.clone(), 100, ledger.clone(), Some(user));
    assert!(matches!(
        allocation.try_reserve(50),
        Err(ExecutionDenied::User)
    ));
    let mut recovered = ledger
        .try_reserve(&principal, 100, 100, std::time::Instant::now())
        .unwrap();
    recovered.settle(0, std::time::Instant::now());
    occupied.settle(0, std::time::Instant::now());
    assert!(allocation.try_reserve(100).is_ok());
}

#[tokio::test]
async fn principal_denial_does_not_consume_the_user_budget() {
    let accounting = accounting().await;
    let principal = PrincipalId::new("user-1-agent-1").unwrap();
    let user = accounting.resolve(&principal).await.unwrap().unwrap();
    let allocation = ExecutionAllocation::new(
        principal,
        10,
        FuelRateLimiter::default(),
        Some(user.clone()),
    );
    assert!(matches!(
        allocation.try_reserve(11),
        Err(ExecutionDenied::Principal)
    ));
    assert!(user.try_reserve(100).is_some());
}

#[tokio::test]
async fn unlimited_principal_cannot_bypass_its_user() {
    let accounting = accounting().await;
    let principal = PrincipalId::new("user-1-agent-1").unwrap();
    let user = accounting.resolve(&principal).await.unwrap().unwrap();
    let allocation = ExecutionAllocation::new(principal, 0, FuelRateLimiter::default(), Some(user));
    let mut occupied = allocation.try_reserve(100).unwrap();
    assert!(matches!(
        allocation.try_reserve(1),
        Err(ExecutionDenied::User)
    ));
    occupied.settle(30, std::time::Instant::now());
    assert!(allocation.try_reserve(70).is_ok());
    assert!(matches!(
        allocation.try_reserve(1),
        Err(ExecutionDenied::User)
    ));
}

#[tokio::test]
async fn joint_waiter_cancellation_leaves_neither_budget_reserved() {
    let accounting = accounting().await;
    let principal = PrincipalId::new("user-1-agent-1").unwrap();
    let user = accounting.resolve(&principal).await.unwrap().unwrap();
    let ledger = FuelRateLimiter::default();
    let mut occupied = user.try_reserve(100).unwrap();
    let allocation = ExecutionAllocation::new(principal.clone(), 100, ledger.clone(), Some(user));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            allocation.reserve_when_available(NonZeroU64::new(100).unwrap()),
        )
        .await
        .is_err()
    );
    let mut free = ledger
        .try_reserve(&principal, 100, 100, std::time::Instant::now())
        .unwrap();
    free.settle(0, std::time::Instant::now());
    occupied.settle(0, std::time::Instant::now());
    assert!(allocation.try_reserve(100).is_ok());
}

#[tokio::test]
async fn joint_waiter_resumes_with_state_after_both_windows_replenish() {
    let accounting = accounting().await;
    let principal = PrincipalId::new("user-1-agent-1").unwrap();
    let user = accounting.resolve(&principal).await.unwrap().unwrap();
    let ledger = FuelRateLimiter::default();
    let allocation = ExecutionAllocation::new(principal, 100, ledger, Some(user));
    let mut spent = allocation.try_reserve(100).unwrap();
    spent.settle(100, std::time::Instant::now());

    let mut service_state = vec!["initialized"];
    {
        let resume = async {
            let mut next = allocation
                .reserve_when_available(NonZeroU64::new(100).unwrap())
                .await
                .unwrap();
            service_state.push("resumed");
            next.settle(100, std::time::Instant::now());
        };
        tokio::pin!(resume);
        // Poll the same future again after the observation timeout; recreating it
        // would not prove that suspended service state survives replenishment.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut resume)
                .await
                .is_err()
        );
        tokio::time::timeout(std::time::Duration::from_secs(3), &mut resume)
            .await
            .expect("joint capacity should replenish");
    }
    assert_eq!(service_state, ["initialized", "resumed"]);
    assert!(matches!(
        allocation.try_reserve(1),
        Err(ExecutionDenied::Principal)
    ));
}

#[tokio::test]
async fn impossible_joint_allowance_returns_without_spending_either_budget() {
    let accounting = accounting().await;
    let principal = PrincipalId::new("user-1-agent-1").unwrap();
    let user = accounting.resolve(&principal).await.unwrap().unwrap();
    for principal_limit in [50, 0] {
        let allocation = ExecutionAllocation::new(
            principal.clone(),
            principal_limit,
            FuelRateLimiter::default(),
            Some(user.clone()),
        );
        let requested = if principal_limit == 0 { 101 } else { 51 };
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            allocation.reserve_when_available(NonZeroU64::new(requested).unwrap()),
        )
        .await
        .expect("impossible allowance must not wait");
        assert!(matches!(result, Err(ExecutionDenied::AllowanceTooLarge)));
    }
    assert!(user.try_reserve(100).is_some());
}
