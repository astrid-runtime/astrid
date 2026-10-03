use super::*;
use crate::user_cpu::execution::{ExecutionAllocation, ExecutionDenied};

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
