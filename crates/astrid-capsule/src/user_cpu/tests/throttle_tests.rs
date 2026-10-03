use super::*;
use std::time::Duration;

#[tokio::test]
async fn exempt_principals_share_persistent_user_debt_without_blocking_other_users() {
    let accounting = accounting().await;
    let first = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-1").unwrap(), 0)
        .await
        .unwrap();
    let second = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-2").unwrap(), 0)
        .await
        .unwrap();
    let other = accounting
        .execution_throttle(&PrincipalId::new("user-2-agent-1").unwrap(), 0)
        .await
        .unwrap();
    first.charge(180);
    assert!(!second.delay().is_zero());
    assert!(other.delay().is_zero());
    assert!(
        tokio::time::timeout(Duration::from_millis(20), second.wait())
            .await
            .is_err()
    );
    // Dropping the original execution handle cannot cancel that user's debt.
    drop(first);
    assert!(!second.delay().is_zero());
    tokio::time::timeout(Duration::from_secs(2), second.wait())
        .await
        .unwrap();
    assert!(second.delay().is_zero());
}

#[tokio::test]
async fn principal_debt_remains_when_user_has_capacity() {
    let accounting = accounting().await;
    let principal = PrincipalId::new("user-1-agent-1").unwrap();
    let first = accounting.execution_throttle(&principal, 10).await.unwrap();
    let same = accounting.execution_throttle(&principal, 10).await.unwrap();
    let peer = accounting
        .execution_throttle(&PrincipalId::new("user-1-agent-2").unwrap(), 10)
        .await
        .unwrap();
    first.charge(20);
    assert!(!same.delay().is_zero());
    assert!(peer.delay().is_zero());
}
