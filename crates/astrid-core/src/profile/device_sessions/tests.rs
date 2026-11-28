use super::*;

#[tokio::test]
async fn retire_waits_for_every_matching_session_and_fences_earlier_challenges() {
    let sessions = DeviceSessions::default();
    let alice = PrincipalId::new("alice").unwrap();
    let bob = PrincipalId::new("bob").unwrap();
    let key = DeviceKeyId::new("a".repeat(16)).unwrap();
    let other = DeviceKeyId::new("b".repeat(16)).unwrap();
    let pending = sessions.challenge(alice.clone()).unwrap();
    let pending_sibling = sessions.challenge(alice.clone()).unwrap();
    let mut a = sessions
        .challenge(alice.clone())
        .unwrap()
        .bind(key.clone())
        .unwrap();
    let mut b = sessions
        .challenge(alice.clone())
        .unwrap()
        .bind(key.clone())
        .unwrap();
    let foreign = sessions.challenge(bob).unwrap().bind(key.clone()).unwrap();
    let sibling = sessions
        .challenge(alice.clone())
        .unwrap()
        .bind(other.clone())
        .unwrap();
    {
        let mut retiring = std::pin::pin!(sessions.retire(&alice, &key));
        tokio::select! {
            biased;
            _ = &mut retiring => panic!("retired before the first session stopped"),
            () = a.retired() => {}
        }
        // Retirement is terminal even after an observer consumes the notification.
        a.retired().await;
        drop(a);
        tokio::select! {
            biased;
            _ = &mut retiring => panic!("retired before the second session stopped"),
            () = b.retired() => {}
        }
        drop(b);
        retiring.await.unwrap();
    }
    assert!(matches!(
        pending.bind(key.clone()),
        Err(DeviceSessionError::Retired)
    ));
    assert!(pending_sibling.bind(other).is_ok());
    assert!(!foreign.0.has_changed().unwrap());
    assert!(!sibling.0.has_changed().unwrap());
    // A new challenge may authenticate the same key after an authorized re-pair.
    assert!(sessions.challenge(alice).unwrap().bind(key).is_ok());
}
