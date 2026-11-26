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
        .bind(key.clone(), None)
        .unwrap();
    let mut b = sessions
        .challenge(alice.clone())
        .unwrap()
        .bind(key.clone(), None)
        .unwrap();
    let foreign = sessions
        .challenge(bob)
        .unwrap()
        .bind(key.clone(), None)
        .unwrap();
    let sibling = sessions
        .challenge(alice.clone())
        .unwrap()
        .bind(other.clone(), None)
        .unwrap();
    {
        let mut retiring = std::pin::pin!(sessions.retire_with_receipt(&alice, &key));
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
        let receipt = retiring.await.unwrap();
        assert_eq!(receipt.principal(), alice.as_str());
        assert_eq!(receipt.key_id(), key.as_str());
    }
    assert!(matches!(
        pending.bind(key.clone(), None),
        Err(DeviceSessionError::Retired)
    ));
    assert!(pending_sibling.bind(other, None).is_ok());
    assert!(!foreign.signal.has_changed().unwrap());
    assert!(!sibling.signal.has_changed().unwrap());
    // A new challenge may authenticate the same key after an authorized re-pair.
    assert!(sessions.challenge(alice).unwrap().bind(key, None).is_ok());
}

struct ObservedWork {
    channel: watch::Sender<bool>,
    first_poll: Option<tokio::sync::oneshot::Sender<()>>,
    dropped: Option<tokio::sync::oneshot::Sender<bool>>,
    ready: bool,
}

impl Future for ObservedWork {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if let Some(first_poll) = self.first_poll.take() {
            let _ = first_poll.send(());
        }
        if self.ready {
            std::task::Poll::Ready(())
        } else {
            std::task::Poll::Pending
        }
    }
}

impl Drop for ObservedWork {
    fn drop(&mut self) {
        if let Some(dropped) = self.dropped.take() {
            let _ = dropped.send(self.channel.is_closed());
        }
    }
}

#[tokio::test]
async fn serving_work_drops_before_session_closure_on_every_exit() {
    enum Exit {
        BeforePoll,
        Completed,
        Aborted,
        Retired,
    }
    for exit in [
        Exit::BeforePoll,
        Exit::Completed,
        Exit::Aborted,
        Exit::Retired,
    ] {
        let registry = DeviceSessions::default();
        let owner = PrincipalId::new("alice").unwrap();
        let key = DeviceKeyId::new("a".repeat(16)).unwrap();
        let challenge = registry.challenge(owner.clone()).unwrap();
        let channel = challenge.signal.clone();
        let session = challenge.bind(key.clone(), None).unwrap();
        let (first_poll, started) = tokio::sync::oneshot::channel();
        let (drop_tx, dropped) = tokio::sync::oneshot::channel();
        let work = ObservedWork {
            channel: channel.clone(),
            first_poll: Some(first_poll),
            dropped: Some(drop_tx),
            ready: matches!(exit, Exit::Completed),
        };
        let serving = session.serve(move || work);
        if matches!(exit, Exit::BeforePoll) {
            drop(serving);
        } else {
            let task = tokio::spawn(serving);
            started.await.unwrap();
            match exit {
                Exit::Completed => task.await.unwrap(),
                Exit::Aborted => {
                    task.abort();
                    assert!(task.await.unwrap_err().is_cancelled());
                },
                Exit::Retired => {
                    registry.retire(&owner, &key).await.unwrap();
                    task.await.unwrap();
                },
                Exit::BeforePoll => unreachable!(),
            }
        }
        assert!(
            !dropped.await.unwrap(),
            "session closed before serving work dropped"
        );
        assert!(channel.is_closed());
    }
}
