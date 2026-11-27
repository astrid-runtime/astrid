use super::*;
use std::io;

fn alias(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

fn uid(byte: u8) -> PrincipalUid {
    format!("{byte:02x}").repeat(32).parse().unwrap()
}

#[test]
fn owned_publication_runs_under_the_binding_or_returns_its_candidate() {
    let directory = PrincipalDirectory::default();
    let original = alias("original");
    let renamed = alias("renamed");
    let owner = uid(1);
    directory.register(original.clone(), owner).unwrap();
    let candidate = Box::new(37);
    let candidate = directory
        .with_bound_input(&original, owner, candidate, |candidate| {
            assert!(directory.inner.try_write().is_none());
            candidate
        })
        .unwrap();
    directory.rename(owner, &original, renamed.clone()).unwrap();
    directory.register(original.clone(), uid(2)).unwrap();
    let candidate = directory
        .with_bound_input(&original, owner, candidate, |_| {
            panic!("cannot publish an old owner's candidate into a reused alias")
        })
        .unwrap_err();
    directory.inner.write().principals.remove(&owner);
    let candidate = directory
        .with_bound_input(&renamed, owner, candidate, |_| {
            panic!("cannot publish through a one-way binding")
        })
        .unwrap_err();
    assert_eq!(*candidate, 37);
}

#[test]
fn live_binding_holds_read_authority_through_the_callback() {
    let directory = PrincipalDirectory::default();
    let owner = alias("alice");
    let id = uid(1);
    directory.register(owner.clone(), id).unwrap();
    let result = directory
        .with_live_uid_binding(id, |current| {
            assert_eq!(current, &owner);
            // This checks the actual lock, without a scheduler-dependent sleep.
            assert!(directory.inner.try_write().is_none());
            Ok(42)
        })
        .unwrap();
    assert_eq!(result, Some(42));
    assert!(directory.inner.try_write().is_some());
    directory.unregister(&owner, id);
    assert!(!directory.contains_uid(id));
}

#[test]
fn renamed_uid_keeps_its_identity_when_the_old_alias_is_reused() {
    let directory = PrincipalDirectory::default();
    let alice = alias("alice");
    let bob = alias("bob");
    let old = uid(1);
    let new = uid(2);
    directory.register(alice.clone(), old).unwrap();
    directory.rename(old, &alice, bob.clone()).unwrap();
    directory.register(alice.clone(), new).unwrap();
    assert_eq!(
        directory
            .with_live_uid_binding(old, |current| Ok(current.clone()))
            .unwrap(),
        Some(bob)
    );
    assert_eq!(
        directory
            .with_live_uid_binding(new, |current| Ok(current.clone()))
            .unwrap(),
        Some(alice.clone())
    );
    directory.unregister(&alice, new);
    assert_eq!(
        directory
            .with_live_uid_binding::<()>(new, |_| panic!("deleted UID must never enter native IO"))
            .unwrap(),
        None
    );
}

#[test]
fn absent_or_inconsistent_uid_never_calls_native_operation() {
    let directory = PrincipalDirectory::default();
    let id = uid(1);
    assert_eq!(
        directory
            .with_live_uid_binding::<()>(id, |_| panic!("missing UID"))
            .unwrap(),
        None
    );
    directory.register(alias("alice"), id).unwrap();
    directory.inner.write().aliases.clear();
    assert_eq!(
        directory
            .with_live_uid_binding::<()>(id, |_| panic!("one-way mapping"))
            .unwrap(),
        None
    );
}

#[test]
fn native_error_preserves_context_and_releases_binding() {
    let directory = PrincipalDirectory::default();
    directory.register(alias("alice"), uid(1)).unwrap();
    let error = directory
        .with_live_uid_binding::<()>(uid(1), |_| {
            assert!(directory.inner.try_write().is_none());
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected native failure",
            ))
        })
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "injected native failure");
    assert!(directory.inner.try_write().is_some());
}

#[test]
fn unwinding_native_callback_releases_binding_without_poisoning() {
    let directory = PrincipalDirectory::default();
    directory.register(alias("alice"), uid(1)).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ =
            directory.with_live_uid_binding::<()>(uid(1), |_| panic!("injected callback unwind"));
    }));
    assert!(result.is_err());
    assert!(directory.inner.try_write().is_some());
    directory.unregister(&alias("alice"), uid(1));
    assert!(!directory.contains_uid(uid(1)));
}

#[test]
fn batch_membership_checks_every_uid_with_one_live_read_guard() {
    let directory = PrincipalDirectory::default();
    directory.register(alias("alice"), uid(1)).unwrap();
    directory.register(alias("bob"), uid(2)).unwrap();
    assert_eq!(directory.first_missing_uid([]), None);
    assert_eq!(directory.first_missing_uid([uid(1), uid(2)]), None);
    assert_eq!(directory.first_missing_uid([uid(3), uid(1)]), Some(uid(3)));
    let yielded = std::cell::Cell::new(0);
    let identities = [uid(1), uid(2), uid(3)].into_iter().inspect(|_| {
        // The first item is pulled before locking, to skip empty batches.
        // Remaining items must see the same held guard, not separate lookups.
        if yielded.get() != 0 {
            assert!(directory.inner.try_write().is_none());
        }
        yielded.set(yielded.get() + 1);
    });
    assert_eq!(directory.first_missing_uid(identities), Some(uid(3)));
    assert_eq!(yielded.get(), 3);
    assert!(directory.inner.try_write().is_some());
    directory.replace_all([(alias("third"), uid(3))]).unwrap();
    assert_eq!(directory.first_missing_uid([uid(1), uid(3)]), Some(uid(1)));
}

#[test]
fn batch_membership_yields_to_pending_writers_before_completing() {
    use std::sync::{
        Arc, Barrier,
        atomic::{AtomicBool, Ordering},
        mpsc,
    };
    let directory = PrincipalDirectory::default();
    directory.register(alias("alice"), uid(1)).unwrap();
    let scanning = Arc::new(Barrier::new(2));
    let stop = Arc::new(AtomicBool::new(false));
    let reader_directory = directory.clone();
    let reader_scanning = scanning.clone();
    let reader_stop = stop.clone();
    let reader = std::thread::spawn(move || {
        let mut signaled = false;
        let rest = std::iter::repeat(uid(1))
            .take_while(|_| !reader_stop.load(Ordering::Acquire))
            .inspect(|_| {
                if !signaled {
                    signaled = true;
                    reader_scanning.wait();
                }
            });
        reader_directory.first_missing_uid(std::iter::once(uid(1)).chain(rest))
    });
    scanning.wait(); // The reader holds its guard and has not completed its batch.
    let (sent, received) = mpsc::channel();
    let writer = std::thread::spawn(move || {
        directory
            .rename(uid(1), &alias("alice"), alias("bob"))
            .unwrap();
        sent.send(()).unwrap();
    });
    let progressed = received.recv_timeout(std::time::Duration::from_secs(2));
    // Always release the synthetic reader and join both threads, including on
    // the old non-yielding implementation's failure path.
    stop.store(true, Ordering::Release);
    assert_eq!(reader.join().unwrap(), None);
    writer.join().unwrap();
    progressed.expect("a pending writer must progress before the batch finishes");
}

#[test]
fn recovery_observes_one_directory_across_reservations() {
    let directory = PrincipalDirectory::default();
    let first = uid(1);
    let second = uid(2);
    directory.register(alias("first"), first).unwrap();
    directory.register(alias("second"), second).unwrap();
    let mut stored = serde_json::to_value(crate::OwnershipSnapshot::default()).unwrap();
    stored["principal_deletions"] =
        serde_json::json!({ first.to_string(): {}, second.to_string(): {} });
    let ownership = serde_json::from_value(stored).unwrap();

    let mut targets = directory.pending_retirement_aliases(&ownership);
    assert_eq!(targets.next(), Some(alias("first")));
    assert!(directory.inner.try_write().is_none());
    assert_eq!(targets.next(), Some(alias("second")));
    assert_eq!(targets.next(), None);
    drop(targets);
    assert!(directory.inner.try_write().is_some());
}
