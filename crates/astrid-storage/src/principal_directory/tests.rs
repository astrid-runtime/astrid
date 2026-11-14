use super::*;
use std::io;

fn alias(name: &str) -> PrincipalId {
    PrincipalId::new(name).unwrap()
}

fn uid(byte: u8) -> PrincipalUid {
    format!("{byte:02x}").repeat(32).parse().unwrap()
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
