use super::*;

#[test]
fn transient_busy_retries_until_success() {
    let mut calls = 0;
    unmount_with(
        || {
            calls += 1;
            if calls < 3 {
                Err(io::ErrorKind::ResourceBusy.into())
            } else {
                Ok(())
            }
        },
        Instant::now() + Duration::from_secs(1),
        Duration::from_millis(1),
    )
    .expect("transient busy must recover");
    assert_eq!(calls, 3);
}

#[test]
fn non_busy_errors_are_not_retried() {
    for kind in [io::ErrorKind::PermissionDenied, io::ErrorKind::NotFound] {
        let mut calls = 0;
        let error = unmount_with(
            || {
                calls += 1;
                Err(kind.into())
            },
            Instant::now() + Duration::from_secs(1),
            Duration::from_millis(1),
        )
        .expect_err("non-busy error must remain a failure");
        assert_eq!(calls, 1);
        assert_eq!(error.kind(), kind);
    }
}

#[test]
fn expired_budget_preserves_busy_without_retry() {
    let mut calls = 0;
    let error = unmount_with(
        || {
            calls += 1;
            Err(io::ErrorKind::ResourceBusy.into())
        },
        Instant::now(),
        Duration::from_millis(50),
    )
    .expect_err("occupied mount must remain busy");
    assert_eq!(calls, 1);
    assert_eq!(error.kind(), io::ErrorKind::ResourceBusy);
}

#[test]
fn permanent_busy_does_not_retry_after_deadline() {
    let mut calls = 0;
    let error = unmount_with(
        || {
            calls += 1;
            Err(io::ErrorKind::ResourceBusy.into())
        },
        Instant::now() + Duration::from_millis(5),
        Duration::from_secs(1),
    )
    .expect_err("busy past deadline must fail");
    assert_eq!(calls, 1);
    assert_eq!(error.kind(), io::ErrorKind::ResourceBusy);
}
