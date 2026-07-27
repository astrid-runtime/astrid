//! Native Windows private-lock regressions.

use super::*;

#[test]
fn private_lock_contention_is_busy_until_the_owner_releases_it() {
    let root = private_temp();
    let path = root.path().join("system.lock");
    let owner = crate::platform_fs::try_acquire_private_file_lock(&path, "test lock owner")
        .unwrap()
        .expect("first lock acquisition succeeds");

    assert!(
        crate::platform_fs::try_acquire_private_file_lock(&path, "test lock owner")
            .unwrap()
            .is_none(),
        "a second acquisition must report the live owner as contention"
    );

    drop(owner);
    let reacquired = crate::platform_fs::try_acquire_private_file_lock(&path, "test lock owner")
        .unwrap()
        .expect("lock can be reacquired after the owner exits");
    drop(reacquired);
}
