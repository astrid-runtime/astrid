use super::*;

#[test]
fn membership_promotes_and_releases_the_shared_tree() {
    let mut users = CachedPrincipals::new(1);
    users.insert(1);
    assert!(matches!(users, CachedPrincipals::Inline(Some(1))));
    users.remove(&99);
    assert!(matches!(users, CachedPrincipals::Inline(Some(1))));
    users.insert(2);
    users.insert(2);
    assert!(matches!(&users, CachedPrincipals::Shared(shared) if shared.len() == 2));
    users.remove(&1);
    assert!(matches!(users, CachedPrincipals::Inline(Some(2))));
    users.remove(&2);
    assert!(users.is_empty());
    users.insert(3);
    assert!(matches!(users, CachedPrincipals::Inline(Some(3))));
    assert_eq!(users.into_iter().collect::<Vec<_>>(), vec![3]);
}

#[test]
fn ten_thousand_shared_users_keep_exact_membership_during_retirement() {
    let mut users = CachedPrincipals::new(0);
    for principal in 0..10_000 {
        users.insert(principal);
        users.insert(principal);
    }
    for principal in (0..10_000).step_by(2) {
        users.remove(&principal);
    }
    let CachedPrincipals::Shared(shared) = &users else {
        panic!("shared users remain")
    };
    assert_eq!(
        shared.iter().copied().collect::<Vec<_>>(),
        (1..10_000).step_by(2).collect::<Vec<_>>()
    );
    for principal in (3..10_000).step_by(2) {
        users.remove(&principal);
    }
    assert!(matches!(users, CachedPrincipals::Inline(Some(1))));
    users.remove(&1);
    assert!(users.is_empty());
    assert_eq!(users.into_iter().count(), 0);
}
