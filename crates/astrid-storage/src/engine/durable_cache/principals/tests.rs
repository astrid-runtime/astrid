use super::*;
use std::sync::Arc;

fn owner(value: u64) -> PrincipalRef<u64> {
    PrincipalRef::new(Arc::new(value))
}

#[test]
fn inline_membership_reuses_holes_and_releases_spill_storage() {
    let owners = (0..5).map(owner).collect::<Vec<_>>();
    let mut members = CachedPrincipals::new(owners[0].clone());
    for owner in &owners[..3] {
        members.insert(owner.clone());
    }
    assert!(matches!(members, CachedPrincipals::Inline(_)));
    members.remove(&owners[1]);
    members.insert(owners[3].clone());
    assert!(matches!(members, CachedPrincipals::Inline(_)));
    members.insert(owners[4].clone());
    assert!(matches!(members, CachedPrincipals::Shared(_)));
    members.remove(&owners[4]);
    assert!(matches!(members, CachedPrincipals::Shared(_)));
    for index in [0, 2, 3] {
        assert!(members.contains(&owners[index]));
    }
    assert!(!members.contains(&owners[1]));
    members.remove(&owners[2]);
    members.remove(&owners[3]);
    assert!(matches!(members, CachedPrincipals::Inline(_)));
    for owner in owners {
        members.remove(&owner);
    }
    assert!(members.is_empty());
    members.insert(owner(9));
    assert_eq!(
        members
            .into_iter()
            .map(|owner| *owner.principal())
            .collect::<Vec<_>>(),
        vec![9]
    );
}

#[test]
fn ten_thousand_principals_keep_exact_membership_during_retirement() {
    let owners = (0..10_000).map(owner).collect::<Vec<_>>();
    let mut members = CachedPrincipals::new(owners[0].clone());
    for owner in &owners {
        members.insert(owner.clone());
        members.insert(owner.clone());
    }
    for owner in owners.iter().step_by(2) {
        members.remove(owner);
    }
    let CachedPrincipals::Shared(shared) = &members else {
        panic!("shared owners remain");
    };
    let mut actual = shared
        .iter()
        .map(|owner| *owner.principal())
        .collect::<Vec<_>>();
    actual.sort_unstable();
    assert_eq!(actual, (1..10_000).step_by(2).collect::<Vec<_>>());
    for owner in owners.iter().skip(3).step_by(2) {
        members.remove(owner);
    }
    assert!(matches!(members, CachedPrincipals::Inline(_)));
    assert!(members.contains(&owners[1]));
    members.remove(&owners[1]);
    assert!(members.is_empty());
}

#[test]
fn membership_header_does_not_duplicate_the_principal_value() {
    use std::mem::size_of;
    assert_eq!(
        size_of::<CachedPrincipals<u8>>(),
        size_of::<CachedPrincipals<[u8; 128]>>()
    );
    assert!(
        size_of::<CachedPrincipals<[u8; 128]>>()
            <= size_of::<BTreeSet<PrincipalRef<[u8; 128]>>>() + size_of::<usize>()
    );
}
