use super::*;

#[test]
fn owner_rename_batch_keeps_only_final_catalog_nodes() {
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    for name in ["alpha", "beta", "gamma"] {
        store
            .put(&owner, &ContentName::new(name).unwrap(), name.as_bytes())
            .unwrap();
    }
    assert!(
        store
            .rename_batch(
                &owner,
                &[(
                    ContentName::new("alpha").unwrap(),
                    ContentName::new("delta").unwrap()
                )]
            )
            .unwrap()
    );
    assert_eq!(
        store
            .read(&owner, &ContentName::new("delta").unwrap())
            .unwrap(),
        Some(b"alpha".to_vec())
    );
    assert_eq!(
        store
            .read(&owner, &ContentName::new("alpha").unwrap())
            .unwrap(),
        None
    );
    for name in ["beta", "gamma"] {
        assert_eq!(
            store
                .read(&owner, &ContentName::new(name).unwrap())
                .unwrap(),
            Some(name.as_bytes().to_vec())
        );
    }
}
