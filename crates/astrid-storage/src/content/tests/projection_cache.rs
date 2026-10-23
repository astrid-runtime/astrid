//! A declined governed cache must not leave a second uncharged header cache.
use super::*;

#[test]
fn disabled_engine_cache_does_not_retain_headers_outside_its_budget() {
    // InMemoryEngine declines projection retention through the default hooks.
    let engine = Arc::new(Engine::new(TestIdentity));
    let store = PrincipalContentStore::from_engine(engine);
    let owner = "alice".to_owned();
    let name = ContentName::new("file").unwrap();
    store.put(&owner, &name, b"original").unwrap();
    let before = store.decode_header_invocations();
    for reads in 1..=3 {
        assert_eq!(
            store.read(&owner, &name).unwrap(),
            Some(b"original".to_vec())
        );
        assert_eq!(store.decode_header_invocations(), before + reads);
    }
    store.put(&owner, &name, b"replacement").unwrap();
    assert_eq!(
        store.read(&owner, &name).unwrap(),
        Some(b"replacement".to_vec())
    );
}
