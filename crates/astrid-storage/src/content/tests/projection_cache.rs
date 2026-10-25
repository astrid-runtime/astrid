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

#[test]
fn replacement_discards_obsolete_decoded_head_but_preserves_held_views_and_peers() {
    let engine = Arc::new(CountingEngine::new());
    let store = PrincipalContentStore::from_engine(Arc::clone(&engine));
    let owner = "alice".to_owned();
    let peer = "bob".to_owned();
    let name = ContentName::new("file").unwrap();
    store.put(&owner, &name, b"original").unwrap();
    store.put(&peer, &name, b"peer").unwrap();
    let held = store.open_read(&owner, &name).unwrap().unwrap();
    let old_root = engine.inner.root(&owner).unwrap();
    let peer_root = engine.inner.root(&peer).unwrap();
    let key = engine
        .projection_cache
        .read()
        .keys()
        .find_map(|(principal, object, key)| {
            (principal == &owner && *object == old_root.commit).then_some(*key)
        })
        .unwrap();
    for value in 0..128_u32 {
        store.put(&owner, &name, &value.to_be_bytes()).unwrap();
        let cache = engine.projection_cache.read();
        assert_eq!(
            cache
                .keys()
                .filter(|(principal, _, kind)| principal == &owner && *kind == key)
                .count(),
            1
        );
        assert!(cache.contains_key(&(peer.clone(), peer_root.commit, key)));
    }
    assert_eq!(held.read().unwrap(), b"original");
    assert!(
        !engine
            .projection_cache
            .read()
            .contains_key(&(owner.clone(), old_root.commit, key))
    );
    assert_eq!(store.read(&peer, &name).unwrap(), Some(b"peer".to_vec()));
    assert_eq!(
        store.read(&owner, &name).unwrap(),
        Some(127_u32.to_be_bytes().to_vec())
    );
    engine.clear_projection_cache();
    assert_eq!(
        store.read(&owner, &name).unwrap(),
        Some(127_u32.to_be_bytes().to_vec())
    );
}
