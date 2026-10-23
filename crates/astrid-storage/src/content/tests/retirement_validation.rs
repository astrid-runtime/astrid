//! Immutable catalogue evidence must survive custody without retaining views.
use super::*;
use crate::content::catalog::CatalogValidation;

type Store = PrincipalContentStore<String, CountingEngine>;

fn fixture() -> (Arc<CountingEngine>, Store, String, Vec<ContentName>) {
    let engine = Arc::new(CountingEngine::new());
    let store = Store::from_engine(Arc::clone(&engine));
    let owner = "system".to_owned();
    let names: Vec<_> = (0..128)
        .map(|i| ContentName::new(format!("projection/{i:04}")).unwrap())
        .collect();
    for name in &names {
        store.put(&owner, name, b"content").unwrap();
    }
    (engine, store, owner, names)
}

fn fresh_store(
    engine: &Arc<CountingEngine>,
    owner: &str,
    proof: Option<CatalogValidation>,
) -> Store {
    // The native custody seam clears all old decoded-object/projection state.
    engine.clear_projection_cache();
    let validations = proof
        .map(|proof| (owner.to_owned(), proof))
        .into_iter()
        .collect();
    Store::from_engine_with_quota_and_validation(
        Arc::clone(engine),
        Arc::new(|_: &String| Ok(None)),
        Arc::new(parking_lot::Mutex::new(validations)),
        Arc::new(crate::kv::KvValidationCache::default()),
    )
}

#[test]
fn detached_catalog_proof_avoids_a_second_full_walk() {
    let (engine, old, owner, names) = fixture();
    let proof = old.take_catalog_validation(&owner).unwrap();
    assert!(old.take_catalog_validation(&owner).is_none());
    let fresh = fresh_store(&engine, &owner, Some(proof));
    engine.reset_object_loads();
    assert!(fresh.describe(&owner, &names[64]).unwrap().is_some());
    assert!(
        engine.object_loads() < names.len(),
        "a point read repeated catalogue-wide validation: {} object loads",
        engine.object_loads()
    );
}

#[test]
fn missing_catalog_proof_still_validates_every_entry() {
    let (engine, _old, owner, names) = fixture();
    let fresh = fresh_store(&engine, &owner, None);
    engine.reset_object_loads();
    assert!(fresh.describe(&owner, &names[64]).unwrap().is_some());
    assert!(engine.object_loads() >= names.len());
}

#[test]
fn detached_catalog_proof_cannot_cover_a_changed_root() {
    let (engine, old, owner, names) = fixture();
    let proof = old.take_catalog_validation(&owner).unwrap();
    // Simulate a stale proof defensively; the native handoff closes old writers.
    old.put(&owner, &names[64], b"new content").unwrap();
    let fresh = fresh_store(&engine, &owner, Some(proof));
    engine.reset_object_loads();
    assert_eq!(
        fresh.read(&owner, &names[64]).unwrap(),
        Some(b"new content".to_vec())
    );
    assert!(engine.object_loads() >= names.len());
}

#[test]
fn detached_catalog_proof_with_wrong_summary_is_rejected() {
    let (engine, old, owner, names) = fixture();
    let mut proof = old.take_catalog_validation(&owner).unwrap();
    proof.summary.entries = proof.summary.entries.strict_add(1);
    let fresh = fresh_store(&engine, &owner, Some(proof));
    let error = fresh.describe(&owner, &names[64]).unwrap_err();
    assert!(error.to_string().contains("validation totals disagree"));
}
