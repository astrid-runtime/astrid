//! Repeated point reads borrow resident metadata without copying its references.

use super::*;

#[tokio::test]
async fn point_read_shares_resident_commit_and_state_records() {
    let engine = Arc::new(MeasuringEngine::new());
    let store =
        TreeKvStore::<String, TestIdentity, _, _>::from_engine(Arc::clone(&engine), Resolver);
    store
        .set("alice:capsule:test", "key", vec![0x42; 32])
        .await
        .unwrap();
    engine.owned_header_reads.store(0, Ordering::Relaxed);
    engine.shared_header_reads.store(0, Ordering::Relaxed);

    assert_eq!(
        store.get("alice:capsule:test", "key").await.unwrap(),
        Some(vec![0x42; 32])
    );
    assert_eq!(
        engine.owned_header_reads.load(Ordering::Relaxed),
        0,
        "point read deep-copied resident commit/state metadata"
    );
    assert_eq!(
        engine.shared_header_reads.load(Ordering::Relaxed),
        2,
        "point read must still load and validate both commit and state"
    );
    store.close().await.unwrap();
}
