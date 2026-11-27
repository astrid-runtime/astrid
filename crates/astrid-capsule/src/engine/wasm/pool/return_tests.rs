use super::{tests::empty_pool, *};

#[tokio::test]
async fn completed_free_checkout_reuses_only_a_clean_instance() {
    let cancel = CancellationToken::new();
    let pool = empty_pool(1, 1, &cancel).await;
    let mut checkout = pool.checkout().await.expect("checkout");
    checkout.begin_call();
    let held = Arc::new(());
    checkout
        .store_mut()
        .data_mut()
        .resource_table
        .push(Arc::clone(&held))
        .expect("push resource");
    checkout.complete_call();
    drop(checkout);
    assert_eq!(Arc::strong_count(&held), 1);
    assert!(pool.available.lock().unwrap().is_empty());

    let mut fresh = pool.checkout().await.expect("replacement checkout");
    fresh.begin_call();
    let table = &mut fresh.store_mut().data_mut().resource_table;
    let released = table.push(17_u32).unwrap();
    assert_eq!(table.delete(released).unwrap(), 17);
    fresh.complete_call();
    drop(fresh);
    assert_eq!(pool.available.lock().unwrap().len(), 1);
    cancel.cancel();
}

#[tokio::test]
async fn completed_persistent_checkout_keeps_the_instance_and_resource() {
    let cancel = CancellationToken::new();
    let mut pool = empty_pool(1, 1, &cancel).await;
    pool.reset_resources_on_return = false;
    let mut checkout = pool.checkout().await.expect("checkout");
    checkout.begin_call();
    let held = checkout
        .store_mut()
        .data_mut()
        .resource_table
        .push(43_u32)
        .unwrap();
    checkout.complete_call();
    drop(checkout);
    assert_eq!(pool.available.lock().unwrap().len(), 1);
    let mut next = pool.checkout().await.expect("persistent checkout");
    assert_eq!(
        next.store_mut()
            .data_mut()
            .resource_table
            .delete(held)
            .unwrap(),
        43
    );
    cancel.cancel();
}
