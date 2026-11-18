//! Matched, unlogged prefix measurements. These are manual evidence, not CI gates.

use std::sync::Arc;
use std::time::Instant;

use super::tree_tests::{Resolver, TestIdentity};
use super::{KvStore, ScopedKvStore, TreeKvStore};
use crate::engine::InMemoryEngine;
use crate::identity::{IdentityStore, KvIdentityStore};

const NS: &str = "alice:capsule:identity";
const LINKS: usize = 1024;
const QUERIES: usize = 128;

#[tokio::test]
#[ignore = "manual matched cold/warm sparse/all-result prefix profile"]
async fn identity_prefix_query_measurement() {
    for (name, checkpoint, all, count) in [
        ("empty", false, false, 0),
        ("single", false, true, 1),
        ("overlay-sparse", false, false, LINKS),
        ("overlay-all", false, true, LINKS),
        ("checkpoint-sparse", true, false, LINKS),
        ("checkpoint-all", true, true, LINKS),
    ] {
        let engine = Arc::new(InMemoryEngine::new(TestIdentity));
        let backend = Arc::new(
            TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine.clone(), Resolver),
        );
        let writer = KvIdentityStore::new(ScopedKvStore::new(backend.clone(), NS).unwrap());
        let target = writer.create_user(Some("target")).await.unwrap();
        let other = writer.create_user(Some("other")).await.unwrap();
        for index in 0..count {
            writer
                .link(
                    "service",
                    &format!("row-{index:04}"),
                    if all || index == 0 {
                        target.id
                    } else {
                        other.id
                    },
                    "operator",
                )
                .await
                .unwrap();
        }
        if checkpoint {
            backend.checkpoint_for_test("alice".to_owned()).unwrap();
            // Exercise a live overlay over a checkpoint, including a shadowed
            // selected row and the two traversal segments' result ordering.
            writer
                .link("service", "row-0000", target.id, "refreshed")
                .await
                .unwrap();
        }
        drop(writer);
        drop(backend);
        let reader = KvIdentityStore::new(
            ScopedKvStore::new(
                Arc::new(
                    TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(engine, Resolver),
                ),
                NS,
            )
            .unwrap(),
        );
        let expected = if all { count } else { usize::from(count != 0) };
        let cold = Instant::now();
        assert_eq!(reader.list_links(target.id).await.unwrap().len(), expected);
        let cold_us = cold.elapsed().as_micros();
        let warm = Instant::now();
        for _ in 0..QUERIES {
            let links = reader.list_links(target.id).await.unwrap();
            assert_eq!(links.len(), expected);
            drop(std::hint::black_box(links));
        }
        println!(
            "prefix_scan case={name} cold_us={cold_us} warm_us={} queries={QUERIES} results={expected}",
            warm.elapsed().as_micros()
        );
    }
}

#[tokio::test]
#[ignore = "manual matched key-only scan and clear-prefix profile"]
async fn prefix_key_clear_measurement() {
    for (name, checkpoint) in [("overlay", false), ("checkpoint", true)] {
        let mut keys_us = Vec::new();
        let mut clear_us = Vec::new();
        for _ in 0..9 {
            let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
                Arc::new(InMemoryEngine::new(TestIdentity)),
                Resolver,
            );
            for index in 0..128 {
                store
                    .set(NS, &format!("link/{index:04}"), vec![0x51; 8192])
                    .await
                    .unwrap();
            }
            if checkpoint {
                store.checkpoint_for_test("alice".to_owned()).unwrap();
            }
            assert_eq!(
                store
                    .list_keys_with_prefix(NS, "link/")
                    .await
                    .unwrap()
                    .len(),
                128
            );
            let start = Instant::now();
            for _ in 0..128 {
                assert_eq!(
                    std::hint::black_box(store.list_keys_with_prefix(NS, "link/").await.unwrap())
                        .len(),
                    128
                );
            }
            keys_us.push(start.elapsed().as_micros());
            let start = Instant::now();
            assert_eq!(store.clear_prefix(NS, "link/").await.unwrap(), 128);
            clear_us.push(start.elapsed().as_micros());
            assert!(
                store
                    .list_keys_with_prefix(NS, "link/")
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        println!("prefix_key_scan_{name}_128_queries_us={keys_us:?}");
        println!("prefix_clear_{name}_128_rows_us={clear_us:?}");
    }
}

#[tokio::test]
#[ignore = "manual fresh clear-only control without preceding key scans"]
async fn prefix_fresh_clear_measurement() {
    for (name, checkpoint) in [("overlay", false), ("checkpoint", true)] {
        let mut clear_us = Vec::new();
        for _ in 0..9 {
            let store = TreeKvStore::<String, TestIdentity, Resolver, _>::from_engine(
                Arc::new(InMemoryEngine::new(TestIdentity)),
                Resolver,
            );
            for index in 0..128 {
                store
                    .set(NS, &format!("link/{index:04}"), vec![0x51; 8192])
                    .await
                    .unwrap();
            }
            if checkpoint {
                store.checkpoint_for_test("alice".to_owned()).unwrap();
            }
            let start = Instant::now();
            assert_eq!(store.clear_prefix(NS, "link/").await.unwrap(), 128);
            clear_us.push(start.elapsed().as_micros());
            assert!(
                store
                    .list_keys_with_prefix(NS, "link/")
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        println!("prefix_fresh_clear_{name}_128_rows_us={clear_us:?}");
    }
}
