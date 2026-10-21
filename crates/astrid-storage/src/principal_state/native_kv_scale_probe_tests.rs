use std::sync::Arc;
use std::time::Instant;

use astrid_core::identity::PrincipalUid;
use astrid_core::principal::PrincipalId;

use super::*;

fn test_directory(aliases: &[&str]) -> PrincipalDirectory {
    let directory = PrincipalDirectory::default();
    for alias in aliases {
        let mut hasher = blake3::Hasher::new_derive_key("astrid principal uid test fixture v1");
        hasher.update(alias.as_bytes());
        let uid = PrincipalUid::from_bytes(*hasher.finalize().as_bytes());
        directory
            .register(PrincipalId::new(*alias).unwrap(), uid)
            .unwrap();
    }
    directory
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "explicit native KV group-commit throughput probe"]
async fn native_kv_group_commit_scale_probe() {
    const COMMITS_PER_WRITER: u8 = 64;

    for writers in [1_u8, 2, 4, 8] {
        let directory = tempfile::tempdir().unwrap();
        let aliases = (0..writers)
            .map(|writer| format!("principal-{writer}"))
            .collect::<Vec<_>>();
        let alias_refs = aliases.iter().map(String::as_str).collect::<Vec<_>>();
        let engine = Arc::new(
            RuntimeEngine::open(
                directory.path(),
                Blake3ObjectIdentityV1,
                StateOwnerCodecV2,
                RecoveryLimits::process_addressable(),
            )
            .unwrap(),
        );
        let specification = bootstrap::format_specification().unwrap();
        let specification_id = engine.identify(&specification);
        engine.persist_standalone_object(&specification).unwrap();
        engine
            .ensure_direct_representation_catalogue(specification_id, &[specification_id])
            .unwrap();
        let store = Arc::new(RuntimeStore::from_engine(
            Arc::clone(&engine),
            StateOwnerResolver::new(test_directory(&alias_refs)),
        ));
        let barrier = Arc::new(tokio::sync::Barrier::new(usize::from(writers) + 1));
        let mut tasks = Vec::new();
        for writer in 0..writers {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                let namespace = format!("principal-{writer}:capsule:probe");
                let mut latencies = Vec::new();
                barrier.wait().await;
                for sequence in 0..COMMITS_PER_WRITER {
                    let mut value = vec![0_u8; 128];
                    value[..2].copy_from_slice(&[writer, sequence]);
                    let started = Instant::now();
                    store.set(&namespace, "state", value).await.unwrap();
                    latencies.push(started.elapsed());
                }
                latencies
            }));
        }
        barrier.wait().await;
        let started = Instant::now();
        let mut writer_latencies = Vec::new();
        for task in tasks {
            writer_latencies.push(task.await.unwrap());
        }
        let elapsed = started.elapsed();
        let mut latencies: Vec<_> = writer_latencies.iter().flatten().copied().collect();
        latencies.sort_unstable();
        let operations = u32::from(writers) * u32::from(COMMITS_PER_WRITER);
        let p50 = latencies[latencies.len() / 2];
        let p95 = latencies[(latencies.len() * 95 / 100).min(latencies.len() - 1)];
        let per_writer_p95: Vec<_> = writer_latencies
            .iter_mut()
            .map(|latencies| {
                latencies.sort_unstable();
                latencies[(latencies.len() * 95 / 100).min(latencies.len() - 1)].as_micros()
            })
            .collect();
        let per_writer_max: Vec<_> = writer_latencies
            .iter()
            .map(|latencies| latencies.last().unwrap().as_micros())
            .collect();
        println!(
            "native_kv_group_commit writers={writers} operations={operations} ops_per_second={:.1} p50_us={} p95_us={} per_writer_p95_us={per_writer_p95:?} per_writer_max_us={per_writer_max:?} wall_ms={}",
            f64::from(operations) / elapsed.as_secs_f64(),
            p50.as_micros(),
            p95.as_micros(),
            elapsed.as_millis(),
        );
        store.close().await.unwrap();
    }
}
