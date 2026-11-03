//! Evolving large values through the same hosted KV API on both producers.
//! Volume deltas are hosted-file length growth, not allocator ownership or
//! uniquely reclaimable physical disk. No history is deleted by this workload.
use std::hint::black_box;
use std::path::Path;
use std::time::{Duration, Instant};

use astrid_core::dirs::AstridHome;
use astrid_storage::KvStore;

use super::{authoritative_store_bytes, open_store};
use crate::BenchResult;
use crate::config::Config;
use crate::report::Report;

// Fixed corpus, not runtime policy. Both lengths exercise the >256 KiB path;
// offsets and 4 KiB insertions mirror existing chunked-value regressions.
const INSERT_BYTES: usize = 4096;
const EDITS: usize = 4;
const NAMESPACE: &str = "system:storage-benchmark";
const KEY: &str = "evolving-value";

pub(crate) async fn run(config: &Config, root: &Path, report: &mut Report) -> BenchResult<()> {
    for (bytes, offset) in [(512 * 1024, 250_000), (8 * 1024 * 1024, 3_000_000)] {
        let versions = corpus(bytes, offset);
        let mut samples = Samples::default();
        for sample in 0..config.samples {
            let home = AstridHome::from_path(root.join(format!("evolving-kv-{bytes}-{sample}")));
            home.ensure()?;
            run_sample(config, &home, &versions, &mut samples).await?;
        }
        samples.record(bytes, report)?;
    }
    Ok(())
}

async fn run_sample(
    config: &Config,
    home: &AstridHome,
    versions: &[Vec<u8>],
    samples: &mut Samples,
) -> BenchResult<()> {
    let store = open_store(home, config.object_cache_bytes).await?;
    let kv = store.kv();
    let initial = versions[0].clone();
    let before = authoritative_store_bytes(home)?;
    let started = Instant::now();
    kv.set(NAMESPACE, KEY, initial).await?;
    samples.initial_set.push(started.elapsed());
    samples.initial_growth.push(growth(home, before)?);
    verify(kv.as_ref(), &versions[0]).await?;
    for pair in versions.windows(2) {
        let replacement = pair[1].clone();
        let before = authoritative_store_bytes(home)?;
        let started = Instant::now();
        let applied = kv
            .compare_and_swap(NAMESPACE, KEY, Some(&pair[0]), replacement)
            .await?;
        samples.cas.push(started.elapsed());
        if !applied {
            return Err("uncontended evolving-value CAS was not applied".into());
        }
        samples.edit_growth.push(growth(home, before)?);
        verify(kv.as_ref(), &pair[1]).await?;
    }
    let final_value = versions.last().ok_or("empty evolving-value corpus")?;
    let started = Instant::now();
    let actual = kv.get(NAMESPACE, KEY).await?;
    samples.read.push(started.elapsed());
    exact(actual, final_value)?;
    let started = Instant::now();
    kv.close().await?;
    samples.close.push(started.elapsed());
    drop(kv);
    drop(store);
    let started = Instant::now();
    let reopened = open_store(home, config.object_cache_bytes).await?;
    samples.reopen.push(started.elapsed());
    let kv = reopened.kv();
    let started = Instant::now();
    let actual = kv.get(NAMESPACE, KEY).await?;
    samples.read_after_reopen.push(started.elapsed());
    exact(actual, final_value)?;
    kv.close().await?;
    drop(kv);
    drop(reopened);
    Ok(())
}

fn corpus(bytes: usize, first_offset: usize) -> Vec<Vec<u8>> {
    let mut seed = 0x12ab_56cd_90ef_3412_u64;
    let original: Vec<u8> = (0..bytes)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed.to_le_bytes()[0]
        })
        .collect();
    let mut versions = vec![original];
    for index in 0..EDITS {
        let mut edited = versions[index].clone();
        let offset = first_offset.strict_add(index.strict_mul(INSERT_BYTES));
        edited.splice(offset..offset, [0x55; INSERT_BYTES]);
        versions.push(edited);
    }
    versions
}

async fn verify(kv: &dyn KvStore, expected: &[u8]) -> BenchResult<()> {
    exact(kv.get(NAMESPACE, KEY).await?, expected)
}

fn exact(actual: Option<Vec<u8>>, expected: &[u8]) -> BenchResult<()> {
    if actual.as_deref() != Some(expected) {
        return Err("evolving-value exact readback mismatch".into());
    }
    black_box(actual);
    Ok(())
}

fn growth(home: &AstridHome, before: u64) -> BenchResult<u64> {
    authoritative_store_bytes(home)?
        .checked_sub(before)
        .ok_or_else(|| {
            "hosted volume shrank; append-only growth metric cannot represent sample".into()
        })
}

#[derive(Default)]
struct Samples {
    initial_set: Vec<Duration>,
    initial_growth: Vec<u64>,
    cas: Vec<Duration>,
    edit_growth: Vec<u64>,
    read: Vec<Duration>,
    close: Vec<Duration>,
    reopen: Vec<Duration>,
    read_after_reopen: Vec<Duration>,
}

impl Samples {
    fn record(self, bytes: usize, report: &mut Report) -> BenchResult<()> {
        let names = match bytes {
            524_288 => [
                "kv_512k_initial",
                "kv_512k_insert_cas",
                "kv_512k_read",
                "kv_512k_close",
                "kv_512k_reopen",
                "kv_512k_reopen_read",
            ],
            8_388_608 => [
                "kv_8m_initial",
                "kv_8m_insert_cas",
                "kv_8m_read",
                "kv_8m_close",
                "kv_8m_reopen",
                "kv_8m_reopen_read",
            ],
            _ => return Err("unrecognized evolving-value corpus size".into()),
        };
        let initial_bytes = u64::try_from(bytes)?;
        let final_bytes = u64::try_from(bytes.strict_add(EDITS.strict_mul(INSERT_BYTES)))?;
        report.record_bytes(names[0], initial_bytes, self.initial_set);
        report.record_write_amplification(names[0], initial_bytes, self.initial_growth)?;
        // Each observation is one exact full-value CAS. The amplification
        // denominator is inserted logical bytes, not the full submitted value.
        report.record_operations(names[1], 1, self.cas);
        report.record_write_amplification(
            names[1],
            u64::try_from(INSERT_BYTES)?,
            self.edit_growth,
        )?;
        report.record_bytes(names[2], final_bytes, self.read);
        report.record_operations(names[3], 1, self.close);
        report.record_operations(names[4], 1, self.reopen);
        report.record_bytes(names[5], final_bytes, self.read_after_reopen);
        Ok(())
    }
}
