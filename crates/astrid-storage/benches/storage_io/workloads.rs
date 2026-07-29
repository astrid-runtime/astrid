use std::convert::Infallible;
use std::fs::{File, OpenOptions};
use std::hint::black_box;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use astrid_core::dirs::AstridHome;
use astrid_core::principal::PrincipalId;
use astrid_storage::{
    Blake3ObjectIdentityV1, ChunkingProfile, ContentName, KvQuotaResolver,
    NativeContentStagingArea, NativePrincipalContentStore, RuntimePrincipalStore, StateOwner,
    open_runtime_principal_store,
};
use astrid_storage_content::{ContentObjectSink, build_content_streaming};
use astrid_storage_model::{ObjectId, ObjectIdentity, ObjectRecord};

use super::config::Config;
use super::report::Report;
use crate::BenchResult;

pub(super) async fn run(
    config: &Config,
    root: &Path,
    source: &Path,
    source_digest: [u8; 32],
    report: &mut Report,
) -> BenchResult<()> {
    benchmark_native_large_writes(config, root, source, report)?;
    benchmark_staging_large_writes(config, root, source, report)?;
    benchmark_content_compute(config, source, report)?;
    benchmark_small_files(config, root, report)?;
    benchmark_runtime(config, root, source, source_digest, report).await?;
    benchmark_concurrent_principals(config, root, source, source_digest, report).await?;
    report.record_substrate_comparison(
        "cached_staging_write",
        "astrid_stage_write",
        "native_write",
    )?;
    report.record_substrate_comparison(
        "warm_verified_read",
        "astrid_read_warm",
        "native_read_warm",
    )?;
    report.record_throughput_scaling(
        "concurrent_shared_publication",
        "astrid_concurrent_shared_publish",
        "astrid_publish_unique",
    )?;
    report.record_throughput_scaling(
        "concurrent_shared_warm_read",
        "astrid_concurrent_shared_read_warm",
        "astrid_read_warm",
    )?;
    Ok(())
}

fn benchmark_native_large_writes(
    config: &Config,
    root: &Path,
    source: &Path,
    report: &mut Report,
) -> BenchResult<()> {
    let mut copy_samples = Vec::with_capacity(config.samples);
    let mut sync_samples = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let destination = root.join(format!("native-large-{sample}.bin"));
        let mut input = File::open(source)?;
        let mut output = create_truncated(&destination)?;
        let started = Instant::now();
        let copied = copy_stream(&mut input, &mut output, config.block_bytes)?;
        copy_samples.push(started.elapsed());
        if copied != config.bytes {
            return Err(format!(
                "native copy wrote {copied} bytes, expected {}",
                config.bytes
            )
            .into());
        }
        let started = Instant::now();
        output.sync_all()?;
        sync_samples.push(started.elapsed());
        drop(output);
        std::fs::remove_file(destination)?;
    }
    report.record_bytes("native_write", config.bytes, copy_samples);
    report.record_operations("native_sync_after_write", 1, sync_samples);
    Ok(())
}

fn benchmark_staging_large_writes(
    config: &Config,
    root: &Path,
    source: &Path,
    report: &mut Report,
) -> BenchResult<()> {
    let owner = benchmark_owner()?;
    let mut write_samples = Vec::with_capacity(config.samples);
    let mut seal_samples = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let directory = tempfile::tempdir_in(root)?;
        let staging = NativeContentStagingArea::open(directory.path().join("staging"))?;
        let name = ContentName::new(format!("large/{sample}"))?;
        let mut writer = staging.begin(owner.clone(), name, ChunkingProfile::ASTRID_V1)?;
        let mut input = File::open(source)?;
        let started = Instant::now();
        let copied = copy_stream(&mut input, &mut writer, config.block_bytes)?;
        write_samples.push(started.elapsed());
        if copied != config.bytes {
            return Err(format!(
                "staged copy wrote {copied} bytes, expected {}",
                config.bytes
            )
            .into());
        }
        let started = Instant::now();
        black_box(writer.seal()?);
        seal_samples.push(started.elapsed());
    }
    report.record_bytes("astrid_stage_write", config.bytes, write_samples);
    report.record_bytes("astrid_stage_seal", config.bytes, seal_samples);
    Ok(())
}

fn benchmark_content_compute(
    config: &Config,
    source: &Path,
    report: &mut Report,
) -> BenchResult<()> {
    let mut samples = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        let input = File::open(source)?;
        let mut sink = DiscardSink;
        let started = Instant::now();
        black_box(build_content_streaming(
            ChunkingProfile::ASTRID_V1,
            input,
            &mut sink,
        )?);
        samples.push(started.elapsed());
    }
    report.record_bytes("astrid_content_build_compute", config.bytes, samples);
    Ok(())
}

struct DiscardSink;

impl ContentObjectSink for DiscardSink {
    type Error = Infallible;

    fn stage_content_object(&mut self, record: ObjectRecord) -> Result<ObjectId, Self::Error> {
        Ok(Blake3ObjectIdentityV1.identify(&record))
    }
}

fn benchmark_small_files(config: &Config, root: &Path, report: &mut Report) -> BenchResult<()> {
    let payload = vec![0x5a; config.small_file_bytes];
    let native_root = root.join("native-small");
    std::fs::create_dir_all(&native_root)?;
    let mut native_close_samples = Vec::with_capacity(config.samples);
    let mut native_sync_samples = Vec::with_capacity(config.samples);
    let mut astrid_seal_samples = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        let started = Instant::now();
        for index in 0..config.small_files {
            let path = native_root.join(format!("cached-{sample}-{index}"));
            let mut file = File::create(path)?;
            file.write_all(&payload)?;
        }
        native_close_samples.push(started.elapsed());
    }
    report.record_operations(
        "native_small_write_close",
        config.small_files,
        native_close_samples,
    );

    for sample in 0..config.samples {
        let started = Instant::now();
        for index in 0..config.small_files {
            let path = native_root.join(format!("durable-{sample}-{index}"));
            let mut file = File::create(path)?;
            file.write_all(&payload)?;
            file.sync_all()?;
        }
        native_sync_samples.push(started.elapsed());
    }
    report.record_operations(
        "native_small_write_sync",
        config.small_files,
        native_sync_samples,
    );

    let staging = NativeContentStagingArea::open(root.join("small-staging"))?;
    let owner = benchmark_owner()?;
    for sample in 0..config.samples {
        let started = Instant::now();
        for index in 0..config.small_files {
            let name = ContentName::new(format!("small/{sample}/{index}"))?;
            let mut writer = staging.begin(owner.clone(), name, ChunkingProfile::ASTRID_V1)?;
            writer.write_all(&payload)?;
            black_box(writer.seal()?);
        }
        astrid_seal_samples.push(started.elapsed());
    }
    report.record_operations(
        "astrid_small_write_seal",
        config.small_files,
        astrid_seal_samples,
    );
    Ok(())
}

async fn benchmark_runtime(
    config: &Config,
    root: &Path,
    source: &Path,
    source_digest: [u8; 32],
    report: &mut Report,
) -> BenchResult<()> {
    benchmark_native_reads(config, source, source_digest, report)?;
    let owner = benchmark_owner()?;
    let home_path = root.join("astrid-home");
    let mut samples = RuntimeSamples::default();
    for sample in 0..config.samples {
        if sample != 0 {
            reset_benchmark_home(&home_path)?;
        }
        let home = AstridHome::from_path(home_path.clone());
        home.ensure()?;
        let started = Instant::now();
        let store = open_store(&home).await?;
        samples.fresh_open.push(started.elapsed());

        let publication = benchmark_publication(config, source, &store, &owner, &home).await?;
        samples.unique_publish.push(publication.unique_publish);
        samples
            .unique_authoritative_bytes
            .push(publication.unique_authoritative_bytes);
        samples
            .unique_end_to_end
            .push(publication.unique_end_to_end);
        samples
            .duplicate_stage_write
            .push(publication.duplicate_stage_write);
        samples
            .duplicate_stage_seal
            .push(publication.duplicate_stage_seal);
        samples
            .duplicate_publish
            .push(publication.duplicate_publish);
        samples
            .duplicate_authoritative_bytes
            .push(publication.duplicate_authoritative_bytes);
        samples
            .duplicate_end_to_end
            .push(publication.duplicate_end_to_end);

        samples.read_first.push(timed_content_read(
            store.content().as_ref(),
            &owner,
            &publication.unique_name,
            config.bytes,
            config.range_bytes,
            source_digest,
        )?);
        samples.read_warm.push(timed_content_read(
            store.content().as_ref(),
            &owner,
            &publication.unique_name,
            config.bytes,
            config.range_bytes,
            source_digest,
        )?);

        drop(store);
        let started = Instant::now();
        let reopened = open_store(&home).await?;
        samples.reopen.push(started.elapsed());
        samples.read_after_reopen.push(timed_content_read(
            reopened.content().as_ref(),
            &owner,
            &publication.unique_name,
            config.bytes,
            config.range_bytes,
            source_digest,
        )?);
        drop(reopened);
    }
    samples.record(config, report)?;
    Ok(())
}

async fn benchmark_publication(
    config: &Config,
    source: &Path,
    store: &RuntimePrincipalStore,
    owner: &StateOwner,
    home: &AstridHome,
) -> BenchResult<PublicationSample> {
    let (unique_name, unique_staged, stage_write, stage_seal) =
        stage_source(store, source, owner, "large/unique.bin", config.block_bytes)?;
    let authoritative_before = authoritative_store_bytes(home)?;
    let started = Instant::now();
    black_box(store.publish_staged(unique_staged).await?);
    let unique_publish = started.elapsed();
    let authoritative_after_unique = authoritative_store_bytes(home)?;
    let unique_authoritative_bytes = authoritative_after_unique
        .checked_sub(authoritative_before)
        .ok_or("authoritative store shrank during unique publication")?;
    let unique_end_to_end = sum_durations(&[stage_write, stage_seal, unique_publish])?;

    let (_, duplicate_staged, duplicate_write, duplicate_seal) = stage_source(
        store,
        source,
        owner,
        "large/duplicate.bin",
        config.block_bytes,
    )?;
    let authoritative_before_duplicate = authoritative_store_bytes(home)?;
    let started = Instant::now();
    black_box(store.publish_staged(duplicate_staged).await?);
    let duplicate_publish = started.elapsed();
    let authoritative_after_duplicate = authoritative_store_bytes(home)?;
    let duplicate_authoritative_bytes = authoritative_after_duplicate
        .checked_sub(authoritative_before_duplicate)
        .ok_or("authoritative store shrank during duplicate publication")?;
    Ok(PublicationSample {
        unique_name,
        unique_publish,
        unique_authoritative_bytes,
        unique_end_to_end,
        duplicate_stage_write: duplicate_write,
        duplicate_stage_seal: duplicate_seal,
        duplicate_publish,
        duplicate_authoritative_bytes,
        duplicate_end_to_end: sum_durations(&[duplicate_write, duplicate_seal, duplicate_publish])?,
    })
}

struct PublicationSample {
    unique_name: ContentName,
    unique_publish: Duration,
    unique_authoritative_bytes: u64,
    unique_end_to_end: Duration,
    duplicate_stage_write: Duration,
    duplicate_stage_seal: Duration,
    duplicate_publish: Duration,
    duplicate_authoritative_bytes: u64,
    duplicate_end_to_end: Duration,
}

#[derive(Default)]
struct RuntimeSamples {
    fresh_open: Vec<Duration>,
    unique_publish: Vec<Duration>,
    unique_authoritative_bytes: Vec<u64>,
    unique_end_to_end: Vec<Duration>,
    duplicate_stage_write: Vec<Duration>,
    duplicate_stage_seal: Vec<Duration>,
    duplicate_publish: Vec<Duration>,
    duplicate_authoritative_bytes: Vec<u64>,
    duplicate_end_to_end: Vec<Duration>,
    read_first: Vec<Duration>,
    read_warm: Vec<Duration>,
    reopen: Vec<Duration>,
    read_after_reopen: Vec<Duration>,
}

impl RuntimeSamples {
    fn record(self, config: &Config, report: &mut Report) -> BenchResult<()> {
        report.record_operations("astrid_fresh_open", 1, self.fresh_open);
        report.record_bytes("astrid_publish_unique", config.bytes, self.unique_publish);
        report.record_write_amplification(
            "astrid_publish_unique",
            config.bytes,
            self.unique_authoritative_bytes,
        )?;
        report.record_bytes(
            "astrid_unique_end_to_end",
            config.bytes,
            self.unique_end_to_end,
        );
        report.record_bytes(
            "astrid_duplicate_stage_write",
            config.bytes,
            self.duplicate_stage_write,
        );
        report.record_bytes(
            "astrid_duplicate_stage_seal",
            config.bytes,
            self.duplicate_stage_seal,
        );
        report.record_bytes(
            "astrid_publish_duplicate",
            config.bytes,
            self.duplicate_publish,
        );
        report.record_write_amplification(
            "astrid_publish_duplicate",
            config.bytes,
            self.duplicate_authoritative_bytes,
        )?;
        report.record_bytes(
            "astrid_duplicate_end_to_end",
            config.bytes,
            self.duplicate_end_to_end,
        );
        report.record_bytes("astrid_read_first", config.bytes, self.read_first);
        report.record_bytes("astrid_read_warm", config.bytes, self.read_warm);
        report.record_operations("astrid_reopen", 1, self.reopen);
        report.record_bytes(
            "astrid_read_after_reopen",
            config.bytes,
            self.read_after_reopen,
        );
        Ok(())
    }
}

fn authoritative_store_bytes(home: &AstridHome) -> BenchResult<u64> {
    ["objects.arena", "roots.journal"]
        .into_iter()
        .try_fold(0_u64, |total, file_name| {
            let bytes = std::fs::metadata(home.principal_store_path().join(file_name))?.len();
            total
                .checked_add(bytes)
                .ok_or_else(|| "authoritative store byte count overflow".into())
        })
}

fn benchmark_native_reads(
    config: &Config,
    source: &Path,
    source_digest: [u8; 32],
    report: &mut Report,
) -> BenchResult<()> {
    let native_first = timed_native_read(source, config.block_bytes, source_digest)?;
    let mut native_warm = Vec::with_capacity(config.samples);
    for _ in 0..config.samples {
        native_warm.push(timed_native_read(
            source,
            config.block_bytes,
            source_digest,
        )?);
    }
    report.record_bytes("native_read_first", config.bytes, vec![native_first]);
    report.record_bytes("native_read_warm", config.bytes, native_warm);
    Ok(())
}

async fn benchmark_concurrent_principals(
    config: &Config,
    root: &Path,
    source: &Path,
    source_digest: [u8; 32],
    report: &mut Report,
) -> BenchResult<()> {
    let total_bytes = config.bytes;
    let range_bytes = config.range_bytes;
    let logical_bytes = config
        .bytes
        .checked_mul(u64::try_from(config.concurrent_principals)?)
        .ok_or("concurrent logical byte count overflow")?;
    let home_path = root.join("concurrent-home");
    let mut publish_samples = Vec::with_capacity(config.samples);
    let mut read_samples = Vec::with_capacity(config.samples);
    for sample in 0..config.samples {
        if sample != 0 {
            reset_benchmark_home(&home_path)?;
        }
        let home = AstridHome::from_path(home_path.clone());
        home.ensure()?;
        let store = open_store(&home).await?;
        let mut staged = Vec::with_capacity(config.concurrent_principals);
        let mut descriptors = Vec::with_capacity(config.concurrent_principals);
        for index in 0..config.concurrent_principals {
            let owner = benchmark_owner_named(&format!("storage-benchmark-concurrent-{index}"))?;
            let name = format!("shared/{sample}/{index}.bin");
            let (name, ready, _, _) =
                stage_source(&store, source, &owner, &name, config.block_bytes)?;
            staged.push(ready);
            descriptors.push((owner, name));
        }

        let started = Instant::now();
        let mut publishers = Vec::with_capacity(staged.len());
        for ready in staged {
            let store = store.clone();
            publishers.push(tokio::spawn(
                async move { store.publish_staged(ready).await },
            ));
        }
        for publisher in publishers {
            black_box(publisher.await??);
        }
        publish_samples.push(started.elapsed());

        let started = Instant::now();
        let mut readers = Vec::with_capacity(descriptors.len());
        for (owner, name) in descriptors {
            let content = store.content();
            readers.push(tokio::task::spawn_blocking(move || {
                timed_content_read(
                    content.as_ref(),
                    &owner,
                    &name,
                    total_bytes,
                    range_bytes,
                    source_digest,
                )
            }));
        }
        for reader in readers {
            black_box(reader.await??);
        }
        read_samples.push(started.elapsed());
        drop(store);
    }
    report.record_bytes(
        "astrid_concurrent_shared_publish",
        logical_bytes,
        publish_samples,
    );
    report.record_bytes(
        "astrid_concurrent_shared_read_warm",
        logical_bytes,
        read_samples,
    );
    Ok(())
}

fn reset_benchmark_home(path: &Path) -> BenchResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => Err(format!(
            "benchmark home {} is redirected or not a directory",
            path.display()
        )
        .into()),
        Ok(_) => std::fs::remove_dir_all(path).map_err(Into::into),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn stage_source(
    store: &RuntimePrincipalStore,
    source: &Path,
    owner: &StateOwner,
    name: &str,
    block_bytes: usize,
) -> BenchResult<(
    ContentName,
    astrid_storage::ReadyStagedContent,
    Duration,
    Duration,
)> {
    let name = ContentName::new(name)?;
    let mut writer =
        store
            .staging()
            .begin(owner.clone(), name.clone(), ChunkingProfile::ASTRID_V1)?;
    let mut input = File::open(source)?;
    let started = Instant::now();
    let copied = copy_stream(&mut input, &mut writer, block_bytes)?;
    let write_duration = started.elapsed();
    let started = Instant::now();
    let staged = writer.seal()?;
    let seal_duration = started.elapsed();
    if staged.logical_bytes() != copied {
        return Err("staged length differs from copied byte count".into());
    }
    Ok((name, staged, write_duration, seal_duration))
}

async fn open_store(home: &AstridHome) -> BenchResult<RuntimePrincipalStore> {
    let quota: Arc<dyn KvQuotaResolver<StateOwner>> = Arc::new(|_: &StateOwner| Ok(None));
    open_runtime_principal_store(home, quota)
        .await
        .map_err(Into::into)
}

fn timed_native_read(path: &Path, block_bytes: usize, expected: [u8; 32]) -> BenchResult<Duration> {
    let started = Instant::now();
    let actual = hash_native(path, block_bytes)?;
    let elapsed = started.elapsed();
    if actual != expected {
        return Err("native read digest mismatch".into());
    }
    black_box(actual);
    Ok(elapsed)
}

fn timed_content_read(
    content: &NativePrincipalContentStore,
    owner: &StateOwner,
    name: &ContentName,
    total_bytes: u64,
    range_bytes: usize,
    expected: [u8; 32],
) -> BenchResult<Duration> {
    let started = Instant::now();
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0_u64;
    while offset < total_bytes {
        let length = total_bytes
            .saturating_sub(offset)
            .min(u64::try_from(range_bytes)?);
        let bytes = content
            .read_range(owner, name, offset, length)?
            .ok_or("published content disappeared during benchmark")?;
        hasher.update(&bytes);
        offset = offset
            .checked_add(length)
            .ok_or("published read offset overflow")?;
    }
    let actual = *hasher.finalize().as_bytes();
    let elapsed = started.elapsed();
    if actual != expected {
        return Err("published read digest mismatch".into());
    }
    black_box(actual);
    Ok(elapsed)
}

pub(super) fn prepare_source(path: &Path, bytes: u64, block_bytes: usize) -> BenchResult<()> {
    let mut file = create_truncated(path)?;
    let mut buffer = vec![0_u8; block_bytes];
    let mut offset = 0_u64;
    while offset < bytes {
        let remaining = bytes
            .checked_sub(offset)
            .ok_or("source offset exceeded length")?;
        let length = usize::try_from(remaining.min(u64::try_from(block_bytes)?))?;
        fill_pattern(&mut buffer[..length], offset)?;
        file.write_all(&buffer[..length])?;
        offset = offset
            .checked_add(u64::try_from(length)?)
            .ok_or("source offset overflow")?;
    }
    file.sync_all()?;
    Ok(())
}

fn fill_pattern(bytes: &mut [u8], byte_offset: u64) -> BenchResult<()> {
    for (index, destination) in bytes.chunks_mut(8).enumerate() {
        let word = (byte_offset / 8)
            .checked_add(u64::try_from(index)?)
            .ok_or("pattern word offset overflow")?;
        let value = splitmix64(word ^ 0xa076_1d64_78bd_642f).to_le_bytes();
        destination.copy_from_slice(&value[..destination.len()]);
    }
    Ok(())
}

const fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9e37_79b9_7f4a_7c15);
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn copy_stream<R: Read, W: Write>(
    source: &mut R,
    destination: &mut W,
    block_bytes: usize,
) -> BenchResult<u64> {
    let mut buffer = vec![0_u8; block_bytes];
    let mut copied = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        destination.write_all(&buffer[..read])?;
        copied = copied
            .checked_add(u64::try_from(read)?)
            .ok_or("copy byte count overflow")?;
    }
    Ok(copied)
}

pub(super) fn hash_native(path: &Path, block_bytes: usize) -> BenchResult<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut buffer = vec![0_u8; block_bytes];
    let mut hasher = blake3::Hasher::new();
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn benchmark_owner() -> BenchResult<StateOwner> {
    benchmark_owner_named("storage-benchmark")
}

fn benchmark_owner_named(name: &str) -> BenchResult<StateOwner> {
    PrincipalId::new(name)
        .map(StateOwner::Principal)
        .map_err(Into::into)
}

fn create_truncated(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
}

fn sum_durations(durations: &[Duration]) -> BenchResult<Duration> {
    durations
        .iter()
        .try_fold(Duration::ZERO, |total, duration| {
            total
                .checked_add(*duration)
                .ok_or_else(|| "benchmark duration overflow".into())
        })
}
