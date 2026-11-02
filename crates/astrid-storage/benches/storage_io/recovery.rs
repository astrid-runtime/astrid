//! Engine recovery on byte-identical copies; never opens the source as a volume.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

use astrid_storage::engine::{DurableEngine, ObjectCacheStats, PrincipalCodec, RecoveryLimits};
use astrid_storage::storage_model::RootState;
use astrid_storage::volume::HostedFileVolume;
use astrid_storage::{Blake3ObjectIdentityV1, DurableEnginePolicy, StateOwner, StateOwnerCodecV2};
use sha2::{Digest, Sha256};
use tracing_subscriber::fmt::format::FmtSpan;

use super::config::Config;
use super::provenance::RunProvenance;
use super::report::{RecoveryFixture, Report};
use super::resource;
use crate::BenchResult;

pub(super) fn run(config: &Config, root: &Path, provenance: RunProvenance) -> BenchResult<Report> {
    if config.profile_recovery {
        tracing_subscriber::fmt()
            .with_env_filter("astrid_storage::recovery=debug")
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .json()
            .with_writer(std::io::stderr)
            .try_init()?;
    }
    let source_path = config
        .recovery_volume
        .as_ref()
        .ok_or("missing recovery source")?;
    let mut source = FrozenSource::open(source_path)?;
    let mut observations = Vec::new();
    let mut expected_roots = None;
    for sample in 0..config.samples {
        let path = root.join(format!("recovery-{sample}.volume"));
        source.copy_to(&path)?;
        let (observation, roots) = recover_copy(&path)?;
        if let Some(expected) = &expected_roots {
            if expected != &roots {
                return Err(
                    "identical recovery snapshots yielded different principal roots".into(),
                );
            }
        } else {
            expected_roots = Some(roots);
        }
        observations.push(observation);
        // Keep only the last copy, outside the timed intervals. The source is
        // still shared-locked and every next sample copies its original bytes.
        if sample.strict_add(1) < config.samples {
            std::fs::remove_file(path)?;
        }
    }
    source.verify()?;
    let roots = expected_roots.ok_or("recovery benchmark requires samples")?;
    let mut report = Report::new(config.clone(), provenance);
    report.record_recovery_fixture(RecoveryFixture {
        volume_bytes: source.bytes,
        volume_sha256: source.sha256,
        root_count: roots.len(),
        roots_sha256: roots_digest(&roots),
        instrumented: config.profile_recovery,
    });
    report.record_operations(
        "astrid_recovery_container_open",
        1,
        durations(&observations, |observation| observation.container),
    );
    report.record_operations(
        "astrid_recovery_engine_open",
        1,
        durations(&observations, |observation| observation.engine),
    );
    report.record_operations(
        "astrid_recovery_engine_close",
        1,
        durations(&observations, |observation| observation.close),
    );
    record_recovery_peaks(&mut report, &observations)?;
    Ok(report)
}

struct RecoveryObservation {
    container: Duration,
    engine: Duration,
    close: Duration,
    rss_before_container: Option<u64>,
    rss_after_container: Option<u64>,
    rss_after_engine_open: Option<u64>,
    rss_after_engine_close: Option<u64>,
    object_cache: ObjectCacheStats,
}

fn recover_copy(path: &Path) -> BenchResult<(RecoveryObservation, Vec<(StateOwner, RootState)>)> {
    let rss_before_container = resource::process_resident_bytes()?;
    let started = Instant::now();
    let volume = HostedFileVolume::open(path)?;
    let container = started.elapsed();
    let rss_after_container = resource::process_resident_bytes()?;

    let started = Instant::now();
    let engine = DurableEngine::open_volume(
        volume.clone(),
        Blake3ObjectIdentityV1,
        StateOwnerCodecV2,
        RecoveryLimits::process_addressable(),
        DurableEnginePolicy::default(),
    )?;
    let engine_open = started.elapsed();
    let object_cache = engine.object_cache_stats();
    let rss_after_engine_open = resource::process_resident_bytes()?;
    let roots = engine.roots()?;

    let started = Instant::now();
    engine.close()?;
    drop(engine);
    drop(volume);
    let close = started.elapsed();
    let rss_after_engine_close = resource::process_resident_bytes()?;

    Ok((
        RecoveryObservation {
            container,
            engine: engine_open,
            close,
            rss_before_container,
            rss_after_container,
            rss_after_engine_open,
            rss_after_engine_close,
            object_cache,
        },
        roots,
    ))
}

type ResourceMetric<T> = (&'static str, fn(&RecoveryObservation) -> T);

fn record_recovery_peaks(
    report: &mut Report,
    observations: &[RecoveryObservation],
) -> BenchResult<()> {
    record_rss_peaks(report, observations)?;
    // Cache occupancy is charged bytes; resident_objects is a count.
    let metrics: [ResourceMetric<u64>; 4] = [
        ("astrid_recovery_object_cache_resident_bytes", |x| {
            x.object_cache.resident_bytes
        }),
        ("astrid_recovery_object_cache_resident_record_bytes", |x| {
            x.object_cache.resident_record_bytes
        }),
        (
            "astrid_recovery_object_cache_resident_association_bytes",
            |x| x.object_cache.resident_association_bytes,
        ),
        (
            "astrid_recovery_object_cache_resident_projection_bytes",
            |x| x.object_cache.resident_projection_bytes,
        ),
    ];
    for (name, select) in metrics {
        report.record_resource_peak(name, observations.iter().map(select).collect())?;
    }
    Ok(())
}

fn record_rss_peaks(report: &mut Report, observations: &[RecoveryObservation]) -> BenchResult<()> {
    let available = observations
        .first()
        .is_some_and(|x| x.rss_before_container.is_some());
    let metrics: [ResourceMetric<Option<u64>>; 4] = [
        ("astrid_recovery_rss_bytes_before_container", |x| {
            x.rss_before_container
        }),
        ("astrid_recovery_rss_bytes_after_container", |x| {
            x.rss_after_container
        }),
        ("astrid_recovery_rss_bytes_after_engine_open", |x| {
            x.rss_after_engine_open
        }),
        ("astrid_recovery_rss_bytes_after_engine_close", |x| {
            x.rss_after_engine_close
        }),
    ];
    for (name, select) in metrics {
        let samples = observations.iter().map(select).collect::<Option<Vec<_>>>();
        match (available, samples) {
            (true, Some(samples)) => report.record_resource_peak(name, samples)?,
            (false, None) if observations.iter().all(|x| select(x).is_none()) => {},
            _ => {
                return Err(format!(
                    "resource peak {name:?} mixed available and omitted RSS samples"
                )
                .into());
            },
        }
    }
    Ok(())
}

fn durations(
    observations: &[RecoveryObservation],
    select: fn(&RecoveryObservation) -> Duration,
) -> Vec<Duration> {
    observations.iter().map(select).collect()
}

pub(super) struct FrozenSource {
    file: File,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

impl FrozenSource {
    pub(super) fn open(path: &Path) -> BenchResult<Self> {
        let mut file = open_source_file(path)?;
        fs2::FileExt::try_lock_shared(&file)
            .map_err(|error| format!("recovery source is locked by a writer: {error}"))?;
        let bytes = file.metadata()?.len();
        if bytes == 0 {
            return Err("recovery source is empty".into());
        }
        let sha256 = hash_file(&mut file)?;
        Ok(Self {
            file,
            bytes,
            sha256,
        })
    }

    pub(super) fn copy_to(&mut self, path: &Path) -> BenchResult<()> {
        let mut destination = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)?;
        self.file.seek(SeekFrom::Start(0))?;
        let copied = std::io::copy(&mut self.file, &mut destination)?;
        destination.sync_all()?;
        if copied != self.bytes || hash_file(&mut destination)? != self.sha256 {
            return Err("recovery copy differs from its frozen source".into());
        }
        Ok(())
    }

    pub(super) fn verify(&mut self) -> BenchResult<()> {
        if self.file.metadata()?.len() != self.bytes || hash_file(&mut self.file)? != self.sha256 {
            return Err("recovery source changed during the benchmark".into());
        }
        Ok(())
    }
}

pub(super) fn open_source_file(path: &Path) -> BenchResult<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // Refuse the final symlink atomically; a raced FIFO must not block open.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err("recovery source must be a regular, stopped volume snapshot".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err("recovery source must not be a reparse point".into());
        }
    }
    Ok(file)
}

fn hash_file(file: &mut File) -> BenchResult<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 64 * 1024].into_boxed_slice();
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        hasher.update(&buffer[..length]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn roots_digest(roots: &[(StateOwner, RootState)]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"astrid-recovery-benchmark-roots-v1\0");
    for (owner, root) in roots {
        let owner = StateOwnerCodecV2.encode(owner);
        hasher.update((owner.len() as u64).to_le_bytes());
        hasher.update(owner);
        hasher.update(root.generation.get().to_le_bytes());
        hasher.update(root.commit.as_bytes());
    }
    hex::encode(hasher.finalize())
}
