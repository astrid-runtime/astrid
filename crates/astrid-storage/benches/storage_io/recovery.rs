//! Engine recovery on byte-identical copies; never opens the source as a volume.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

use astrid_storage::engine::{DurableEngine, PrincipalCodec, RecoveryLimits};
use astrid_storage::storage_model::RootState;
use astrid_storage::volume::HostedFileVolume;
use astrid_storage::{Blake3ObjectIdentityV1, DurableEnginePolicy, StateOwner, StateOwnerCodecV2};
use sha2::{Digest, Sha256};
use tracing_subscriber::fmt::format::FmtSpan;

use super::config::Config;
use super::provenance::RunProvenance;
use super::report::{RecoveryFixture, Report};
use crate::BenchResult;

pub(super) fn run(config: &Config, root: &Path, provenance: RunProvenance) -> BenchResult<Report> {
    if config.profile_recovery {
        tracing_subscriber::fmt()
            .with_env_filter("astrid_storage::recovery=debug")
            .with_span_events(FmtSpan::CLOSE)
            .json()
            .with_writer(std::io::stderr)
            .try_init()?;
    }
    let source_path = config
        .recovery_volume
        .as_ref()
        .ok_or("missing recovery source")?;
    let mut source = FrozenSource::open(source_path)?;
    let mut container_samples = Vec::new();
    let mut engine_samples = Vec::new();
    let mut close_samples = Vec::new();
    let mut expected_roots = None;
    for sample in 0..config.samples {
        let path = root.join(format!("recovery-{sample}.volume"));
        source.copy_to(&path)?;
        let started = Instant::now();
        let volume = HostedFileVolume::open(&path)?;
        container_samples.push(started.elapsed());
        let started = Instant::now();
        let engine = DurableEngine::open_volume(
            volume.clone(),
            Blake3ObjectIdentityV1,
            StateOwnerCodecV2,
            RecoveryLimits::process_addressable(),
            DurableEnginePolicy::default(),
        )?;
        engine_samples.push(started.elapsed());
        let roots = engine.roots()?;
        if let Some(expected) = &expected_roots {
            if expected != &roots {
                return Err(
                    "identical recovery snapshots yielded different principal roots".into(),
                );
            }
        } else {
            expected_roots = Some(roots);
        }
        let started = Instant::now();
        engine.close()?;
        drop(engine);
        drop(volume);
        close_samples.push(started.elapsed());
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
    report.record_operations("astrid_recovery_container_open", 1, container_samples);
    report.record_operations("astrid_recovery_engine_open", 1, engine_samples);
    report.record_operations("astrid_recovery_engine_close", 1, close_samples);
    Ok(report)
}

pub(super) struct FrozenSource {
    file: File,
    pub(super) bytes: u64,
    pub(super) sha256: String,
}

impl FrozenSource {
    pub(super) fn open(path: &Path) -> BenchResult<Self> {
        if !std::fs::symlink_metadata(path)?.is_file() {
            return Err("recovery source must be a regular, stopped volume snapshot".into());
        }
        let mut file = File::open(path)?;
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
