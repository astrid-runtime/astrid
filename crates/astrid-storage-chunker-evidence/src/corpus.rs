use std::fs::{self, File};
use std::hint::black_box;
use std::io::{BufReader, Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::Serialize;
use walkdir::WalkDir;

use crate::algorithm::Candidate;
use crate::fixture::{periodic_bytes, pseudorandom_bytes};
use crate::metrics::{Accumulator, Measurements};
use crate::throughput::{Timing, fold_digest, median_duration, timing};

const EXCLUDED_TOP_LEVEL_DIRECTORIES: &[&str] = &["keys", "secrets", "run", ".Trash"];
const READER_CAPACITY: usize = 1024 * 1024;
const CORPUS_THROUGHPUT_SAMPLES: usize = 4;

#[derive(Clone)]
enum Input {
    File {
        path: PathBuf,
        snapshot: FileSnapshot,
    },
    Memory(Arc<[u8]>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileSnapshot {
    logical_bytes: u64,
    identity: [u8; 32],
}

pub struct Corpus {
    name: String,
    kind: CorpusKind,
    inputs: Vec<Input>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CorpusKind {
    DirectorySnapshot,
    VersionChain,
    SyntheticAdversarial,
}

#[derive(Debug, Serialize)]
pub struct CandidateResult {
    pub corpus: String,
    pub corpus_kind: CorpusKind,
    pub candidate: Candidate,
    pub throughput: CorpusThroughput,
    pub measurements: Measurements,
}

#[derive(Debug, Serialize)]
pub struct CorpusThroughput {
    pub samples: u64,
    pub scope: &'static str,
    pub chunk_only: Timing,
    pub chunk_and_blake3: Timing,
}

impl Corpus {
    pub fn from_path(name: String, root: &Path) -> Result<Self> {
        Self::from_files(
            name,
            CorpusKind::DirectorySnapshot,
            collect_files(root, true)?,
        )
    }

    pub fn version_chain_from_path(name: String, root: &Path) -> Result<Self> {
        Self::from_files(name, CorpusKind::VersionChain, collect_files(root, false)?)
    }

    pub fn version_chain_from_git(
        name: String,
        repository: &Path,
        relative_path: &Path,
    ) -> Result<Self> {
        validate_relative_git_path(relative_path)?;
        let revisions = Command::new("git")
            .args(["-C"])
            .arg(repository)
            .args(["rev-list", "--reverse", "--max-count=32", "HEAD", "--"])
            .arg(relative_path)
            .output()
            .context("enumerate captured version chain")?;
        if !revisions.status.success() {
            bail!("git could not enumerate the captured version chain");
        }
        let revisions = String::from_utf8(revisions.stdout).context("git emitted non-UTF-8 IDs")?;
        let mut inputs = Vec::new();
        for revision in revisions.lines() {
            if revision.is_empty() || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("git emitted an invalid revision ID");
            }
            if !git_path_exists_at_revision(repository, relative_path, revision)? {
                continue;
            }
            let object = format!("{revision}:{}", relative_path.to_string_lossy());
            let version = Command::new("git")
                .args(["-C"])
                .arg(repository)
                .args(["show", &object])
                .output()
                .context("read captured version")?;
            if !version.status.success() {
                bail!(
                    "git could not read captured version: {}",
                    String::from_utf8_lossy(&version.stderr).trim()
                );
            }
            inputs.push(memory(version.stdout));
        }
        if inputs.len() < 2 {
            bail!("captured version chain must contain at least two readable versions");
        }
        Self::from_files(name, CorpusKind::VersionChain, inputs)
    }

    pub fn synthetic_adversarial() -> Self {
        let mebibyte = 1024 * 1024;
        let inputs = vec![
            memory(Vec::new()),
            memory(vec![0x5a]),
            memory(vec![0x7e; 4093]),
            memory(vec![0; 8 * mebibyte]),
            memory(vec![0xff; 8 * mebibyte]),
            memory(periodic_bytes(8 * mebibyte)),
            memory((0_u8..=u8::MAX).cycle().take(8 * mebibyte).collect()),
            memory(b"abcd".repeat(2 * mebibyte)),
            memory(pseudorandom_bytes(8 * mebibyte, 0x5eed_f00d_dead_beef)),
            memory(boundary_pressure(8 * mebibyte)),
        ];
        Self {
            name: "synthetic-adversarial-v1".to_owned(),
            kind: CorpusKind::SyntheticAdversarial,
            inputs,
        }
    }

    pub fn synthetic_version_chain() -> Self {
        Self {
            name: "synthetic-version-chain-v1".to_owned(),
            kind: CorpusKind::VersionChain,
            inputs: version_chain(),
        }
    }

    pub fn measure(&self, candidate: Candidate) -> Result<CandidateResult> {
        // Every timed file read is immediately re-hashed outside its timed
        // interval. The authoritative measurement that follows independently
        // validates the same baseline again.
        let (chunk_only, chunk_and_blake3) = self.measure_throughput_samples(&candidate)?;
        let started = Instant::now();
        let mut accumulator = Accumulator::default();
        for input in &self.inputs {
            let logical_bytes = input.logical_bytes();
            if logical_bytes <= u64::from(candidate.maximum_bytes) {
                let bytes = input.read_all()?;
                let observed = FileSnapshot::from_bytes(&bytes)?;
                input.validate_observation(observed)?;
                accumulator.add_file_identity(observed.logical_bytes, observed.identity)?;
                if !bytes.is_empty() {
                    accumulator.add_whole_record(&bytes)?;
                }
                continue;
            }

            match input {
                Input::File { path, snapshot } => {
                    let file = File::open(path)
                        .with_context(|| format!("open corpus input {}", path.display()))?;
                    let mut reader =
                        HashingReader::new(BufReader::with_capacity(READER_CAPACITY, file));
                    candidate.visit_records(&mut reader, |chunk, logical_chunks| {
                        accumulator.add_chunk_record(chunk, logical_chunks)
                    })?;
                    let observed = reader.finish();
                    snapshot.validate(observed)?;
                    accumulator.add_file_identity(observed.logical_bytes, observed.identity)?;
                },
                Input::Memory(bytes) => {
                    accumulator.add_file(bytes)?;
                    candidate
                        .visit_records(Cursor::new(bytes.as_ref()), |chunk, logical_chunks| {
                            accumulator.add_chunk_record(chunk, logical_chunks)
                        })?;
                },
            }
        }
        Ok(CandidateResult {
            corpus: self.name.clone(),
            corpus_kind: self.kind,
            candidate,
            throughput: CorpusThroughput {
                samples: u64::try_from(CORPUS_THROUGHPUT_SAMPLES)?,
                scope: self.throughput_scope(),
                chunk_only,
                chunk_and_blake3,
            },
            measurements: accumulator.finish(started.elapsed())?,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> CorpusKind {
        self.kind
    }

    pub fn visit_inputs<F>(&self, mut visit: F) -> Result<()>
    where
        F: FnMut(&[u8]) -> Result<()>,
    {
        for input in &self.inputs {
            let bytes = input.read_all()?;
            input.validate_observation(FileSnapshot::from_bytes(&bytes)?)?;
            visit(&bytes)?;
        }
        Ok(())
    }

    fn throughput_scope(&self) -> &'static str {
        if self
            .inputs
            .iter()
            .any(|input| matches!(input, Input::File { .. }))
        {
            "median of alternating end-to-end corpus traversals including file I/O and the whole-file policy"
        } else {
            "median of alternating in-memory corpus traversals including the whole-file policy"
        }
    }

    fn measure_throughput_samples(&self, candidate: &Candidate) -> Result<(Timing, Timing)> {
        let mut chunk_only = Vec::with_capacity(CORPUS_THROUGHPUT_SAMPLES);
        let mut chunk_and_blake3 = Vec::with_capacity(CORPUS_THROUGHPUT_SAMPLES);
        for sample in 0..CORPUS_THROUGHPUT_SAMPLES {
            if sample % 2 == 0 {
                chunk_only.push(self.measure_throughput(candidate, false)?);
                chunk_and_blake3.push(self.measure_throughput(candidate, true)?);
            } else {
                chunk_and_blake3.push(self.measure_throughput(candidate, true)?);
                chunk_only.push(self.measure_throughput(candidate, false)?);
            }
        }
        chunk_only.sort_unstable();
        chunk_and_blake3.sort_unstable();
        let logical_bytes = self.logical_bytes()?;
        let chunk_only_median = median_duration(&chunk_only)?;
        let chunk_and_blake3_median = median_duration(&chunk_and_blake3)?;
        Ok((
            timing(logical_bytes, chunk_only_median, chunk_only[0])?,
            timing(logical_bytes, chunk_and_blake3_median, chunk_and_blake3[0])?,
        ))
    }

    fn measure_throughput(&self, candidate: &Candidate, hash_records: bool) -> Result<Duration> {
        let mut elapsed = Duration::ZERO;
        let mut guard = [0_u8; 32];
        for input in &self.inputs {
            let started = Instant::now();
            let observed_bytes = match input {
                Input::File { path, .. } => {
                    let file = File::open(path).with_context(|| {
                        format!("open corpus throughput input {}", path.display())
                    })?;
                    measure_reader(
                        BufReader::with_capacity(READER_CAPACITY, file),
                        input.logical_bytes(),
                        candidate,
                        hash_records,
                        &mut guard,
                    )?
                },
                Input::Memory(bytes) => measure_reader(
                    Cursor::new(bytes.as_ref()),
                    input.logical_bytes(),
                    candidate,
                    hash_records,
                    &mut guard,
                )?,
            };
            elapsed = elapsed
                .checked_add(started.elapsed())
                .ok_or_else(|| anyhow::anyhow!("corpus throughput duration overflow"))?;
            if observed_bytes != input.logical_bytes() {
                bail!(
                    "corpus input changed during throughput measurement: expected {} bytes, read {observed_bytes}",
                    input.logical_bytes()
                );
            }
            input.validate_current_file()?;
        }
        black_box(guard);
        Ok(elapsed)
    }

    fn logical_bytes(&self) -> Result<u64> {
        self.inputs.iter().try_fold(0_u64, |total, input| {
            total
                .checked_add(input.logical_bytes())
                .ok_or_else(|| anyhow::anyhow!("corpus logical byte count overflow"))
        })
    }

    fn from_files(name: String, kind: CorpusKind, inputs: Vec<Input>) -> Result<Self> {
        validate_label(&name)?;
        if inputs.is_empty() {
            bail!("corpus {name:?} contains no regular files");
        }
        Ok(Self { name, kind, inputs })
    }
}

fn measure_reader<R: Read>(
    reader: R,
    logical_bytes: u64,
    candidate: &Candidate,
    hash_records: bool,
    guard: &mut [u8; 32],
) -> Result<u64> {
    let mut reader = CountingReader::new(reader);
    if logical_bytes <= u64::from(candidate.maximum_bytes) {
        let mut buffer = vec![0_u8; READER_CAPACITY];
        let mut hasher = hash_records.then(blake3::Hasher::new);
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            if let Some(hasher) = &mut hasher {
                hasher.update(&buffer[..read]);
            } else {
                guard[0] ^= buffer[0];
                let last = read
                    .checked_sub(1)
                    .expect("a non-empty read has a final byte");
                guard[1] ^= buffer[last];
            }
        }
        if logical_bytes != 0
            && let Some(hasher) = hasher
        {
            fold_digest(guard, hasher.finalize().as_bytes());
        }
    } else {
        candidate.visit_records(&mut reader, |bytes, logical_chunks| {
            if hash_records {
                fold_digest(guard, blake3::hash(bytes).as_bytes());
            } else {
                guard[0] ^= bytes.first().copied().unwrap_or_default();
                guard[1] ^= bytes.last().copied().unwrap_or_default();
                guard[2] ^= u8::try_from(logical_chunks & 0xff)?;
            }
            Ok(())
        })?;
    }
    Ok(reader.bytes_read)
}

struct CountingReader<R> {
    inner: R,
    bytes_read: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.bytes_read = self
            .bytes_read
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("corpus byte count overflow"))?;
        Ok(read)
    }
}

struct HashingReader<R> {
    inner: R,
    hasher: blake3::Hasher,
    bytes_read: u64,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: blake3::Hasher::new(),
            bytes_read: 0,
        }
    }

    fn finish(self) -> FileSnapshot {
        FileSnapshot {
            logical_bytes: self.bytes_read,
            identity: *self.hasher.finalize().as_bytes(),
        }
    }
}

impl FileSnapshot {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            logical_bytes: u64::try_from(bytes.len())?,
            identity: *blake3::hash(bytes).as_bytes(),
        })
    }

    fn validate(self, observed: Self) -> Result<()> {
        if self != observed {
            bail!(
                "corpus input changed after the baseline snapshot; rerun against immutable inputs"
            );
        }
        Ok(())
    }
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.hasher.update(&buffer[..read]);
        self.bytes_read = self
            .bytes_read
            .checked_add(u64::try_from(read).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("corpus byte count overflow"))?;
        Ok(read)
    }
}

impl Input {
    fn logical_bytes(&self) -> u64 {
        match self {
            Self::File { snapshot, .. } => snapshot.logical_bytes,
            Self::Memory(bytes) => {
                u64::try_from(bytes.len()).expect("in-memory fixture length fits in u64")
            },
        }
    }

    fn read_all(&self) -> Result<Vec<u8>> {
        match self {
            Self::File { path, .. } => {
                fs::read(path).with_context(|| format!("read corpus input {}", path.display()))
            },
            Self::Memory(bytes) => Ok(bytes.to_vec()),
        }
    }

    fn validate_observation(&self, observed: FileSnapshot) -> Result<()> {
        match self {
            Self::File { snapshot, .. } => snapshot.validate(observed),
            Self::Memory(bytes) => FileSnapshot::from_bytes(bytes)?.validate(observed),
        }
    }

    fn validate_current_file(&self) -> Result<()> {
        if let Self::File { path, snapshot } = self {
            snapshot.validate(snapshot_file(path)?)?;
        }
        Ok(())
    }
}

fn collect_files(root: &Path, recursive: bool) -> Result<Vec<Input>> {
    let maximum_depth = if recursive { usize::MAX } else { 1 };
    let walker = WalkDir::new(root)
        .max_depth(maximum_depth)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            include_walker_entry(
                recursive,
                entry.depth(),
                entry.file_type().is_dir(),
                &entry.file_name().to_string_lossy(),
            )
        });
    let mut inputs = Vec::new();
    for entry in walker {
        let entry = entry.with_context(|| format!("walk corpus {}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.into_path();
        let snapshot = snapshot_file(&path)?;
        inputs.push(Input::File { path, snapshot });
    }
    inputs.sort_by(|left, right| input_path(left).cmp(&input_path(right)));
    Ok(inputs)
}

fn include_walker_entry(recursive: bool, depth: usize, is_directory: bool, name: &str) -> bool {
    !recursive || depth != 1 || !is_directory || !EXCLUDED_TOP_LEVEL_DIRECTORIES.contains(&name)
}

fn snapshot_file(path: &Path) -> Result<FileSnapshot> {
    let file = File::open(path)
        .with_context(|| format!("open corpus input for snapshot {}", path.display()))?;
    let expected_bytes = file
        .metadata()
        .with_context(|| format!("stat corpus input {}", path.display()))?
        .len();
    let mut reader = HashingReader::new(BufReader::with_capacity(READER_CAPACITY, file));
    std::io::copy(&mut reader, &mut std::io::sink())
        .with_context(|| format!("snapshot corpus input {}", path.display()))?;
    let snapshot = reader.finish();
    if snapshot.logical_bytes != expected_bytes {
        bail!("corpus input changed while its baseline snapshot was captured");
    }
    Ok(snapshot)
}

fn validate_label(label: &str) -> Result<()> {
    if label.is_empty()
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        bail!("corpus label must contain only lowercase ASCII letters, digits, and hyphens");
    }
    Ok(())
}

fn validate_relative_git_path(path: &Path) -> Result<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
        || path.to_string_lossy().contains(':')
    {
        bail!("git history path must be a relative in-repository path");
    }
    Ok(())
}

fn git_path_exists_at_revision(
    repository: &Path,
    relative_path: &Path,
    revision: &str,
) -> Result<bool> {
    let tree = Command::new("git")
        .args(["-C"])
        .arg(repository)
        .args(["ls-tree", "--full-tree", revision, "--"])
        .arg(relative_path)
        .output()
        .context("inspect captured version path")?;
    if !tree.status.success() {
        bail!(
            "git could not inspect captured version: {}",
            String::from_utf8_lossy(&tree.stderr).trim()
        );
    }
    Ok(!tree.stdout.is_empty())
}

fn input_path(input: &Input) -> Option<&Path> {
    match input {
        Input::File { path, .. } => Some(path),
        Input::Memory(_) => None,
    }
}

fn memory(bytes: Vec<u8>) -> Input {
    Input::Memory(Arc::from(bytes))
}

fn boundary_pressure(length: usize) -> Vec<u8> {
    let mut bytes = pseudorandom_bytes(length, 0x9f4a_7c15_6a09_e667);
    for window in bytes.chunks_mut(64 * 1024) {
        if window.len() >= 64 {
            window[..32].fill(0);
            window[32..64].fill(0xff);
        }
    }
    bytes
}

fn version_chain() -> Vec<Input> {
    let base = pseudorandom_bytes(4 * 1024 * 1024, 0x1234_5678_90ab_cdef);
    let mut versions = Vec::new();
    for generation in 0..16_usize {
        let mut version = base.clone();
        let insertion = generation
            .checked_mul(4093)
            .and_then(|offset| offset.checked_add(1_000_000))
            .expect("version-chain offset is bounded by constants");
        let marker = format!("astrid-version-{generation:02}");
        version.splice(insertion..insertion, marker.bytes());
        let replacement = generation
            .checked_mul(8191)
            .and_then(|offset| offset.checked_add(2_000_000))
            .expect("version-chain replacement is bounded by constants");
        let end = replacement
            .checked_add(256)
            .expect("version-chain replacement is bounded by constants");
        version[replacement..end].fill(u8::try_from(generation).expect("generation fits in u8"));
        versions.push(memory(version));
    }
    versions
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algorithm::candidates;

    #[test]
    fn synthetic_corpora_are_deterministic_except_for_wall_time() {
        let candidate = candidates(8).unwrap().remove(1);
        let first = Corpus::synthetic_version_chain()
            .measure(candidate.clone())
            .unwrap();
        let second = Corpus::synthetic_version_chain()
            .measure(candidate)
            .unwrap();
        assert_eq!(
            first.measurements.logical_bytes,
            second.measurements.logical_bytes
        );
        assert_eq!(
            first.measurements.total_chunks,
            second.measurements.total_chunks
        );
        assert_eq!(
            first.measurements.unique_chunks,
            second.measurements.unique_chunks
        );
        assert_eq!(
            first.measurements.chunk_deduplication,
            second.measurements.chunk_deduplication
        );
        assert_eq!(first.throughput.samples, 4);
        assert!(first.throughput.chunk_only.median_bytes_per_second > 0);
        assert!(first.throughput.chunk_and_blake3.median_bytes_per_second > 0);
    }

    #[test]
    fn corpus_labels_cannot_smuggle_paths_into_reports() {
        for invalid in ["", "../home", "Users-Joshua", "contains space", "a/b"] {
            assert!(validate_label(invalid).is_err());
        }
        validate_label("agent-state").unwrap();
    }

    #[test]
    fn sensitive_names_exclude_only_top_level_snapshot_directories() {
        for name in EXCLUDED_TOP_LEVEL_DIRECTORIES {
            assert!(!include_walker_entry(true, 1, true, name));
            assert!(include_walker_entry(true, 1, false, name));
            assert!(include_walker_entry(false, 1, true, name));
            assert!(include_walker_entry(true, 2, true, name));
        }
    }

    #[test]
    fn throughput_scope_distinguishes_file_and_memory_inputs() {
        let in_memory = Corpus::synthetic_adversarial();
        assert!(in_memory.throughput_scope().contains("in-memory"));

        let file_backed = Corpus {
            name: "file-backed".to_owned(),
            kind: CorpusKind::DirectorySnapshot,
            inputs: vec![Input::File {
                path: PathBuf::from("not-opened-by-this-test"),
                snapshot: FileSnapshot {
                    logical_bytes: 0,
                    identity: [0; 32],
                },
            }],
        };
        assert!(file_backed.throughput_scope().contains("file I/O"));
    }

    #[test]
    fn git_history_paths_stay_inside_the_repository() {
        for invalid in ["/tmp/file", "../file", "dir/../../file", "revision:file"] {
            assert!(validate_relative_git_path(Path::new(invalid)).is_err());
        }
        validate_relative_git_path(Path::new("crates/storage/src/lib.rs")).unwrap();
    }

    #[test]
    fn git_history_distinguishes_absent_paths_from_git_failures() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        assert!(git_path_exists_at_revision(&repository, Path::new("Cargo.lock"), "HEAD").unwrap());
        assert!(
            !git_path_exists_at_revision(&repository, Path::new("definitely-not-present"), "HEAD")
                .unwrap()
        );
        assert!(
            git_path_exists_at_revision(&repository, Path::new("Cargo.lock"), "not-a-revision")
                .is_err()
        );
    }

    #[test]
    fn empty_files_do_not_mint_chunk_objects_or_references() {
        let corpus = Corpus {
            name: "empty-file-regression".to_owned(),
            kind: CorpusKind::SyntheticAdversarial,
            inputs: vec![memory(Vec::new()), memory(vec![0x5a])],
        };
        let measurements = corpus
            .measure(candidates(8).unwrap().remove(0))
            .unwrap()
            .measurements;
        assert_eq!(measurements.files, 2);
        assert_eq!(measurements.total_chunks, 1);
        assert_eq!(measurements.representation_records, 1);
        assert_eq!(measurements.unique_chunks, 1);
    }

    #[test]
    fn same_length_changes_fail_snapshot_validation() {
        let original = FileSnapshot::from_bytes(b"same").unwrap();
        let changed = FileSnapshot::from_bytes(b"size").unwrap();
        assert_eq!(original.logical_bytes, changed.logical_bytes);
        assert!(original.validate(changed).is_err());
    }

    #[test]
    fn timed_file_validation_detects_same_length_changes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input.bin");
        fs::write(&path, b"same").unwrap();
        let input = Input::File {
            path: path.clone(),
            snapshot: snapshot_file(&path).unwrap(),
        };

        fs::write(path, b"size").unwrap();

        assert!(input.validate_current_file().is_err());
    }
}
