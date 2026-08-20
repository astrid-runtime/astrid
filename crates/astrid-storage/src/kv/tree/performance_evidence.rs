//! Machine-readable evidence for the ignored native/`SurrealKV` comparisons.
//!
//! The recorder is intentionally small and test-only.  It captures the exact
//! executable and source tree that produced a run, while keeping the measured
//! samples and derived ratios separate from the human-readable diagnostics.

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use sha2::{Digest, Sha256};

const OUTPUT_ENV: &str = "ASTRID_STORAGE_PERF_OUTPUT";
const FORMAT: &str = "astrid-storage-kv-microbench-v1";
// Mirrors KvReadCacheConfig::reserved_64_mib in hot_cache.rs.
const CACHE_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const CACHE_OWNER_BYTES: u64 = 4 * 1024 * 1024;
const CACHE_OWNER_LIMIT: u64 = 4_096;
const CACHE_ENTRIES_PER_OWNER: u64 = 4_096;
const WAL_CHECKPOINT_BYTES: u64 = 256 * 1024 * 1024;

/// Which operating policy was used by a comparison workload.
#[derive(Clone, Copy)]
pub(super) enum WorkloadPolicy {
    /// Hot reads use the disposable point-read cache and leave the transaction
    /// WAL off; this isolates the cache/read path rather than strict writes.
    HotReads,
    /// Strict writes and batches use the transaction WAL; this measures the
    /// acknowledged durable publication path.
    StrictWrites,
}

impl WorkloadPolicy {
    fn name(self) -> &'static str {
        match self {
            Self::HotReads => "hot_reads",
            Self::StrictWrites => "strict_writes_and_batches",
        }
    }

    fn wal(self) -> WalPolicyEvidence {
        match self {
            Self::HotReads => WalPolicyEvidence {
                mode: "disabled",
                checkpoint_bytes: None,
                comment: "hot reads use cache; WAL off",
            },
            Self::StrictWrites => WalPolicyEvidence {
                mode: "enabled",
                checkpoint_bytes: Some(WAL_CHECKPOINT_BYTES),
                comment: "strict writes/batches use WAL on",
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct EvidenceEnvelope {
    format: &'static str,
    payload_digest: PayloadDigest,
    payload_json: String,
    payload: Report,
}

#[derive(Debug, Serialize)]
struct PayloadDigest {
    algorithm: &'static str,
    scope: &'static str,
    hex: String,
}

#[derive(Debug, Serialize)]
struct Report {
    provenance: Provenance,
    host: HostEvidence,
    payload: Payload,
}

#[derive(Debug, Serialize)]
struct Provenance {
    repository: &'static str,
    git_revision: String,
    dirty: bool,
    git_tree: GitTreeState,
    executable_argv: Vec<String>,
    executable: ExecutableEvidence,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum GitTreeState {
    Clean,
    Dirty { porcelain_v1: Vec<String> },
}

#[derive(Clone, Debug, Serialize)]
struct ExecutableEvidence {
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct HostEvidence {
    machine_class: String,
    filesystem: String,
    volume_kind: String,
    uname: String,
}

#[derive(Debug, Serialize)]
struct Payload {
    test: String,
    workload: String,
    wal_policy: WalPolicyEvidence,
    kv_cache_policy: KvCachePolicyEvidence,
    scope_notes: Vec<&'static str>,
    samples: Vec<SampleEvidence>,
    ratios: Vec<RatioEvidence>,
}

#[derive(Debug, Serialize)]
struct WalPolicyEvidence {
    mode: &'static str,
    checkpoint_bytes: Option<u64>,
    comment: &'static str,
}

#[derive(Debug, Serialize)]
struct KvCachePolicyEvidence {
    mode: &'static str,
    total_bytes: u64,
    per_owner_bytes: u64,
    owner_limit: u64,
    entries_per_owner: u64,
    comment: &'static str,
}

#[derive(Debug, Serialize)]
struct SampleEvidence {
    name: String,
    ordinal: usize,
    dimensions: BTreeMap<String, String>,
    metrics: BTreeMap<String, f64>,
}

#[derive(Debug, Serialize)]
struct RatioEvidence {
    name: String,
    numerator: f64,
    denominator: f64,
    value: Option<f64>,
}

/// Collect and optionally persist one ignored performance-test report.
pub(super) struct EvidenceRecorder {
    report: Report,
}

impl EvidenceRecorder {
    pub(super) fn new(test: &str, volume: &Path, policy: WorkloadPolicy) -> Self {
        let provenance = Provenance::capture();
        let host = HostEvidence::capture(volume);
        Self {
            report: Report {
                provenance,
                host,
                payload: Payload {
                    test: test.to_owned(),
                    workload: policy.name().to_owned(),
                    wal_policy: policy.wal(),
                    kv_cache_policy: KvCachePolicyEvidence {
                        mode: "reserved_64_mib",
                        total_bytes: CACHE_TOTAL_BYTES,
                        per_owner_bytes: CACHE_OWNER_BYTES,
                        owner_limit: CACHE_OWNER_LIMIT,
                        entries_per_owner: CACHE_ENTRIES_PER_OWNER,
                        comment: "disposable point-read cache; not recovery state",
                    },
                    scope_notes: vec![
                        "overlay-before-fold is group_tests correctness, not a benchmark claim",
                        "all benchmark stores use tempfile volumes; no ~/.astrid state is touched",
                    ],
                    samples: Vec::new(),
                    ratios: Vec::new(),
                },
            },
        }
    }

    pub(super) fn sample(
        &mut self,
        name: &str,
        ordinal: usize,
        dimensions: &[(&str, String)],
        metrics: &[(&str, f64)],
    ) {
        self.report.payload.samples.push(SampleEvidence {
            name: name.to_owned(),
            ordinal,
            dimensions: dimensions
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone()))
                .collect(),
            metrics: metrics
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect(),
        });
    }

    /// Record a ratio without making it a pass/fail assertion.
    pub(super) fn ratio(&mut self, name: &str, numerator: f64, denominator: f64) {
        self.report.payload.ratios.push(RatioEvidence {
            name: name.to_owned(),
            numerator,
            denominator,
            value: (denominator != 0.0).then_some(numerator / denominator),
        });
    }

    /// Write the v1 envelope only when the caller explicitly requests it.
    pub(super) fn finish(self) {
        let Some(path) = output_path(&self.report.payload.test) else {
            return;
        };
        let encoded = encode(self.report);
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).expect("create KV performance evidence parent");
        }
        fs::write(&path, encoded).expect("write KV performance evidence");
        eprintln!("machine-readable KV report: {}", path.display());
    }
}

fn output_path(test: &str) -> Option<PathBuf> {
    let raw = env::var_os(OUTPUT_ENV).filter(|value| !value.is_empty())?;
    let path = PathBuf::from(raw);
    if path.extension().is_none() {
        return Some(path.join(format!("{test}.json")));
    }
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("kv-microbench");
    Some(path.with_file_name(format!("{stem}-{test}.json")))
}

fn encode(report: Report) -> Vec<u8> {
    let payload_json = serde_json::to_string(&report).expect("serialize KV performance payload");
    let digest = PayloadDigest {
        algorithm: "sha-256",
        scope: "utf8:payload_json:astrid-storage-kv-microbench-v1",
        hex: hex::encode(Sha256::digest(payload_json.as_bytes())),
    };
    serde_json::to_vec_pretty(&EvidenceEnvelope {
        format: FORMAT,
        payload_digest: digest,
        payload_json,
        payload: report,
    })
    .expect("serialize KV performance evidence")
}

impl Provenance {
    fn capture() -> Self {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let git_sha = git_output(manifest, &["rev-parse", "--verify", "HEAD"]);
        let status = git_output(
            manifest,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        );
        let dirty_entries = status
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let dirty = !dirty_entries.is_empty();
        let git_tree = if dirty {
            GitTreeState::Dirty {
                porcelain_v1: dirty_entries,
            }
        } else {
            GitTreeState::Clean
        };
        let executable_argv = env::args().collect::<Vec<_>>();
        let executable = env::current_exe()
            .ok()
            .map_or_else(ExecutableEvidence::missing, |path| hash_executable(&path));
        Self {
            repository: "astrid-runtime/astrid",
            git_revision: git_sha,
            dirty,
            git_tree,
            executable_argv,
            executable,
        }
    }
}

impl ExecutableEvidence {
    fn missing() -> Self {
        Self {
            bytes: 0,
            sha256: String::new(),
        }
    }
}

impl HostEvidence {
    fn capture(volume: &Path) -> Self {
        let filesystem = filesystem_type(volume);
        Self {
            machine_class: machine_class(),
            volume_kind: volume_kind(&filesystem).to_owned(),
            filesystem,
            uname: uname(),
        }
    }
}

fn machine_class() -> String {
    env::var("ASTRID_BENCH_MACHINE_CLASS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("local:{}-{}", env::consts::OS, env::consts::ARCH))
}

fn volume_kind(filesystem: &str) -> &'static str {
    let filesystem = filesystem.trim().to_ascii_lowercase();
    if filesystem.is_empty() || filesystem == "unknown" {
        "unknown"
    } else if filesystem.contains("overlay") || filesystem == "aufs" {
        "container_overlay"
    } else {
        "host_path"
    }
}

fn git_output(directory: &Path, arguments: &[&str]) -> String {
    Command::new("git")
        .args(arguments)
        .current_dir(directory)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map_or_else(|| "unknown".to_owned(), |value| value.trim().to_owned())
}

fn hash_executable(path: &Path) -> ExecutableEvidence {
    let Ok(file) = fs::File::open(path) else {
        return ExecutableEvidence::missing();
    };
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut bytes = 0_u64;
    loop {
        let Ok(read) = reader.read(&mut buffer) else {
            return ExecutableEvidence::missing();
        };
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        let Ok(read) = u64::try_from(read) else {
            return ExecutableEvidence::missing();
        };
        let Some(total) = bytes.checked_add(read) else {
            return ExecutableEvidence::missing();
        };
        bytes = total;
    }
    ExecutableEvidence {
        bytes,
        sha256: hex::encode(hasher.finalize()),
    }
}

fn filesystem_type(path: &Path) -> String {
    for arguments in [["-f", "%T"], ["-c", "%T"]] {
        let Ok(output) = Command::new("stat").args(arguments).arg(path).output() else {
            continue;
        };
        if output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            if !value.is_empty() {
                return value;
            }
        }
    }
    "unknown".to_owned()
}

fn uname() -> String {
    Command::new("uname")
        .arg("-a")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map_or_else(
            || format!("{} {}", env::consts::OS, env::consts::ARCH),
            |output| String::from_utf8_lossy(&output.stdout).trim().to_owned(),
        )
}
