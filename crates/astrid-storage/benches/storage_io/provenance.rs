use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::process::Command;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::BenchResult;

#[derive(Debug, Serialize)]
pub(super) struct RunProvenance {
    repository: &'static str,
    git_revision: String,
    git_tree: GitTreeState,
    executable_argv: Vec<String>,
    executable: ExecutableEvidence,
    host: HostEvidence,
}

impl RunProvenance {
    /// Capture provenance for the benchmark data directory rather than for the
    /// checkout containing the benchmark executable. The measured root is the
    /// storage surface whose filesystem and volume kind qualify every metric.
    pub(super) fn capture_for_root(measured_root: &Path) -> BenchResult<Self> {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        let git_revision = git_output(manifest, &["rev-parse", "--verify", "HEAD"])?;
        let status = git_output(
            manifest,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?;
        let dirty_entries = status
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let executable_path = env::current_exe()
            .map_err(|error| format!("failed to locate benchmark executable: {error}"))?;
        let executable = hash_executable(&executable_path)?;
        let filesystem = filesystem_type(measured_root).unwrap_or_else(|_| "unknown".to_owned());

        Ok(Self::from_captured_evidence(
            git_revision,
            dirty_entries,
            env::args().collect(),
            executable,
            HostEvidence::captured(machine_class(), filesystem, uname()),
        ))
    }

    #[allow(dead_code)]
    pub(super) fn from_evidence(
        git_revision: String,
        dirty_entries: Vec<String>,
        executable_argv: Vec<String>,
        executable_bytes: u64,
        executable_sha256: String,
    ) -> Self {
        Self::from_captured_evidence(
            git_revision,
            dirty_entries,
            executable_argv,
            ExecutableEvidence {
                bytes: executable_bytes,
                sha256: executable_sha256,
            },
            HostEvidence::unknown(),
        )
    }

    fn from_captured_evidence(
        git_revision: String,
        dirty_entries: Vec<String>,
        executable_argv: Vec<String>,
        executable: ExecutableEvidence,
        host: HostEvidence,
    ) -> Self {
        let git_tree = if dirty_entries.is_empty() {
            GitTreeState::Clean
        } else {
            GitTreeState::Dirty {
                porcelain_v1: dirty_entries,
            }
        };
        Self {
            repository: "astrid-runtime/astrid",
            git_revision,
            git_tree,
            executable_argv,
            executable,
            host,
        }
    }

    pub(super) fn is_clean(&self) -> bool {
        matches!(self.git_tree, GitTreeState::Clean)
    }

    pub(super) fn revision(&self) -> &str {
        &self.git_revision
    }

    pub(super) fn describe_host(&self) -> String {
        format!(
            "machine_class={} filesystem={} volume_kind={} uname={}",
            self.host.machine_class,
            self.host.filesystem,
            self.host.volume_kind.as_str(),
            self.host.uname
        )
    }
}

#[derive(Debug, Serialize)]
struct ExecutableEvidence {
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct HostEvidence {
    machine_class: String,
    filesystem: String,
    volume_kind: VolumeKind,
    uname: String,
}

impl HostEvidence {
    #[allow(dead_code)]
    fn unknown() -> Self {
        Self {
            machine_class: "unknown".to_owned(),
            filesystem: "unknown".to_owned(),
            volume_kind: VolumeKind::Unknown,
            uname: "unknown".to_owned(),
        }
    }

    fn captured(machine_class: String, filesystem: String, uname: String) -> Self {
        Self {
            machine_class,
            volume_kind: VolumeKind::from_filesystem(&filesystem),
            filesystem,
            uname,
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum GitTreeState {
    Clean,
    Dirty { porcelain_v1: Vec<String> },
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum VolumeKind {
    HostPath,
    ContainerOverlay,
    Unknown,
}

impl VolumeKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::HostPath => "host_path",
            Self::ContainerOverlay => "container_overlay",
            Self::Unknown => "unknown",
        }
    }

    fn from_filesystem(filesystem: &str) -> Self {
        let filesystem = filesystem.trim().to_ascii_lowercase();
        if filesystem.is_empty() || filesystem == "unknown" {
            return Self::Unknown;
        }
        if filesystem.contains("overlay") || filesystem == "aufs" {
            Self::ContainerOverlay
        } else {
            Self::HostPath
        }
    }
}

fn machine_class() -> String {
    env::var("ASTRID_BENCH_MACHINE_CLASS")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| format!("local:{}-{}", env::consts::OS, env::consts::ARCH))
}

#[cfg(target_os = "linux")]
fn filesystem_type(path: &Path) -> BenchResult<String> {
    let mut command = Command::new("stat");
    command.args(["-f", "-c", "%T"]).arg(path);
    command_text(command, "Linux filesystem type")
}

#[cfg(target_os = "macos")]
fn filesystem_type(path: &Path) -> BenchResult<String> {
    let mut df = Command::new("df");
    df.args(["-P"]).arg(path);
    let Some(device) = command_text(df, "macOS filesystem device")?
        .lines()
        .nth(1)
        .and_then(|line| line.split_whitespace().next())
        .map(str::to_owned)
    else {
        return Err("macOS df output did not contain a filesystem device".into());
    };
    let mounts = command_text(Command::new("mount"), "macOS mount table")?;
    let filesystem = mounts.lines().find_map(|line| {
        let (mounted_device, details) = line.split_once(" on ")?;
        if mounted_device != device {
            return None;
        }
        let (_, options) = details.rsplit_once(" (")?;
        let filesystem = options.strip_suffix(')')?.split(',').next()?.trim();
        (!filesystem.is_empty()).then_some(filesystem.to_owned())
    });
    match filesystem {
        Some(filesystem) => Ok(filesystem),
        None => Err(format!("macOS mount table did not identify filesystem for {device}").into()),
    }
}

#[cfg(target_os = "windows")]
fn filesystem_type(path: &Path) -> BenchResult<String> {
    let mut command = Command::new("fsutil");
    command.args(["fsinfo", "volumeinfo"]).arg(path);
    let output = command_text(command, "Windows filesystem type")?;
    match output.lines().find_map(|line| {
        let (label, value) = line.split_once(':')?;
        label
            .trim()
            .eq_ignore_ascii_case("File System Name")
            .then_some(value.trim().to_owned())
    }) {
        Some(filesystem) if !filesystem.is_empty() => Ok(filesystem),
        _ => Err("fsutil output did not contain a filesystem name".into()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn filesystem_type(_path: &Path) -> BenchResult<String> {
    Ok("unknown".to_owned())
}

#[cfg(unix)]
fn uname() -> String {
    let mut command = Command::new("uname");
    command.arg("-a");
    command_text(command, "uname")
        .unwrap_or_else(|_| format!("{} {}", env::consts::OS, env::consts::ARCH))
}

#[cfg(not(unix))]
fn uname() -> String {
    format!("{} {}", env::consts::OS, env::consts::ARCH)
}

fn command_text(mut command: Command, description: &str) -> BenchResult<String> {
    let output = command.output().map_err(|error| {
        format!("failed to execute {description} for benchmark provenance: {error}")
    })?;
    if !output.status.success() {
        return Err(format!(
            "{description} failed while capturing benchmark provenance: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let value = String::from_utf8(output.stdout)
        .map_err(|error| format!("{description} output was not UTF-8: {error}"))?;
    let value = value.trim();
    if value.is_empty() {
        return Err(format!("{description} returned empty output").into());
    }
    Ok(value.to_owned())
}

fn git_output(working_directory: &Path, arguments: &[&str]) -> BenchResult<String> {
    let output = Command::new("git")
        .args(arguments)
        .current_dir(working_directory)
        .output()
        .map_err(|error| format!("failed to execute git for benchmark provenance: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed while capturing benchmark provenance: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    String::from_utf8(output.stdout)
        .map(|value| value.trim().to_owned())
        .map_err(|error| format!("git provenance output was not UTF-8: {error}").into())
}

fn hash_executable(path: &Path) -> BenchResult<ExecutableEvidence> {
    let file = File::open(path).map_err(|error| {
        format!(
            "failed to open benchmark executable {}: {error}",
            path.display()
        )
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut bytes = 0_u64;
    loop {
        let read = reader.read(&mut buffer).map_err(|error| {
            format!(
                "failed to hash benchmark executable {}: {error}",
                path.display()
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        let read_bytes = u64::try_from(read)
            .map_err(|_| "benchmark executable read length does not fit in u64")?;
        bytes = bytes
            .checked_add(read_bytes)
            .ok_or("benchmark executable length overflowed u64")?;
    }
    Ok(ExecutableEvidence {
        bytes,
        sha256: hex::encode(hasher.finalize()),
    })
}
