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
}

impl RunProvenance {
    pub(super) fn capture() -> BenchResult<Self> {
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

        Ok(Self::from_evidence(
            git_revision,
            dirty_entries,
            env::args().collect(),
            executable.bytes,
            executable.sha256,
        ))
    }

    pub(super) fn from_evidence(
        git_revision: String,
        dirty_entries: Vec<String>,
        executable_argv: Vec<String>,
        executable_bytes: u64,
        executable_sha256: String,
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
            executable: ExecutableEvidence {
                bytes: executable_bytes,
                sha256: executable_sha256,
            },
        }
    }

    pub(super) fn is_clean(&self) -> bool {
        matches!(self.git_tree, GitTreeState::Clean)
    }

    pub(super) fn revision(&self) -> &str {
        &self.git_revision
    }
}

#[derive(Debug, Serialize)]
struct ExecutableEvidence {
    bytes: u64,
    sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum GitTreeState {
    Clean,
    Dirty { porcelain_v1: Vec<String> },
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
