//! Optional host-owned generation marker for long-lived MCP sessions.
//!
//! Distributors may bind a host plugin snapshot to an immutable one-line
//! marker without teaching Astrid the distributor's release protocol. Astrid
//! only enforces byte-exact identity and stops touching the daemon once it
//! changes.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

pub(super) const HOST_GENERATION_ENV: &str = "ASTRID_HOST_GENERATION";
pub(super) const HOST_GENERATION_FILE_ENV: &str = "ASTRID_HOST_GENERATION_FILE";
const MAX_HOST_GENERATION_LEN: usize = 512;

#[derive(Debug, Clone, Default)]
pub(super) struct HostGenerationFence(Option<ConfiguredFence>);

#[derive(Debug, Clone)]
struct ConfiguredFence {
    path: PathBuf,
    expected: String,
}

impl HostGenerationFence {
    pub(super) fn from_environment() -> Result<Self> {
        let expected = std::env::var_os(HOST_GENERATION_ENV);
        let path = std::env::var_os(HOST_GENERATION_FILE_ENV);
        match (expected, path) {
            (None, None) => Ok(Self::default()),
            (Some(expected), Some(path)) => {
                let expected = expected
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("{HOST_GENERATION_ENV} is not valid UTF-8"))?;
                Self::configured(PathBuf::from(path), expected)
            },
            _ => anyhow::bail!(
                "{HOST_GENERATION_ENV} and {HOST_GENERATION_FILE_ENV} must be set together"
            ),
        }
    }

    fn configured(path: PathBuf, expected: String) -> Result<Self> {
        if !path.is_absolute() {
            anyhow::bail!("{HOST_GENERATION_FILE_ENV} must be an absolute path");
        }
        if expected.is_empty() || expected.len() > MAX_HOST_GENERATION_LEN {
            anyhow::bail!("{HOST_GENERATION_ENV} has an invalid length");
        }
        if !expected.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'-' | b':' | b'+' | b'@' | b'/')
        }) {
            anyhow::bail!("{HOST_GENERATION_ENV} contains a non-canonical character");
        }
        Ok(Self(Some(ConfiguredFence { path, expected })))
    }

    pub(super) fn validate(&self) -> Result<(), HostGenerationMismatch> {
        let Some(configured) = &self.0 else {
            return Ok(());
        };
        let actual = read_marker(&configured.path).ok();
        if actual.as_deref() == Some(configured.expected.as_str()) {
            return Ok(());
        }
        Err(HostGenerationMismatch {
            expected: configured.expected.clone(),
            actual: actual.unwrap_or_else(|| "missing or invalid".to_owned()),
        })
    }
}

fn read_marker(path: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(path).with_context(|| {
        format!(
            "could not inspect host generation marker {}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        let target_metadata = fs::metadata(path).with_context(|| {
            format!(
                "could not resolve host generation marker {}",
                path.display()
            )
        })?;
        if !target_metadata.is_file() {
            anyhow::bail!("host generation marker does not resolve to a regular file");
        }
    } else if !metadata.is_file() {
        anyhow::bail!("host generation marker is not a regular file");
    }
    let bytes = fs::read(path)?;
    if bytes.len() > MAX_HOST_GENERATION_LEN + 1 {
        anyhow::bail!("host generation marker is too large");
    }
    let value = std::str::from_utf8(&bytes).context("host generation marker is not UTF-8")?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.contains(['\n', '\r']) {
        anyhow::bail!("host generation marker must contain exactly one line");
    }
    Ok(value.to_owned())
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("host generation changed (expected {expected}, found {actual})")]
pub(super) struct HostGenerationMismatch {
    expected: String,
    actual: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(case: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "astrid-host-generation-{case}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn exact_marker_matches_and_changed_marker_is_terminal() {
        let path = fixture("changed");
        fs::write(&path, "oracle:codex:0.2.6:astrid:0.10.5:source\n").unwrap();
        let fence = HostGenerationFence::configured(
            path.clone(),
            "oracle:codex:0.2.6:astrid:0.10.5:source".to_owned(),
        )
        .unwrap();
        assert!(fence.validate().is_ok());
        fs::write(&path, "oracle:codex:0.2.7:astrid:0.10.5:source\n").unwrap();
        assert!(fence.validate().is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn missing_marker_fails_closed() {
        let path = fixture("missing");
        let _ = fs::remove_file(&path);
        let fence =
            HostGenerationFence::configured(path, "oracle:claude:0.2.6".to_owned()).unwrap();
        assert!(fence.validate().is_err());
    }

    #[test]
    fn four_old_host_sessions_are_fenced_after_a_mixed_host_cutover() {
        let codex_path = fixture("four-sessions-codex");
        let claude_path = fixture("four-sessions-claude");
        let codex_a = "oracle:codex:0.2.6:astrid:0.10.5:source-a";
        let claude_a = "oracle:claude:0.2.6:astrid:0.10.5:source-a";
        fs::write(&codex_path, format!("{codex_a}\n")).unwrap();
        fs::write(&claude_path, format!("{claude_a}\n")).unwrap();

        let codex =
            HostGenerationFence::configured(codex_path.clone(), codex_a.to_owned()).unwrap();
        let claude =
            HostGenerationFence::configured(claude_path.clone(), claude_a.to_owned()).unwrap();
        let old_sessions = [codex.clone(), codex, claude.clone(), claude];
        assert!(old_sessions.iter().all(|fence| fence.validate().is_ok()));

        let codex_b = "oracle:codex:0.2.7:astrid:0.10.6:source-b";
        let claude_b = "oracle:claude:0.2.7:astrid:0.10.6:source-b";
        fs::write(&codex_path, format!("{codex_b}\n")).unwrap();
        fs::write(&claude_path, format!("{claude_b}\n")).unwrap();
        assert!(old_sessions.iter().all(|fence| fence.validate().is_err()));

        let new_sessions = [
            HostGenerationFence::configured(codex_path.clone(), codex_b.to_owned()).unwrap(),
            HostGenerationFence::configured(claude_path.clone(), claude_b.to_owned()).unwrap(),
        ];
        assert!(new_sessions.iter().all(|fence| fence.validate().is_ok()));

        fs::remove_file(codex_path).unwrap();
        fs::remove_file(claude_path).unwrap();
    }

    #[test]
    fn partial_configuration_is_rejected_by_constructor_contract() {
        let error = HostGenerationFence::configured(
            PathBuf::from("relative/generation"),
            "oracle:grok:0.2.6".to_owned(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("absolute path"));
    }
}
