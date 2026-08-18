//! Lock/index reference scanning for source removal.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::{IndexError, UsageChecker};

/// Default bound for one scanned lock/index file.
pub(crate) const DEFAULT_MAX_LOCK_BYTES: usize = 1024 * 1024;
/// Maximum directory depth traversed by default.
pub(crate) const DEFAULT_MAX_LOCK_DEPTH: usize = 8;
/// Maximum candidate files traversed by default.
pub(crate) const DEFAULT_MAX_LOCK_FILES: usize = 4096;

/// Read-only scanner over caller-selected lock/index paths.
#[derive(Debug, Clone)]
pub(crate) struct LockUsageScanner {
    roots: Vec<PathBuf>,
    max_file_bytes: usize,
    max_depth: usize,
    max_files: usize,
}

impl LockUsageScanner {
    /// Scan one file or directory tree.
    pub(crate) fn new(roots: impl IntoIterator<Item = PathBuf>) -> Self {
        Self {
            roots: roots.into_iter().collect(),
            max_file_bytes: DEFAULT_MAX_LOCK_BYTES,
            max_depth: DEFAULT_MAX_LOCK_DEPTH,
            max_files: DEFAULT_MAX_LOCK_FILES,
        }
    }

    /// Set the maximum bytes read from each candidate file.
    pub(crate) fn max_file_bytes(mut self, max_file_bytes: usize) -> Self {
        self.max_file_bytes = max_file_bytes.max(1);
        self
    }

    /// Set the maximum directory depth traversed.
    pub(crate) fn max_depth(mut self, max_depth: usize) -> Self {
        self.max_depth = max_depth;
        self
    }

    /// Set the maximum candidate files traversed.
    pub(crate) fn max_files(mut self, max_files: usize) -> Self {
        self.max_files = max_files.max(1);
        self
    }
}

impl UsageChecker for LockUsageScanner {
    fn references(&self, id: &str) -> Result<Vec<String>, IndexError> {
        let mut paths = Vec::new();
        for root in &self.roots {
            if !root.exists() {
                continue;
            }
            collect_paths(root, 0, &mut paths, self.max_depth, self.max_files)?;
        }
        paths.sort();
        paths.dedup();

        let mut references = Vec::new();
        for path in paths {
            if file_references_id(&path, id, self.max_file_bytes)? {
                references.push(path.to_string_lossy().into_owned());
            }
        }
        Ok(references)
    }
}

fn collect_paths(
    path: &Path,
    depth: usize,
    output: &mut Vec<PathBuf>,
    max_depth: usize,
    max_files: usize,
) -> Result<(), IndexError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(IndexError::Io {
                path: path.to_path_buf(),
                source,
            });
        },
    };
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if output.len() >= max_files {
            return Err(IndexError::Usage(format!(
                "lock scan exceeded max file count {max_files}"
            )));
        }
        output.push(path.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    if depth >= max_depth {
        return Err(IndexError::Usage(format!(
            "lock scan exceeded max directory depth {max_depth}"
        )));
    }
    let mut children = Vec::new();
    for entry in fs::read_dir(path).map_err(|source| IndexError::Io {
        path: path.to_path_buf(),
        source,
    })? {
        let entry = entry.map_err(|source| IndexError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        children.push(entry.path());
    }
    children.sort();
    for child in children {
        collect_paths(
            &child,
            depth.saturating_add(1),
            output,
            max_depth,
            max_files,
        )?;
    }
    Ok(())
}

fn file_references_id(path: &Path, id: &str, max_bytes: usize) -> Result<bool, IndexError> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(IndexError::Io {
                path: path.to_path_buf(),
                source,
            });
        },
    };
    if metadata.len() > max_bytes as u64 {
        return Ok(false);
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(IndexError::Io {
                path: path.to_path_buf(),
                source,
            });
        },
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return Ok(false);
    };
    if let Ok(value) = serde_json::from_str::<Value>(text)
        && value_references_id(&value, id)
    {
        return Ok(true);
    }
    if let Ok(value) = toml::from_str::<toml::Value>(text) {
        let json =
            serde_json::to_value(value).map_err(|source| IndexError::JsonSerialize { source })?;
        if value_references_id(&json, id) {
            return Ok(true);
        }
    }
    // Keep a conservative text fallback for lock formats that intentionally
    // use canonical line-oriented serialization rather than JSON/TOML. Match
    // the complete scalar value so `one` does not block removal of `one-old`.
    Ok(text.lines().any(|line| {
        let line = line.trim();
        let Some((key, value)) = line.split_once('=').or_else(|| line.split_once(':')) else {
            return false;
        };
        let key = key.trim().to_ascii_lowercase().replace(['_', '-'], "");
        if !matches!(key.as_str(), "indexid" | "sourceid") {
            return false;
        }
        value
            .trim()
            .trim_end_matches(',')
            .trim_matches(|character| character == '"' || character == '\'')
            == id
    }))
}

fn value_references_id(value: &Value, id: &str) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let normalized = key.to_ascii_lowercase().replace(['_', '-'], "");
            let direct =
                matches!(normalized.as_str(), "indexid" | "sourceid") && value.as_str() == Some(id);
            let nested = normalized == "index"
                && ((value.get("id").and_then(Value::as_str) == Some(id))
                    || (value.get("index-id").and_then(Value::as_str) == Some(id))
                    || (value.get("index_id").and_then(Value::as_str) == Some(id)));
            direct || nested || value_references_id(value, id)
        }),
        Value::Array(values) => values.iter().any(|value| value_references_id(value, id)),
        _ => false,
    }
}
