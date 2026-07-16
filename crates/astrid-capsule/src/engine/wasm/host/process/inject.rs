//! Read-only file injection for sandboxed spawns.
//!
//! At process spawn, the host can expose host-verified, READ-ONLY bytes to the
//! spawned child's OS sandbox (bwrap on Linux, Seatbelt on macOS). This module
//! owns the snapshot / verify / audit work behind the
//! `spawn-request.file-injections` surface.
//!
//! # Invariant
//!
//! The bytes the child reads MUST NOT be writable by (a) the child or any
//! subprocess it spawns, NOR (b) the spawning principal's capsule `fs_*` surface
//! (which runs in capsule space, OUTSIDE the child's OS sandbox).
//!
//! # Integrity contract (per injection, at spawn)
//!
//! 1. BLAKE3-hash `content`.
//! 2. Snapshot it to a host-owned path the child AND the capsule fs surface
//!    cannot write (a private `TempDir`, outside every VFS mount), then VERIFY by
//!    re-reading the materialized bytes against the pin (closes the copy->expose
//!    TOCTOU).
//! 3. Record the hash in the spawn audit.
//!
//! # Placement modes
//!
//! - `env-pointer(var)` — expose the snapshot read-only AT ITS OWN host path
//!   (Linux `--ro-bind P P` so it survives the `/tmp` tmpfs overlay; macOS
//!   `allow file-read*` + a trailing `deny file-write*` on the literal) and set
//!   the env var `var` on the child to that path. The host owns the path, so
//!   there is no caller-chosen target and no host write to a caller-named path.
//!   OS-agnostic (Linux + macOS).
//! - `fixed-path(path)` — `--ro-bind` the snapshot at the absolute in-sandbox
//!   `path`. LINUX ONLY (the bwrap mount-namespace remap); rejected on macOS,
//!   where there is no remap and materializing at a caller-named host path would
//!   be an arbitrary host write.
//!
//! The host owns the materialized bytes in both modes, so it never live-binds
//! bytes the capsule can still reach.

use std::path::PathBuf;

use astrid_crypto::ContentHash;

use crate::engine::wasm::bindings::astrid::process1_1_0::host::{
    ErrorCode, FileInjection, InjectionPlacement,
};

/// Per-injection content ceiling. Managed-policy files are kilobytes; this
/// bounds a capsule's host-scratch footprint per spawn. Oversize => `too-large`.
const MAX_INJECTION_BYTES: usize = 1024 * 1024;

/// RAII cleanup for a spawn's injections. Every snapshot lives in `_scratch`
/// (a private `TempDir`) on every platform, removed when it drops. The owner of
/// this guard controls the lifetime of the exposed bytes: it must outlive the
/// child.
pub(super) struct InjectionGuard {
    /// Snapshots live here, auto-removed on drop. `None` when there are no
    /// injections.
    _scratch: Option<tempfile::TempDir>,
}

impl InjectionGuard {
    /// An empty guard (no injections, nothing to clean).
    fn empty() -> Self {
        Self { _scratch: None }
    }
}

/// The result of preparing a spawn's injections: the sandbox-layer bind specs,
/// the env vars the host must set on the child (one per `env-pointer`
/// placement), the cleanup guard, and the `(descriptor, blake3-hex)` audit pairs.
pub(super) struct PreparedInjections {
    pub(super) sandbox: Vec<astrid_workspace::RoInjection>,
    /// `(env-var name, host path)` pairs the host sets on the child so an
    /// `env-pointer` placement's bytes are discoverable.
    pub(super) env: Vec<(String, String)>,
    pub(super) guard: InjectionGuard,
    /// `(placement descriptor, blake3 hex)` — recorded in the spawn audit; never
    /// the bytes.
    pub(super) audit: Vec<(String, String)>,
}

impl PreparedInjections {
    fn empty() -> Self {
        Self {
            sandbox: Vec::new(),
            env: Vec::new(),
            guard: InjectionGuard::empty(),
            audit: Vec::new(),
        }
    }
}

/// Validate an `env-pointer` variable NAME: non-empty, no `=`, no NUL. The host
/// sets it on the child, so a malformed name must not be able to break the env
/// list or smuggle a second assignment.
fn validate_env_name(name: &str) -> Result<(), ErrorCode> {
    if !super::context::valid_env_key(name) || super::context::reserved_process_env(name) {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(())
}

/// Validate a `fixed-path` target: absolute, free of the forbidden sandbox
/// characters (double-quote, backslash, null), and free of `..` components (a
/// `..` could make bwrap create the mount point somewhere unintended).
fn validate_fixed_path(target: &str) -> Result<(), ErrorCode> {
    use std::path::Component;
    let path = std::path::Path::new(target);
    if !path.is_absolute() || target.contains(['"', '\\', '\0']) {
        return Err(ErrorCode::InvalidInput);
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(ErrorCode::InvalidInput);
    }
    Ok(())
}

/// Write `bytes` to `dest` with mode 0600, then VERIFY by re-reading and
/// re-hashing against `pin`. Closes the copy->expose TOCTOU.
fn write_and_verify(
    dest: &std::path::Path,
    bytes: &[u8],
    pin: &ContentHash,
) -> Result<(), ErrorCode> {
    write_private(dest, bytes)?;
    let reread = std::fs::read(dest)
        .map_err(|_| ErrorCode::Unknown("injection snapshot reread failed".into()))?;
    if &ContentHash::hash(&reread) != pin {
        return Err(ErrorCode::Unknown(
            "injection snapshot integrity check failed".into(),
        ));
    }
    Ok(())
}

/// Write `bytes` to `dest` creating it fresh with file mode 0600.
///
/// Uses `create_new` (`O_CREAT | O_EXCL`): the snapshot path is always a
/// unique index under a freshly-minted host-private `TempDir`, so the file
/// never pre-exists on the legitimate path. `O_EXCL` makes that an enforced
/// invariant rather than an assumption — it refuses to open an existing file
/// or follow a symlink planted at `dest`, so a write can never truncate or
/// redirect through a pre-existing entry (defense in depth against a future
/// caller that routes a non-scratch path here).
fn write_private(dest: &std::path::Path, bytes: &[u8]) -> Result<(), ErrorCode> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(dest)
        .map_err(|e| ErrorCode::Unknown(format!("injection snapshot write failed: {e}")))?;
    f.write_all(bytes)
        .map_err(|e| ErrorCode::Unknown(format!("injection snapshot write failed: {e}")))?;
    Ok(())
}

/// Snapshot `content` into the spawn's scratch `TempDir` (created lazily),
/// verify it, and return the host-owned path. Shared by both placement modes.
fn snapshot(
    scratch: &mut Option<tempfile::TempDir>,
    index: usize,
    content: &[u8],
    hash: &ContentHash,
) -> Result<PathBuf, ErrorCode> {
    if scratch.is_none() {
        *scratch = Some(
            tempfile::TempDir::new()
                .map_err(|e| ErrorCode::Unknown(format!("injection scratch: {e}")))?,
        );
    }
    let dir = scratch.as_ref().expect("scratch set above");
    let dest = dir.path().join(index.to_string());
    write_and_verify(&dest, content, hash)?;
    Ok(dest)
}

/// Prepare all injections for one spawn. Snapshots + verifies each, and produces
/// the sandbox-layer bind specs, the env vars to set on the child, the cleanup
/// guard, and audit pairs. Empty input is a complete no-op (no scratch dir, no
/// fs work).
pub(super) fn prepare_injections(
    injections: &[FileInjection],
) -> Result<PreparedInjections, ErrorCode> {
    if injections.is_empty() {
        return Ok(PreparedInjections::empty());
    }

    let mut prepared = PreparedInjections::empty();
    // One scratch dir for the whole spawn, created lazily on first use.
    let mut scratch: Option<tempfile::TempDir> = None;

    for (index, inj) in injections.iter().enumerate() {
        if inj.content.len() > MAX_INJECTION_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        let hash = ContentHash::hash(&inj.content);

        match &inj.placement {
            InjectionPlacement::EnvPointer(var) => {
                validate_env_name(var)?;
                let dest = snapshot(&mut scratch, index, &inj.content, &hash)?;
                let dest_str = dest
                    .to_str()
                    .ok_or_else(|| ErrorCode::Unknown("injection path is not UTF-8".into()))?
                    .to_string();
                // Expose the snapshot read-only at its OWN host path: Linux
                // `--ro-bind P P` (so it punches through the `/tmp` tmpfs); macOS
                // `allow file-read*` + a trailing `deny file-write*` on the
                // literal. Then point the child's env var at it.
                prepared.sandbox.push(astrid_workspace::RoInjection {
                    source: dest.clone(),
                    target: dest,
                });
                prepared.env.push((var.clone(), dest_str));
                prepared.audit.push((format!("env:{var}"), hash.to_hex()));
            },
            InjectionPlacement::FixedPath(path) => {
                materialize_fixed_path(
                    &mut scratch,
                    index,
                    &inj.content,
                    &hash,
                    path,
                    &mut prepared,
                )?;
            },
        }
    }

    prepared.guard._scratch = scratch;
    Ok(prepared)
}

/// `fixed-path` placement: Linux-only ro-bind of the snapshot at `path`. On
/// macOS (and any non-Linux target) there is no mount-namespace remap, so this
/// is rejected — materializing at a caller-named host path would be an arbitrary
/// host write. The path is validated on every platform so a malformed `path` is
/// `invalid-input` regardless of the unsupported-platform rejection.
fn materialize_fixed_path(
    scratch: &mut Option<tempfile::TempDir>,
    index: usize,
    content: &[u8],
    hash: &ContentHash,
    path: &str,
    prepared: &mut PreparedInjections,
) -> Result<(), ErrorCode> {
    validate_fixed_path(path)?;
    #[cfg(target_os = "linux")]
    {
        let dest = snapshot(scratch, index, content, hash)?;
        prepared.sandbox.push(astrid_workspace::RoInjection {
            source: dest,
            target: PathBuf::from(path),
        });
        prepared.audit.push((format!("path:{path}"), hash.to_hex()));
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (scratch, index, content, hash, prepared);
        Err(ErrorCode::InvalidInput)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_env_name_rejects_empty_and_specials() {
        assert!(matches!(
            validate_env_name(""),
            Err(ErrorCode::InvalidInput)
        ));
        assert!(matches!(
            validate_env_name("FOO=BAR"),
            Err(ErrorCode::InvalidInput)
        ));
        assert!(matches!(
            validate_env_name("FOO\0BAR"),
            Err(ErrorCode::InvalidInput)
        ));
        assert!(matches!(
            validate_env_name("ASTRID_SESSION_TOKEN"),
            Err(ErrorCode::InvalidInput)
        ));
        assert!(matches!(
            validate_env_name("LD_PRELOAD"),
            Err(ErrorCode::InvalidInput)
        ));
    }

    #[test]
    fn validate_env_name_accepts_normal() {
        assert!(validate_env_name("CLAUDE_CODE_MANAGED_SETTINGS_PATH").is_ok());
    }

    #[test]
    fn validate_fixed_path_rejects_relative_and_specials() {
        assert!(matches!(
            validate_fixed_path("relative/path"),
            Err(ErrorCode::InvalidInput)
        ));
        assert!(matches!(
            validate_fixed_path("/etc/ev\"il"),
            Err(ErrorCode::InvalidInput)
        ));
        assert!(matches!(
            validate_fixed_path("/etc/ev\\il"),
            Err(ErrorCode::InvalidInput)
        ));
        assert!(matches!(
            validate_fixed_path("/etc/ev\0il"),
            Err(ErrorCode::InvalidInput)
        ));
    }

    #[test]
    fn validate_fixed_path_rejects_parent_dir_escape() {
        // A `..` could make bwrap create the mount point somewhere unintended.
        assert!(matches!(
            validate_fixed_path("/etc/agent/../../escape"),
            Err(ErrorCode::InvalidInput)
        ));
    }

    #[test]
    fn validate_fixed_path_accepts_absolute_clean() {
        assert!(validate_fixed_path("/etc/codex/requirements.toml").is_ok());
    }

    #[test]
    fn write_and_verify_roundtrip_succeeds() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("snap");
        let bytes = b"injected policy bytes";
        let pin = ContentHash::hash(bytes);
        write_and_verify(&dest, bytes, &pin).expect("verify should pass on a faithful write");
        assert_eq!(std::fs::read(&dest).unwrap(), bytes);
    }

    #[test]
    fn write_and_verify_detects_mismatch() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("snap");
        let wrong_pin = ContentHash::hash(b"some other bytes");
        let err = write_and_verify(&dest, b"actual bytes", &wrong_pin).unwrap_err();
        assert!(matches!(err, ErrorCode::Unknown(ref m) if m.contains("integrity check failed")));
    }

    #[test]
    fn write_private_sets_0600_on_unix() {
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("snap");
        write_private(&dest, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&dest).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "snapshot must be owner-only 0600");
        }
    }

    #[test]
    fn write_private_refuses_existing_path() {
        // O_EXCL invariant: the snapshot writer must never open — and so never
        // truncate, nor follow a symlink planted at — a path that already
        // exists. A pre-existing entry makes the write fail with its content
        // left intact, rather than being overwritten through.
        let dir = tempfile::TempDir::new().unwrap();
        let dest = dir.path().join("snap");
        std::fs::write(&dest, b"pre-existing").unwrap();
        let err = write_private(&dest, b"new bytes").unwrap_err();
        assert!(matches!(err, ErrorCode::Unknown(_)));
        assert_eq!(
            std::fs::read(&dest).unwrap(),
            b"pre-existing",
            "existing content must not be truncated through"
        );
    }

    #[test]
    fn empty_injections_is_noop() {
        let prepared = prepare_injections(&[]).expect("empty is ok");
        assert!(prepared.sandbox.is_empty());
        assert!(prepared.env.is_empty());
        assert!(prepared.audit.is_empty());
    }
}
