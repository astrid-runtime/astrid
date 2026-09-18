//! Bounded rate-accounting leases for fixed local capsule-install sets.
//!
//! A lease never grants install authority. It only lets a caller replace many
//! ordinary `InstallCapsule` frequency charges with one bounded batch charge.
//! Every member still traverses the ordinary install verifier and publisher.

use std::collections::{BTreeMap, HashMap};
use std::fs::{File, OpenOptions};
use std::io::Read as _;
use std::path::Path;
use std::time::{Duration, Instant};

use astrid_core::PrincipalId;
use astrid_core::kernel_api::{
    CapsuleInstallBatchContext, CapsuleInstallBatchId, CapsuleInstallBatchMember,
    CapsuleInstallProvenance,
};
use astrid_storage::StateOwner;

/// Protocol ceiling, not an operator tuning knob. It bounds one in-memory
/// declaration independently of the ordinary per-minute install limit.
const MAX_BATCH_MEMBERS: usize = 64;
/// Each local archive is already capped at 64 `MiB` by install provenance. This
/// aggregate ceiling prevents one lease from multiplying that bound unchecked.
const MAX_BATCH_SOURCE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MEMBER_ATTEMPTS: u8 = 2;
pub(super) const BATCH_LEASE_LIFETIME: Duration = Duration::from_mins(15);

#[derive(Debug, Clone)]
struct MemberState {
    declaration: CapsuleInstallBatchMember,
    attempts: u8,
    completed: bool,
    recovery_attempted: bool,
}

#[derive(Debug)]
struct Lease {
    caller: PrincipalId,
    target: PrincipalId,
    expires_at: Instant,
    members: BTreeMap<String, MemberState>,
}

#[derive(Debug, Default)]
pub(super) struct InstallBatchRegistry {
    leases: HashMap<CapsuleInstallBatchId, Lease>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct InstallBatchLease {
    pub(super) batch_id: CapsuleInstallBatchId,
    pub(super) expires_in_secs: u64,
}

#[derive(Debug)]
pub(super) enum InstallBatchReservation {
    Pending(CapsuleInstallBatchMember),
    Completed(CapsuleInstallBatchMember),
}

pub(super) fn open_batch_archive_source(
    source: &Path,
    expected: &CapsuleInstallBatchMember,
) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(source)
        .map_err(|error| format!("open batch capsule source {}: {error}", source.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect batch capsule source {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != expected.source_bytes
    {
        return Err(format!(
            "capsule '{}' batch source size or type does not match its declaration",
            expected.id
        ));
    }
    Ok(file)
}

fn digest_open_batch_archive_source(
    source: &Path,
    mut file: File,
    expected: &CapsuleInstallBatchMember,
) -> Result<String, String> {
    let mut hasher = blake3::Hasher::new();
    let mut bytes = 0_u64;
    let mut bounded = (&mut file).take(expected.source_bytes.saturating_add(1));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = bounded.read(&mut buffer).map_err(|error| {
            format!(
                "digest completed batch source {}: {error}",
                source.display()
            )
        })?;
        if read == 0 {
            break;
        }
        bytes = bytes.saturating_add(read as u64);
        hasher.update(&buffer[..read]);
    }
    if bytes != expected.source_bytes {
        return Err(format!(
            "capsule '{}' completed batch source changed while it was being verified",
            expected.id
        ));
    }
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

impl InstallBatchReservation {
    pub(super) fn member(&self) -> &CapsuleInstallBatchMember {
        match self {
            Self::Pending(member) | Self::Completed(member) => member,
        }
    }
}

impl InstallBatchRegistry {
    pub(super) fn begin(
        &mut self,
        caller: &PrincipalId,
        target: &PrincipalId,
        members: Vec<CapsuleInstallBatchMember>,
    ) -> Result<InstallBatchLease, String> {
        let now = Instant::now();
        self.prune_expired_at(now);
        if members.is_empty() || members.len() > MAX_BATCH_MEMBERS {
            return Err(format!(
                "capsule install batch must declare 1..={MAX_BATCH_MEMBERS} members"
            ));
        }
        let mut total_bytes = 0_u64;
        let mut declared = BTreeMap::new();
        for member in members {
            validate_member(&member)?;
            total_bytes = total_bytes
                .checked_add(member.source_bytes)
                .ok_or_else(|| "capsule install batch source size overflow".to_owned())?;
            if total_bytes > MAX_BATCH_SOURCE_BYTES {
                return Err(format!(
                    "capsule install batch exceeds {MAX_BATCH_SOURCE_BYTES}-byte source ceiling"
                ));
            }
            let id = member.id.clone();
            if declared
                .insert(
                    id.clone(),
                    MemberState {
                        declaration: member,
                        attempts: 0,
                        completed: false,
                        recovery_attempted: false,
                    },
                )
                .is_some()
            {
                return Err(format!("duplicate capsule install batch member '{id}'"));
            }
        }

        if let Some((batch_id, lease)) = self
            .leases
            .iter()
            .find(|(_, lease)| &lease.caller == caller && &lease.target == target)
        {
            let same_declaration = lease.members.len() == declared.len()
                && lease.members.iter().all(|(id, existing)| {
                    declared
                        .get(id)
                        .is_some_and(|candidate| candidate.declaration == existing.declaration)
                });
            if same_declaration {
                return Ok(InstallBatchLease {
                    batch_id: *batch_id,
                    expires_in_secs: remaining_lease_secs(lease.expires_at, now),
                });
            }
            return Err(format!(
                "a different capsule install batch is already active for target {target}"
            ));
        }

        let batch_id = CapsuleInstallBatchId::new();
        let expires_at = Instant::now()
            .checked_add(BATCH_LEASE_LIFETIME)
            .ok_or_else(|| "capsule install batch lease expiry overflow".to_owned())?;
        self.leases.insert(
            batch_id,
            Lease {
                caller: caller.clone(),
                target: target.clone(),
                expires_at,
                members: declared,
            },
        );
        Ok(InstallBatchLease {
            batch_id,
            expires_in_secs: BATCH_LEASE_LIFETIME.as_secs(),
        })
    }

    pub(super) fn reserve(
        &mut self,
        caller: &PrincipalId,
        target: &PrincipalId,
        context: &CapsuleInstallBatchContext,
        source: &str,
        provenance: Option<&CapsuleInstallProvenance>,
    ) -> Result<InstallBatchReservation, String> {
        self.prune_expired();
        let lease = self
            .leases
            .get_mut(&context.batch_id)
            .ok_or_else(|| "capsule install batch lease is absent or expired".to_owned())?;
        if &lease.caller != caller || &lease.target != target {
            return Err(
                "capsule install batch lease does not belong to this caller and target".into(),
            );
        }
        let member = lease.members.get_mut(&context.member_id).ok_or_else(|| {
            format!(
                "capsule '{}' is not declared in this install batch",
                context.member_id
            )
        })?;
        let supplied_digest = provenance.and_then(|value| value.source_digest.as_deref());
        if supplied_digest != Some(member.declaration.source_digest.as_str()) {
            return Err(format!(
                "capsule '{}' install provenance does not match its batch digest",
                context.member_id
            ));
        }
        let source_path = Path::new(source.strip_prefix("file://").unwrap_or(source));
        if member.completed {
            if member.recovery_attempted {
                return Err(format!(
                    "capsule '{}' exhausted its completed-member recovery budget",
                    context.member_id
                ));
            }
            // Consume the recovery slot before hashing. A same-size tampered
            // source must not provide an unmetered hashing oracle.
            member.recovery_attempted = true;
            let source_file = open_batch_archive_source(source_path, &member.declaration)?;
            let exact_digest =
                digest_open_batch_archive_source(source_path, source_file, &member.declaration)?;
            if exact_digest != member.declaration.source_digest {
                return Err(format!(
                    "capsule '{}' completed batch source no longer matches its declaration",
                    context.member_id
                ));
            }
            return Ok(InstallBatchReservation::Completed(
                member.declaration.clone(),
            ));
        }
        if member.attempts >= MAX_MEMBER_ATTEMPTS {
            return Err(format!(
                "capsule '{}' exhausted its bounded batch attempt budget",
                context.member_id
            ));
        }
        open_batch_archive_source(source_path, &member.declaration)?;
        member.attempts = member.attempts.saturating_add(1);
        Ok(InstallBatchReservation::Pending(member.declaration.clone()))
    }

    pub(super) fn complete(&mut self, context: &CapsuleInstallBatchContext) -> Result<(), String> {
        let lease = self
            .leases
            .get_mut(&context.batch_id)
            .ok_or_else(|| "capsule install batch lease is absent or expired".to_owned())?;
        let member = lease
            .members
            .get_mut(&context.member_id)
            .ok_or_else(|| "capsule install batch member disappeared".to_owned())?;
        member.completed = true;
        Ok(())
    }

    pub(super) fn finish<F>(
        &mut self,
        caller: &PrincipalId,
        target: &PrincipalId,
        batch_id: CapsuleInstallBatchId,
        mut verify: F,
    ) -> Result<(), String>
    where
        F: FnMut(&PrincipalId, &CapsuleInstallBatchMember) -> Result<bool, String>,
    {
        self.prune_expired();
        let lease = self
            .leases
            .get(&batch_id)
            .ok_or_else(|| "capsule install batch lease is absent or expired".to_owned())?;
        if &lease.caller != caller || &lease.target != target {
            return Err(
                "capsule install batch lease does not belong to this caller and target".into(),
            );
        }
        for member in lease.members.values() {
            if !verify(&lease.target, &member.declaration)? {
                return Err(format!(
                    "capsule install batch is incomplete at '{}'",
                    member.declaration.id
                ));
            }
        }
        self.leases.remove(&batch_id);
        Ok(())
    }

    fn prune_expired(&mut self) {
        self.prune_expired_at(Instant::now());
    }

    fn prune_expired_at(&mut self, now: Instant) {
        self.leases.retain(|_, lease| lease.expires_at > now);
    }

    #[cfg(test)]
    fn expire_for_test(&mut self, batch_id: CapsuleInstallBatchId) {
        self.leases
            .get_mut(&batch_id)
            .expect("test lease")
            .expires_at = Instant::now();
    }

    #[cfg(test)]
    fn set_remaining_for_test(&mut self, batch_id: CapsuleInstallBatchId, remaining: Duration) {
        self.leases
            .get_mut(&batch_id)
            .expect("test lease")
            .expires_at = Instant::now()
            .checked_add(remaining)
            .expect("test lease expiry");
    }
}

fn remaining_lease_secs(expires_at: Instant, now: Instant) -> u64 {
    let remaining = expires_at.saturating_duration_since(now);
    remaining
        .as_secs()
        .saturating_add(u64::from(remaining.subsec_nanos() != 0))
}

fn validate_member(member: &CapsuleInstallBatchMember) -> Result<(), String> {
    astrid_capsule_types::CapsuleId::new(member.id.clone()).map_err(|error| {
        format!(
            "invalid capsule install batch member '{}': {error}",
            member.id
        )
    })?;
    let parsed_version = semver::Version::parse(&member.version).map_err(|_| {
        format!(
            "capsule '{}' batch version must be a canonical semantic version up to 128 bytes",
            member.id
        )
    })?;
    if member.version.len() > 128 || parsed_version.to_string() != member.version {
        return Err(format!(
            "capsule '{}' batch version must be a canonical semantic version up to 128 bytes",
            member.id
        ));
    }
    if !canonical_source_digest(&member.source_digest) {
        return Err(format!(
            "capsule '{}' batch digest must be canonical blake3 text",
            member.id
        ));
    }
    if !canonical_source_digest(&member.archive_digest) {
        return Err(format!(
            "capsule '{}' batch archive digest must be canonical blake3 text",
            member.id
        ));
    }
    if member.source_bytes == 0 || member.source_bytes > 64 * 1024 * 1024 {
        return Err(format!(
            "capsule '{}' batch source size must be 1..=67108864 bytes",
            member.id
        ));
    }
    if let Some(generation) = &member.expected_generation {
        super::install_generation::parse_installed_generation(generation).map_err(|error| {
            format!(
                "invalid capsule install batch member '{}': {error}",
                member.id
            )
        })?;
    }
    Ok(())
}

fn canonical_source_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("blake3:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

pub(super) fn installed_member_matches(
    kernel: &crate::Kernel,
    target: &PrincipalId,
    member: &CapsuleInstallBatchMember,
) -> Result<bool, String> {
    Ok(verified_installed_member(kernel, target, member)?.is_some())
}

#[derive(Debug)]
pub(super) struct VerifiedInstalledBatchMember {
    pub(super) version: String,
    pub(super) wasm_hash: Option<String>,
}

impl VerifiedInstalledBatchMember {
    pub(super) fn response_json(self) -> serde_json::Value {
        serde_json::json!({
            "installed_version": self.version,
            "wasm_hash": self.wasm_hash,
            "batch_resumed": true,
        })
    }
}

pub(super) fn verified_installed_member(
    kernel: &crate::Kernel,
    target: &PrincipalId,
    member: &CapsuleInstallBatchMember,
) -> Result<Option<VerifiedInstalledBatchMember>, String> {
    let Some(store) = kernel.principal_store.as_ref() else {
        return Err("durable capsule registry is unavailable".to_owned());
    };
    let uid = kernel
        .principal_directory
        .uid_for(target)
        .map_err(|error| format!("resolve batch target principal {target}: {error}"))?;
    let owner = StateOwner::Principal(uid);
    let package =
        astrid_capsule_install::read_verified_durable_package_for_owner(store, &owner, &member.id)
            .map_err(|error| format!("verify durable batch member '{}': {error}", member.id))?;
    let Some(package) = package else {
        return Ok(None);
    };
    let digest = format!("blake3:{}", blake3::hash(package.archive()).to_hex());
    if package.metadata().version != member.version || digest != member.archive_digest {
        return Ok(None);
    }
    Ok(Some(VerifiedInstalledBatchMember {
        version: package.metadata().version.clone(),
        wasm_hash: package.metadata().wasm_hash.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn principal(value: &str) -> PrincipalId {
        PrincipalId::new(value).expect("valid principal")
    }

    fn member(id: &str, bytes: u64) -> CapsuleInstallBatchMember {
        CapsuleInstallBatchMember {
            id: id.to_owned(),
            version: "1.2.3".to_owned(),
            source_digest: format!("blake3:{}", "a".repeat(64)),
            archive_digest: format!("blake3:{}", "b".repeat(64)),
            source_bytes: bytes,
            expected_generation: None,
        }
    }

    #[cfg(unix)]
    #[test]
    fn batch_source_open_rejects_fifo_without_blocking() {
        use nix::sys::stat::Mode;
        use nix::unistd::mkfifo;

        let root = tempfile::tempdir().expect("fixture root");
        let source = root.path().join("replacement.capsule");
        mkfifo(&source, Mode::from_bits_truncate(0o600)).expect("fixture fifo");

        let error = open_batch_archive_source(&source, &member("one", 0))
            .expect_err("FIFO must never be accepted as an archive source");
        assert!(error.contains("size or type"), "{error}");
    }

    #[test]
    fn begin_rejects_duplicate_and_aggregate_overflow() {
        let caller = principal("default");
        let mut registry = InstallBatchRegistry::default();
        assert!(
            registry
                .begin(&caller, &caller, vec![member("one", 1), member("one", 1)])
                .unwrap_err()
                .contains("duplicate")
        );

        let oversized = (0..9)
            .map(|index| member(&format!("capsule-{index}"), 64 * 1024 * 1024))
            .collect();
        assert!(
            registry
                .begin(&caller, &caller, oversized)
                .unwrap_err()
                .contains("source ceiling")
        );
    }

    #[test]
    fn recovered_response_preserves_wasm_hash_for_distro_lock() {
        let hash = "c".repeat(64);
        let response = VerifiedInstalledBatchMember {
            version: "1.2.3".to_owned(),
            wasm_hash: Some(hash.clone()),
        }
        .response_json();
        assert_eq!(response["installed_version"], "1.2.3");
        assert_eq!(response["wasm_hash"], hash);
        assert_eq!(response["batch_resumed"], true);
    }

    #[test]
    fn one_active_batch_is_bound_to_caller_and_target() {
        let caller = principal("default");
        let target = principal("worker");
        let mut registry = InstallBatchRegistry::default();
        let first = registry
            .begin(&caller, &target, vec![member("one", 1)])
            .expect("first lease");
        let resumed = registry
            .begin(&caller, &target, vec![member("one", 1)])
            .expect("matching lease resumes");
        assert_eq!(resumed.batch_id, first.batch_id);
        assert_eq!(resumed.expires_in_secs, BATCH_LEASE_LIFETIME.as_secs());
        assert!(
            registry
                .begin(&caller, &target, vec![member("two", 1)])
                .unwrap_err()
                .contains("different")
        );
    }

    #[test]
    fn resumed_batch_reports_its_actual_remaining_lifetime() {
        let caller = principal("default");
        let target = principal("worker");
        let mut registry = InstallBatchRegistry::default();
        let first = registry
            .begin(&caller, &target, vec![member("one", 1)])
            .expect("first lease");
        registry.set_remaining_for_test(first.batch_id, Duration::from_secs(7));

        let resumed = registry
            .begin(&caller, &target, vec![member("one", 1)])
            .expect("matching lease resumes");
        assert_eq!(resumed.batch_id, first.batch_id);
        assert_eq!(resumed.expires_in_secs, 7);
    }

    #[test]
    fn reserve_binds_caller_and_target() {
        let caller = principal("default");
        let target = principal("worker");
        let source = tempfile::NamedTempFile::new().expect("source file");
        std::fs::write(source.path(), b"x").expect("source bytes");
        let mut declaration = member("one", 1);
        declaration.source_digest = format!(
            "blake3:{}",
            astrid_capsule_install::source_digest_for_archive(source.path())
                .expect("source digest")
        );
        let provenance = CapsuleInstallProvenance {
            distro: Some("example".to_owned()),
            source_digest: Some(declaration.source_digest.clone()),
        };
        let mut registry = InstallBatchRegistry::default();
        let batch_id = registry
            .begin(&caller, &target, vec![declaration])
            .expect("batch lease")
            .batch_id;
        let context = CapsuleInstallBatchContext {
            batch_id,
            member_id: "one".to_owned(),
        };

        assert!(
            registry
                .reserve(
                    &principal("other"),
                    &target,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .unwrap_err()
                .contains("does not belong")
        );
        assert!(
            registry
                .reserve(
                    &caller,
                    &principal("other-target"),
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .unwrap_err()
                .contains("does not belong")
        );
    }

    #[test]
    fn reserve_binds_digest_size_and_attempts() {
        let caller = principal("default");
        let target = principal("worker");
        let source = tempfile::NamedTempFile::new().expect("source file");
        std::fs::write(source.path(), b"x").expect("source bytes");
        let declaration = member("one", 1);
        let provenance = CapsuleInstallProvenance {
            distro: Some("example".to_owned()),
            source_digest: Some(declaration.source_digest.clone()),
        };
        let mut registry = InstallBatchRegistry::default();
        let batch_id = registry
            .begin(&caller, &target, vec![declaration])
            .expect("batch lease")
            .batch_id;
        let context = CapsuleInstallBatchContext {
            batch_id,
            member_id: "one".to_owned(),
        };
        let wrong = CapsuleInstallProvenance {
            distro: None,
            source_digest: Some(format!("blake3:{}", "b".repeat(64))),
        };
        assert!(
            registry
                .reserve(
                    &caller,
                    &target,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&wrong),
                )
                .unwrap_err()
                .contains("digest")
        );
        let wrong_size = tempfile::NamedTempFile::new().expect("wrong-size source");
        std::fs::write(wrong_size.path(), b"xx").expect("wrong-size bytes");
        assert!(
            registry
                .reserve(
                    &caller,
                    &target,
                    &context,
                    wrong_size.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .unwrap_err()
                .contains("size or type")
        );
        registry
            .reserve(
                &caller,
                &target,
                &context,
                source.path().to_str().unwrap(),
                Some(&provenance),
            )
            .expect("first bounded attempt");
        registry
            .reserve(
                &caller,
                &target,
                &context,
                source.path().to_str().unwrap(),
                Some(&provenance),
            )
            .expect("second bounded attempt");
        assert!(
            registry
                .reserve(
                    &caller,
                    &target,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .unwrap_err()
                .contains("attempt budget")
        );
    }

    #[test]
    fn completed_member_can_recover_after_two_install_attempts() {
        let caller = principal("default");
        let source = tempfile::NamedTempFile::new().expect("source file");
        std::fs::write(source.path(), b"x").expect("source bytes");
        let mut declaration = member("one", 1);
        declaration.source_digest = format!(
            "blake3:{}",
            astrid_capsule_install::source_digest_for_archive(source.path())
                .expect("source digest")
        );
        let provenance = CapsuleInstallProvenance {
            distro: Some("example".to_owned()),
            source_digest: Some(declaration.source_digest.clone()),
        };
        let mut registry = InstallBatchRegistry::default();
        let batch_id = registry
            .begin(&caller, &caller, vec![declaration])
            .expect("batch lease")
            .batch_id;
        let context = CapsuleInstallBatchContext {
            batch_id,
            member_id: "one".to_owned(),
        };

        assert!(matches!(
            registry
                .reserve(
                    &caller,
                    &caller,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .expect("first install attempt"),
            InstallBatchReservation::Pending(_)
        ));
        assert!(matches!(
            registry
                .reserve(
                    &caller,
                    &caller,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .expect("second install attempt"),
            InstallBatchReservation::Pending(_)
        ));
        registry.complete(&context).expect("mark complete");
        assert!(matches!(
            registry
                .reserve(
                    &caller,
                    &caller,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .expect("completed reservation"),
            InstallBatchReservation::Completed(_)
        ));
        assert!(
            registry
                .reserve(
                    &caller,
                    &caller,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .unwrap_err()
                .contains("recovery budget")
        );
    }

    #[test]
    fn failed_completed_source_verification_consumes_recovery_budget() {
        let caller = principal("default");
        let source = tempfile::NamedTempFile::new().expect("source file");
        std::fs::write(source.path(), b"x").expect("source bytes");
        let mut declaration = member("one", 1);
        declaration.source_digest = format!(
            "blake3:{}",
            astrid_capsule_install::source_digest_for_archive(source.path())
                .expect("source digest")
        );
        let provenance = CapsuleInstallProvenance {
            distro: Some("example".to_owned()),
            source_digest: Some(declaration.source_digest.clone()),
        };
        let mut registry = InstallBatchRegistry::default();
        let batch_id = registry
            .begin(&caller, &caller, vec![declaration])
            .expect("batch lease")
            .batch_id;
        let context = CapsuleInstallBatchContext {
            batch_id,
            member_id: "one".to_owned(),
        };
        registry
            .reserve(
                &caller,
                &caller,
                &context,
                source.path().to_str().unwrap(),
                Some(&provenance),
            )
            .expect("install attempt");
        registry.complete(&context).expect("mark complete");
        std::fs::write(source.path(), b"y").expect("tampered source bytes");
        assert!(
            registry
                .reserve(
                    &caller,
                    &caller,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .unwrap_err()
                .contains("no longer matches")
        );
        std::fs::write(source.path(), b"x").expect("restore source bytes");
        assert!(
            registry
                .reserve(
                    &caller,
                    &caller,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .unwrap_err()
                .contains("recovery budget")
        );
    }

    #[test]
    fn expired_lease_is_rejected_before_reserve_or_finish_verification() {
        let caller = principal("default");
        let source = tempfile::NamedTempFile::new().expect("source file");
        std::fs::write(source.path(), b"x").expect("source bytes");
        let declaration = member("one", 1);
        let provenance = CapsuleInstallProvenance {
            distro: Some("example".to_owned()),
            source_digest: Some(declaration.source_digest.clone()),
        };
        let mut registry = InstallBatchRegistry::default();
        let reserve_batch = registry
            .begin(&caller, &caller, vec![declaration.clone()])
            .expect("reserve lease")
            .batch_id;
        let context = CapsuleInstallBatchContext {
            batch_id: reserve_batch,
            member_id: "one".to_owned(),
        };
        registry.expire_for_test(reserve_batch);
        assert!(
            registry
                .reserve(
                    &caller,
                    &caller,
                    &context,
                    source.path().to_str().unwrap(),
                    Some(&provenance),
                )
                .unwrap_err()
                .contains("absent or expired")
        );

        let finish_batch = registry
            .begin(&caller, &caller, vec![declaration])
            .expect("finish lease")
            .batch_id;
        registry.expire_for_test(finish_batch);
        assert!(
            registry
                .finish(&caller, &caller, finish_batch, |_, _| {
                    panic!("expired finish must not inspect durable packages")
                })
                .unwrap_err()
                .contains("absent or expired")
        );
    }
}
