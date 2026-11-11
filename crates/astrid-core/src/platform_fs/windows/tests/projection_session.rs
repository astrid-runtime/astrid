//! Native Windows private-projection root-capture regressions.
//!
//! These prove absolute-path replacement cannot redirect a live session, and
//! that inspection never repairs privacy.

use super::super::projection_session::{
    ProjectionInspection, ProjectionRoot, set_temporary_cleanup_failures,
};
use super::*;
use crate::platform_fs::StagingScope;
use std::io::{Read, Seek, Write};

fn rel(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(|part| OsString::from(*part)).collect()
}

fn assert_no_private_file_journal_residue(dir: &Path) {
    let mut unexpected = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let lower = name.to_string_lossy().to_ascii_lowercase();
        if lower == ".astrid-private-write.lock"
            || lower == ".astrid-private-write.transaction.json"
            || lower.starts_with(".astrid-private.")
        {
            unexpected.push(name);
        }
    }
    assert!(
        unexpected.is_empty(),
        "projection publish left private-file journal residue: {unexpected:?}"
    );
}

fn assert_no_staging_temps(dir: &Path) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let text = name.to_string_lossy();
        assert!(
            !text.starts_with(".astrid-private-"),
            "projection success left staging temporary {text}"
        );
    }
}

struct FailAfter {
    remaining: usize,
}

impl Read for FailAfter {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.remaining == 0 {
            return Err(std::io::Error::other(
                "injected midstream projection read failure",
            ));
        }
        let take = self.remaining.min(buf.len());
        for slot in &mut buf[..take] {
            *slot = 0x11;
        }
        self.remaining = self.remaining.checked_sub(take).unwrap();
        Ok(take)
    }
}

fn scoped_temporary_paths(dir: &Path, scope: StagingScope) -> Vec<PathBuf> {
    // Prefix match stays independent of staging_name_scope cfg gating; nonce is 32 hex.
    let prefix = format!(".astrid-private-{}-", scope.as_hex());
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        let text = name.to_string_lossy();
        let Some(nonce) = text.strip_prefix(&prefix) else {
            continue;
        };
        if nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            found.push(entry.path());
        }
    }
    found
}

struct TemporaryCleanupFaultGuard;

impl Drop for TemporaryCleanupFaultGuard {
    fn drop(&mut self) {
        set_temporary_cleanup_failures(0);
    }
}

#[test]
fn root_replacement_before_write_is_rejected() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();

    let captured = root.path().join("captured-root");
    // Authority omits delete sharing; blocked rename is a valid lock outcome.
    let rename_result = std::fs::rename(&projection_root, &captured);
    if rename_result.is_ok() {
        std::fs::create_dir(&projection_root).unwrap();
        apply_private_acl(&projection_root, true).unwrap();
        std::fs::write(projection_root.join("sentinel"), b"replacement root").unwrap();
        apply_private_acl(&projection_root.join("sentinel"), false).unwrap();

        assert!(projection.write(&rel(&["state"]), b"bad").is_err());
        assert!(projection.sync().is_err());
        assert!(!projection_root.join("state").exists());
        assert!(!captured.join("state").exists());
        assert_eq!(
            std::fs::read(projection_root.join("sentinel")).unwrap(),
            b"replacement root"
        );
    } else {
        projection.write(&rel(&["state"]), b"ok").unwrap();
        projection.sync().unwrap();
        assert_eq!(std::fs::read(projection_root.join("state")).unwrap(), b"ok");
    }
}

#[test]
fn ancestor_swap_before_nested_write_is_rejected() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let ancestor = root.path().join("ancestor");
    let projection_root = ancestor.join("root");
    std::fs::create_dir(&ancestor).unwrap();
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&ancestor, true).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();

    let moved_ancestor = root.path().join("moved-ancestor");
    // Delete-sharing on retained handles may block rename; either hard failure
    // on rename or failure on subsequent write/sync is acceptance.
    let rename_result = std::fs::rename(&ancestor, &moved_ancestor);
    if rename_result.is_ok() {
        std::fs::create_dir(&ancestor).unwrap();
        std::fs::create_dir(&projection_root).unwrap();
        apply_private_acl(&ancestor, true).unwrap();
        apply_private_acl(&projection_root, true).unwrap();
        assert!(
            projection
                .write(&rel(&["nested", "state"]), b"bad")
                .is_err()
        );
        assert!(projection.sync().is_err());
        assert!(!projection_root.join("nested").join("state").exists());
        assert!(
            !moved_ancestor
                .join("root")
                .join("nested")
                .join("state")
                .exists()
        );
    } else {
        projection.write(&rel(&["nested", "state"]), b"ok").unwrap();
        projection.sync().unwrap();
        assert_eq!(
            std::fs::read(projection_root.join("nested").join("state")).unwrap(),
            b"ok"
        );
    }
}

#[test]
fn intermediate_directory_preop_replacement_is_bound_on_next_capture() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    let mid = projection_root.join("mid");
    std::fs::create_dir(&projection_root).unwrap();
    std::fs::create_dir(&mid).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    apply_private_acl(&mid, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    projection.write(&rel(&["mid", "leaf"]), b"bound").unwrap();

    let diverted = root.path().join("diverted-mid");
    std::fs::create_dir(&diverted).unwrap();
    apply_private_acl(&diverted, true).unwrap();
    // Session retains the root, not a durable mid cache. Pre-op replacement of
    // an unlocked descendant is permitted; the next capture binds the new mid.
    // During-capture swaps are covered by midwalk_descendant_swap_during_capture.
    let rename_result = std::fs::rename(&mid, root.path().join("old-mid"));
    if rename_result.is_ok() {
        std::fs::rename(&diverted, &mid).unwrap();
        projection
            .write(&rel(&["mid", "leaf"]), b"replaced")
            .unwrap();
        assert_eq!(std::fs::read(mid.join("leaf")).unwrap(), b"replaced");
        assert_eq!(
            std::fs::read(root.path().join("old-mid").join("leaf")).unwrap(),
            b"bound"
        );
    } else {
        assert_eq!(std::fs::read(mid.join("leaf")).unwrap(), b"bound");
    }
}

#[test]
fn leaf_preop_replacement_is_visible_to_snapshot() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    projection
        .write(&rel(&["payload"]), b"original-private")
        .unwrap();

    let replacement = root.path().join("replacement");
    std::fs::write(&replacement, b"replacement-private").unwrap();
    apply_private_acl(&replacement, false).unwrap();
    let live = projection_root.join("payload");
    // Pre-open leaf replacement under the retained root is current-generation
    // capture, not a mid-read race. Mid-walk directory swaps use the capture hook.
    let renamed = std::fs::rename(&live, root.path().join("displaced-payload"));
    if renamed.is_ok() {
        std::fs::rename(&replacement, &live).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            projection
                .snapshot_to(&rel(&["payload"]), &mut out)
                .unwrap(),
            Some(u64::try_from(b"replacement-private".len()).unwrap())
        );
        assert_eq!(out, b"replacement-private");
    } else {
        let mut out = Vec::new();
        assert_eq!(
            projection
                .snapshot_to(&rel(&["payload"]), &mut out)
                .unwrap(),
            Some(u64::try_from(b"original-private".len()).unwrap())
        );
        assert_eq!(out, b"original-private");
    }
}

#[test]
fn unchanged_replacement_directory_at_same_spelling_is_still_rejected() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    let original = projection_root.clone();
    let parked = root.path().join("parked");
    let rename_result = std::fs::rename(&projection_root, &parked);
    if rename_result.is_ok() {
        // Recreate empty private directory at the exact original spelling.
        std::fs::create_dir(&original).unwrap();
        apply_private_acl(&original, true).unwrap();
        assert!(
            projection.sync().is_err(),
            "terminal binding must detect replacement"
        );
        assert!(projection.write(&rel(&["x"]), b"nope").is_err());
    } else {
        projection.write(&rel(&["x"]), b"ok").unwrap();
        projection.sync().unwrap();
        assert_eq!(std::fs::read(projection_root.join("x")).unwrap(), b"ok");
    }
}

#[test]
fn inspection_rejects_nonprivate_root_and_does_not_repair() {
    let _serial = serial_test_guard();
    let root = private_temp();
    // private_temp roots are ExactPrivate; loosen by replacing with a fresh dir
    // that only has default ACL from create_dir (not ExactPrivate).
    let probe = root.path().join("open");
    std::fs::create_dir(&probe).unwrap();
    assert!(
        ProjectionInspection::try_open(&probe).is_err(),
        "inspection must require ExactPrivate without repairing"
    );
    // Creating a private child via ensure would be repair; inspection must not.
    assert!(!probe.join(".astrid-private-write.lock").exists());
}

#[test]
fn inspection_matches_bytes_without_write_authority() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    {
        let writer = ProjectionRoot::open_writer(&projection_root, None).unwrap();
        writer.write(&rel(&["payload"]), b"exact-bytes").unwrap();
        writer.ensure_directory(&rel(&["child"])).unwrap();
    }
    let inspection = ProjectionInspection::try_open(&projection_root).unwrap();
    assert!(
        inspection
            .matches_private_file(&rel(&["payload"]), b"exact-bytes")
            .unwrap()
    );
    assert!(
        !inspection
            .matches_private_file(&rel(&["payload"]), b"other")
            .unwrap()
    );
    assert!(
        inspection
            .matches_private_directory(&rel(&["child"]))
            .unwrap()
    );
    inspection.confirm_absolute_root().unwrap();
}

#[test]
fn streaming_write_from_reader_round_trips_without_vec_payload_api() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    let payload = vec![0x5a; 50_003];
    let len = u64::try_from(payload.len()).unwrap();
    projection
        .write_from(&rel(&["big"]), &mut std::io::Cursor::new(&payload), len)
        .unwrap();
    let mut out = Vec::new();
    assert_eq!(
        projection.snapshot_to(&rel(&["big"]), &mut out).unwrap(),
        Some(len)
    );
    assert_eq!(out, payload);
    assert_no_private_file_journal_residue(&projection_root);
    assert_no_staging_temps(&projection_root);
}

#[test]
fn bound_write_leaves_no_journal_or_scoped_temp_residue() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let scope = StagingScope::parse("0123456789abcdef0123456789abcdef").unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, Some(scope)).unwrap();
    projection
        .write_from(
            &rel(&["state"]),
            &mut std::io::Cursor::new(b"bound-bytes"),
            11,
        )
        .unwrap();
    assert_eq!(
        std::fs::read(projection_root.join("state")).unwrap(),
        b"bound-bytes"
    );
    assert_no_private_file_journal_residue(&projection_root);
    assert_no_staging_temps(&projection_root);
}

#[test]
fn midstream_write_failure_cleans_temporary_without_journal() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let scope = StagingScope::parse("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, Some(scope)).unwrap();
    let err = projection
        .write_from(&rel(&["leaf"]), &mut FailAfter { remaining: 32 }, 1_024)
        .expect_err("midstream failure must abort before publish");
    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(!projection_root.join("leaf").exists());
    assert_no_private_file_journal_residue(&projection_root);
    assert_no_staging_temps(&projection_root);
}

#[test]
fn temporary_cleanup_failure_blocks_next_write_until_sync_recovers() {
    let _serial = serial_test_guard();
    let _fault = TemporaryCleanupFaultGuard;
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let scope = StagingScope::parse("cccccccccccccccccccccccccccccccc").unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, Some(scope)).unwrap();

    set_temporary_cleanup_failures(2);
    let err = projection
        .write_from(&rel(&["leaf"]), &mut FailAfter { remaining: 16 }, 512)
        .expect_err("midstream failure must surface");
    assert!(
        err.to_string().contains("temporary cleanup failed"),
        "cleanup failure must be surfaced, got {err}"
    );
    assert!(
        projection.test_has_pending_temporary(),
        "failed cleanup must retain the held temporary"
    );
    assert!(!projection_root.join("leaf").exists());
    assert_eq!(scoped_temporary_paths(&projection_root, scope).len(), 1);

    let blocked = projection
        .write(&rel(&["leaf"]), b"blocked-while-pending")
        .expect_err("pending cleanup must block creating another temporary");
    assert!(
        blocked.to_string().contains("temporary cleanup failed")
            || blocked
                .to_string()
                .contains("injected projection temporary cleanup failure"),
        "blocked write must retry the retained cleanup, got {blocked}"
    );
    assert!(projection.test_has_pending_temporary());

    set_temporary_cleanup_failures(0);
    projection.sync().unwrap();
    assert!(!projection.test_has_pending_temporary());
    assert!(scoped_temporary_paths(&projection_root, scope).is_empty());
    assert_no_private_file_journal_residue(&projection_root);

    projection
        .write(&rel(&["leaf"]), b"after-recovery")
        .unwrap();
    assert_eq!(
        std::fs::read(projection_root.join("leaf")).unwrap(),
        b"after-recovery"
    );
    assert_no_private_file_journal_residue(&projection_root);
    assert_no_staging_temps(&projection_root);
}

#[test]
fn temporary_cleanup_never_deletes_unknown_same_basename_by_path() {
    let _serial = serial_test_guard();
    let _fault = TemporaryCleanupFaultGuard;
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let scope = StagingScope::parse("dddddddddddddddddddddddddddddddd").unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, Some(scope)).unwrap();

    set_temporary_cleanup_failures(1);
    let err = projection
        .write_from(&rel(&["leaf"]), &mut FailAfter { remaining: 8 }, 256)
        .expect_err("midstream failure must surface");
    assert!(err.to_string().contains("temporary cleanup failed"));
    assert!(projection.test_has_pending_temporary());

    let temps = scoped_temporary_paths(&projection_root, scope);
    assert_eq!(
        temps.len(),
        1,
        "exactly one retained staging temporary expected"
    );
    let original_name = temps[0].file_name().unwrap().to_os_string();

    projection
        .test_park_pending_temporary(OsStr::new("parked-held-temporary"))
        .unwrap();
    assert!(
        !projection_root.join(&original_name).exists(),
        "held object must move aside by handle before the decoy is planted"
    );
    assert!(projection_root.join("parked-held-temporary").exists());

    let decoy = projection_root.join(&original_name);
    std::fs::write(&decoy, b"decoy-must-survive").unwrap();
    apply_private_acl(&decoy, false).unwrap();

    set_temporary_cleanup_failures(0);
    projection.sync().unwrap();
    assert!(!projection.test_has_pending_temporary());
    assert!(
        !projection_root.join("parked-held-temporary").exists(),
        "cleanup must delete only the held parked object"
    );
    assert_eq!(
        std::fs::read(&decoy).unwrap(),
        b"decoy-must-survive",
        "cleanup must not reopen/delete an unknown same-basename replacement"
    );
    assert_no_private_file_journal_residue(&projection_root);

    projection.write(&rel(&["leaf"]), b"published").unwrap();
    assert_eq!(
        std::fs::read(projection_root.join("leaf")).unwrap(),
        b"published"
    );
    // Decoy may still be present under a scoped temporary spelling; that is
    // unrelated residue from the adversarial plant, not publish journal state.
    assert!(!projection_root.join(".astrid-private-write.lock").exists());
}

#[test]
fn staging_scope_remove_requires_bound_matching_scope_without_delete_on_reject() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let scope = StagingScope::parse("0123456789abcdef0123456789abcdef").unwrap();
    let other = StagingScope::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();

    let unbound = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    let unbound_name = scope.temporary_basename();
    unbound
        .write(&rel(&[&unbound_name]), b"unbound-tmp")
        .unwrap();
    assert!(
        unbound
            .remove_staging(&rel(&[&unbound_name]), scope)
            .is_err(),
        "unbound sessions must reject staging removal"
    );
    assert!(
        projection_root.join(&unbound_name).exists(),
        "failed unbound staging removal must not delete the leaf"
    );

    let projection = ProjectionRoot::open_writer(&projection_root, Some(scope)).unwrap();
    let name = scope.temporary_basename();
    projection.write(&rel(&[&name]), b"tmp").unwrap();
    assert!(
        projection.remove_staging(&rel(&[&name]), other).is_err(),
        "wrong scope must reject staging removal"
    );
    assert!(
        projection_root.join(&name).exists(),
        "failed wrong-scope staging removal must not delete the leaf"
    );
    projection.remove_staging(&rel(&[&name]), scope).unwrap();
    assert!(!projection_root.join(&name).exists());
}

#[test]
fn snapshot_to_missing_nested_parent_returns_none_after_root_validate() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    let mut out = Vec::new();
    assert_eq!(
        projection
            .snapshot_to(&rel(&["missing-dir", "leaf"]), &mut out)
            .unwrap(),
        None
    );
    assert!(out.is_empty());
    projection.sync().unwrap();
}

#[test]
fn ensure_directory_creates_missing_nested_under_existing_parent() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    let existing = projection_root.join("existing");
    std::fs::create_dir(&projection_root).unwrap();
    std::fs::create_dir(&existing).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    apply_private_acl(&existing, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    projection
        .ensure_directory(&rel(&["existing", "nested", "leaf-dir"]))
        .unwrap();
    assert!(existing.join("nested").join("leaf-dir").is_dir());
    projection
        .write(
            &rel(&["existing", "nested", "leaf-dir", "state"]),
            b"mixed-create",
        )
        .unwrap();
    assert_eq!(
        std::fs::read(existing.join("nested").join("leaf-dir").join("state")).unwrap(),
        b"mixed-create"
    );
}

#[test]
fn snapshot_accepts_trusted_world_readable_prior_generation() {
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;

    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let prior = projection_root.join("state");
    std::fs::write(&prior, b"ordinary-prior").unwrap();
    apply_private_acl(&prior, false).unwrap();
    // Loosen ExactPrivate while keeping a Trusted owner/DACL (world read only).
    super::set_world_entry(&prior, FILE_GENERIC_READ, true);

    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    let mut out = Vec::new();
    assert_eq!(
        projection.snapshot_to(&rel(&["state"]), &mut out).unwrap(),
        Some(u64::try_from(b"ordinary-prior".len()).unwrap())
    );
    assert_eq!(out, b"ordinary-prior");

    let inspection = ProjectionInspection::try_open(&projection_root).unwrap();
    assert!(
        !inspection
            .matches_private_file(&rel(&["state"]), b"ordinary-prior")
            .unwrap(),
        "matches must keep ExactPrivate and reject world-readable priors"
    );
}

#[test]
fn midwalk_descendant_swap_during_capture_is_rejected() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    let mid = projection_root.join("mid");
    let nested = mid.join("nested");
    std::fs::create_dir(&projection_root).unwrap();
    std::fs::create_dir(&mid).unwrap();
    std::fs::create_dir(&nested).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    apply_private_acl(&mid, true).unwrap();
    apply_private_acl(&nested, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    projection
        .write(&rel(&["mid", "nested", "leaf"]), b"bound")
        .unwrap();

    let parked = root.path().join("parked-mid");
    let replacement = root.path().join("replacement-mid");
    let replacement_nested = replacement.join("nested");
    std::fs::create_dir(&replacement).unwrap();
    std::fs::create_dir(&replacement_nested).unwrap();
    apply_private_acl(&replacement, true).unwrap();
    apply_private_acl(&replacement_nested, true).unwrap();
    std::fs::write(replacement_nested.join("leaf"), b"attacker").unwrap();
    apply_private_acl(&replacement_nested.join("leaf"), false).unwrap();

    *TEST_MOVE_DESCENDANT_DURING_CAPTURE.lock().unwrap() =
        Some((mid.clone(), parked.clone(), replacement.clone()));

    let mut out = Vec::new();
    let snap = projection.snapshot_to(&rel(&["mid", "nested", "leaf"]), &mut out);
    assert!(
        TEST_MOVE_DESCENDANT_DURING_CAPTURE
            .lock()
            .unwrap()
            .is_none(),
        "mid-walk swap hook was not exercised"
    );
    assert!(
        snap.is_err() || out != b"attacker",
        "mid-walk spelling swap must not redirect snapshot onto the replacement tree"
    );
    assert_ne!(
        std::fs::read(parked.join("nested").join("leaf"))
            .ok()
            .as_deref(),
        Some(&b"attacker"[..])
    );
    // Original bound bytes remain under the parked identity when rename succeeded.
    if parked.join("nested").join("leaf").exists() {
        assert_eq!(
            std::fs::read(parked.join("nested").join("leaf")).unwrap(),
            b"bound"
        );
    }
}

#[test]
fn remove_authorized_private_leaf_deletes_exact_private_file() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let projection_root = root.path().join("root");
    std::fs::create_dir(&projection_root).unwrap();
    apply_private_acl(&projection_root, true).unwrap();
    let projection = ProjectionRoot::open_writer(&projection_root, None).unwrap();
    projection.write(&rel(&["payload"]), b"delete-me").unwrap();
    assert!(projection_root.join("payload").exists());
    projection
        .remove_authorized_private_leaf(&rel(&["payload"]))
        .unwrap();
    assert!(!projection_root.join("payload").exists());
}

#[test]
fn private_scratch_create_is_exact_private_readable_and_delete_on_close() {
    use super::super::acl::validate_private_acl_handle;
    use super::super::projection_session::create_private_scratch_file;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_NAME_NORMALIZED, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };

    let _serial = serial_test_guard();
    let mut file = create_private_scratch_file().unwrap();
    let handle: HANDLE = file.as_raw_handle().cast();
    validate_private_acl_handle(handle, false, "created private scratch").unwrap();
    assert_eq!(
        file.metadata().unwrap().len(),
        0,
        "scratch must be empty before secrets"
    );

    // Capture the DOS path only for delete-on-close proof; production API returns File only.
    let mut wide = vec![0u16; 1024];
    // SAFETY: live handle and writable buffer for documented Win32 query.
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            wide.as_mut_ptr(),
            u32::try_from(wide.len()).unwrap(),
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    assert!(
        written > 0 && (written as usize) < wide.len(),
        "final path query failed"
    );
    wide.truncate(written as usize);
    let path = String::from_utf16(&wide).unwrap();
    let path = path.strip_prefix(r"\?\").map(str::to_owned).unwrap_or(path);
    let path = std::path::PathBuf::from(path);
    assert!(
        path.exists(),
        "delete-on-close name exists while handle is live"
    );

    file.write_all(b"secret-prior-generation").unwrap();
    file.flush().unwrap();
    file.rewind().unwrap();
    let mut got = Vec::new();
    file.read_to_end(&mut got).unwrap();
    assert_eq!(&got, b"secret-prior-generation");
    validate_private_acl_handle(handle, false, "scratch after write").unwrap();

    drop(file);
    assert!(
        !path.exists(),
        "scratch path must disappear after final handle drop (DELETE_ON_CLOSE)"
    );
}

#[test]
fn directory_validation_does_not_create_a_missing_leaf() {
    let _serial = serial_test_guard();
    let root = private_temp();
    let missing = root.path().join("missing");
    assert!(crate::platform_fs::validate_private_directory(&missing).is_err());
    assert!(
        !missing.exists(),
        "validation created a directory before durable intent"
    );
}
