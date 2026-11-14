//! Retirement preserves the captured volume and refuses changed namespaces.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use super::{PreparedProjectionRetirement, retire_with_hook};
use crate::platform_fs::windows::ntfs_directory_flush::ReportedFilesystemOverride;

const CANONICAL_VOLUME: &str = "astrid.volume";

fn volume_root() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("projection");
    fs::create_dir(&root).unwrap();
    fs::write(root.join(CANONICAL_VOLUME), b"durable authority").unwrap();
    (temp, root)
}

fn write_nested(root: &Path) {
    fs::create_dir(root.join("z-child")).unwrap();
    fs::write(root.join("z-child/state"), b"earlier").unwrap();
    fs::create_dir(root.join("z-late")).unwrap();
    fs::write(root.join("z-late/nested.txt"), b"later").unwrap();
}

#[test]
fn retires_nested_projection_to_volume_only_while_engine_holds_volume() {
    let (_temp, root) = volume_root();
    write_nested(&root);
    let engine = File::open(root.join(CANONICAL_VOLUME)).unwrap();
    let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
    let files: Vec<_> = plan.regular_files().map(Path::to_path_buf).collect();
    assert!(files.iter().any(|p| p.ends_with("z-child/state")));
    plan.retire(&engine).unwrap();
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"durable authority"
    );
    assert!(!root.join("z-child").exists());
    assert!(!root.join("z-late").exists());
    drop(engine);
}

#[test]
fn wrong_volume_identity_is_rejected_before_deletes() {
    let (_temp, root) = volume_root();
    write_nested(&root);
    let other = tempfile::NamedTempFile::new().unwrap();
    other.as_file().write_all(b"other").unwrap();
    let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
    let err = plan.retire(other.as_file()).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(root.join("z-child/state").exists());
}

#[test]
fn nested_unreceipted_astrid_volume_is_not_skipped_from_regular_files() {
    let (_temp, root) = volume_root();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested").join(CANONICAL_VOLUME), b"unreceipted").unwrap();
    let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
    let files: Vec<_> = plan.regular_files().map(Path::to_path_buf).collect();
    assert!(
        files
            .iter()
            .any(|p| p.as_path() == Path::new("nested").join(CANONICAL_VOLUME)),
        "nested astrid.volume must remain in regular_files for receipt require_file: {files:?}"
    );
    assert!(!files.iter().any(|p| p.as_os_str() == CANONICAL_VOLUME));
}

#[test]
fn post_preflight_nested_replacement_preserves_all_entries() {
    let (_temp, root) = volume_root();
    write_nested(&root);
    let replacement = root.parent().unwrap().join("replacement");
    fs::write(&replacement, b"replacement").unwrap();
    let err = retire_with_hook(&root, || {
        fs::rename(&replacement, root.join("z-child/state")).unwrap();
    })
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        fs::read(root.join("z-child/state")).unwrap(),
        b"replacement"
    );
    assert!(root.join("z-late/nested.txt").exists());
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"durable authority"
    );
}

#[test]
fn post_preflight_volume_swap_preserves_projection() {
    let (_temp, root) = volume_root();
    write_nested(&root);
    let junk = root.parent().unwrap().join("junk-volume");
    fs::write(&junk, b"replacement volume").unwrap();
    let err = retire_with_hook(&root, || {
        fs::remove_file(root.join(CANONICAL_VOLUME)).unwrap();
        fs::rename(&junk, root.join(CANONICAL_VOLUME)).unwrap();
    })
    .unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(root.join("z-child/state").exists());
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"replacement volume"
    );
}

#[test]
fn inventory_change_after_prepare_is_rejected() {
    let (_temp, root) = volume_root();
    write_nested(&root);
    let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
    fs::write(root.join("late-entry.txt"), b"after prepare").unwrap();
    let engine = File::open(root.join(CANONICAL_VOLUME)).unwrap();
    let err = plan.retire(&engine).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert!(root.join("late-entry.txt").exists());
    assert!(root.join("z-child/state").exists());
}

#[test]
fn non_ntfs_reported_filesystem_is_rejected_at_prepare_before_deletes() {
    // Fixture lives on the host volume (typically NTFS). Override only the
    // reported filesystem string at the shared opener's GetVolume gate so the
    // production Unsupported path is exercised without a second opener.
    for name in ["FAT32", "exFAT", "ReFS"] {
        let (_temp, root) = volume_root();
        write_nested(&root);
        let _override = ReportedFilesystemOverride::install(name);
        // Ok lacks Debug; use .err().expect to avoid deriving Debug on the plan type.
        let err = PreparedProjectionRetirement::prepare(&root)
            .err()
            .expect(name);
        assert_eq!(err.kind(), io::ErrorKind::Unsupported, "{name}: {err}");
        // No retirement deletes: nested sources must remain intact.
        assert!(root.join("z-child/state").is_file(), "{name}");
        assert!(root.join("z-late/nested.txt").is_file(), "{name}");
        assert_eq!(
            fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
            b"durable authority",
            "{name}"
        );
    }
}

#[test]
fn ntfs_prepare_and_retire_still_succeeds_without_filesystem_override() {
    let (_temp, root) = volume_root();
    write_nested(&root);
    let engine = File::open(root.join(CANONICAL_VOLUME)).unwrap();
    let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
    plan.retire(&engine).unwrap();
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"durable authority"
    );
    assert!(!root.join("z-child").exists());
}

#[test]
fn root_replacement_before_retire_is_blocked_or_rejected() {
    let (_temp, root) = volume_root();
    write_nested(&root);
    let plan = PreparedProjectionRetirement::prepare(&root).unwrap();
    let relocated = root.parent().unwrap().join("relocated");
    let rename_result = fs::rename(&root, &relocated);
    let engine_path = if rename_result.is_ok() {
        relocated.join(CANONICAL_VOLUME)
    } else {
        root.join(CANONICAL_VOLUME)
    };
    let engine = File::open(&engine_path);
    match (rename_result, engine) {
        (Ok(()), Ok(engine)) => {
            let err = plan.retire(&engine).unwrap_err();
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::NotFound
                        | io::ErrorKind::PermissionDenied
                        | io::ErrorKind::InvalidData
                ),
                "unexpected kind {:?}",
                err.kind()
            );
        },
        (Err(_), _) => {
            // Rename blocked by no-share-delete root — valid outcome.
            let engine = File::open(root.join(CANONICAL_VOLUME)).unwrap();
            plan.retire(&engine).unwrap();
        },
        (Ok(()), Err(_)) => panic!("relocated root missing volume"),
    }
}

#[cfg(windows)]
fn try_junction(link: &Path, target: &Path) -> bool {
    Command::new("cmd")
        .args([
            "/C",
            "mklink",
            "/J",
            &link.to_string_lossy(),
            &target.to_string_lossy(),
        ])
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn post_preflight_junction_swap_preserves_outside_sentinel() {
    let (_temp, root) = volume_root();
    write_nested(&root);
    let outside = root.parent().unwrap().join("outside");
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"outside").unwrap();
    let err = retire_with_hook(&root, || {
        fs::remove_dir_all(root.join("z-child")).unwrap();
        assert!(
            try_junction(&root.join("z-child"), &outside),
            "junction fixture must be established to prove redirect rejection"
        );
    })
    .expect_err("retirement must reject the substituted junction");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
}
