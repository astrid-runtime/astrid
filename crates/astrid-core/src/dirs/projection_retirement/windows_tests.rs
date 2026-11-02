use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io;
use std::os::windows::fs::symlink_dir;
use std::path::Path;
use std::process::Command;

use crate::platform_fs::windows_projection::{
    EntryKind, OpenedDirectory, directory_list_count, fail_directory_flush,
    reset_directory_list_count,
};

const CANONICAL_VOLUME: &str = "astrid.volume";

fn volume(root: &Path) {
    fs::write(root.join(CANONICAL_VOLUME), b"canonical media").unwrap();
}

fn junction(link: &Path, target: &Path) {
    let status = Command::new("cmd.exe")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .status()
        .unwrap();
    assert!(status.success(), "failed to create directory junction");
}

struct RestoreDirectoryFlush;

impl Drop for RestoreDirectoryFlush {
    fn drop(&mut self) {
        fail_directory_flush(false);
    }
}

fn retire_with_hook(path: &Path, after_preflight: impl FnOnce()) -> io::Result<()> {
    super::retire_after_preflight(path, after_preflight)
}

fn retire_after_proven_flush(path: &Path, after_flush: impl FnOnce()) -> io::Result<()> {
    // Production `retire_after_preflight` stages with the injection after
    // `prove_flush`. The existing after-preflight hook is before validate.
    let root = OpenedDirectory::open_existing(path)?;
    let entries = super::inventory(&root, true)?;
    super::validate_inventory(&root, &entries)?;
    super::prove_flush(&root, &entries, true)?;
    after_flush();
    let retirement = super::retire_entries(&root, &entries, true)
        .and_then(|()| super::validate_survivor(&root, &entries));
    super::finish_retirement(retirement, root.sync_all())
}

fn retire_portable_red_control(root: &Path, after_preflight: impl FnOnce()) -> io::Result<()> {
    preflight_portable(root)?;
    after_preflight();
    let mut entries = fs::read_dir(root)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        if entry.file_name() == OsStr::new(CANONICAL_VOLUME) {
            continue;
        }
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            crate::dirs::retire_legacy_source_tree(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
    }
    File::open(root)?.sync_all()?;
    Ok(())
}

fn preflight_portable(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("runtime projection is redirected: {}", path.display()),
        ));
    }
    if metadata.is_dir() {
        for entry in fs::read_dir(path)? {
            preflight_portable(&entry?.path())?;
        }
        return Ok(());
    }
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "runtime projection contains a special entry: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[test]
fn late_nested_junction_preserves_earlier_file() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir_all(root.join("z-late")).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(outside.join("sentinel"), b"outside").unwrap();
    junction(&root.join("z-late/nested"), &outside);
    assert!(crate::dirs::retire_projection_root(&root).is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
}

#[test]
fn redirected_root_junction_preserves_target() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"keep").unwrap();
    let root = directory.path().join("redirect");
    junction(&root, &target);
    assert!(crate::dirs::retire_projection_root(&root).is_err());
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"keep");
}

#[test]
fn redirected_root_symlink_preserves_target() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("target");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("sentinel"), b"keep").unwrap();
    let root = directory.path().join("redirect");
    symlink_dir(&target, &root).unwrap();
    assert!(crate::dirs::retire_projection_root(&root).is_err());
    assert_eq!(fs::read(target.join("sentinel")).unwrap(), b"keep");
}

#[test]
fn missing_root_preserves_existing_ancestor() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("sentinel"), b"keep").unwrap();
    let error =
        crate::dirs::retire_projection_root(&directory.path().join("missing/nested")).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        fs::read(directory.path().join("sentinel")).unwrap(),
        b"keep"
    );
}

#[test]
fn portable_red_control_missing_root_preserves_existing_ancestor() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("sentinel"), b"keep").unwrap();
    let error =
        retire_portable_red_control(&directory.path().join("missing/nested"), || {}).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        fs::read(directory.path().join("sentinel")).unwrap(),
        b"keep"
    );
}

#[test]
fn post_preflight_replacement_preserves_all_entries() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("z-child")).unwrap();
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"original").unwrap();
    let replacement = directory.path().join("replacement");
    fs::write(&replacement, b"replacement").unwrap();
    let result = retire_with_hook(&root, || {
        fs::rename(&replacement, root.join("z-child/state")).unwrap();
    });
    assert!(result.is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
    assert_eq!(
        fs::read(root.join("z-child/state")).unwrap(),
        b"replacement"
    );
}

#[test]
fn post_flush_replacement_preserves_all_entries() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("z-child")).unwrap();
    volume(&root);
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"original").unwrap();
    let replacement = directory.path().join("replacement");
    fs::write(&replacement, b"replacement").unwrap();
    // Replace the first deletable child after flush and before the delete
    // reopen. A missing captured-identity check would unlink this file and
    // then the later nested original.
    let result = retire_after_proven_flush(&root, || {
        fs::rename(&replacement, root.join("a-earlier")).unwrap();
    });
    assert!(result.is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"replacement");
    assert_eq!(fs::read(root.join("z-child/state")).unwrap(), b"original");
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"canonical media"
    );
}

#[test]
fn portable_red_control_first_child_replacement_unlinks_later_nested() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("z-child")).unwrap();
    volume(&root);
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"original").unwrap();
    let replacement = directory.path().join("replacement");
    fs::write(&replacement, b"replacement").unwrap();
    let _result = retire_portable_red_control(&root, || {
        fs::rename(&replacement, root.join("a-earlier")).unwrap();
    });
    assert!(!root.join("a-earlier").exists());
    assert!(!root.join("z-child").exists());
}

#[test]
fn portable_red_control_replacement_deletes_earlier_file() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("z-child")).unwrap();
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"original").unwrap();
    let replacement = directory.path().join("replacement");
    fs::write(&replacement, b"replacement").unwrap();
    let _result = retire_portable_red_control(&root, || {
        fs::rename(&replacement, root.join("z-child/state")).unwrap();
    });
    assert!(!root.join("a-earlier").exists());
}

#[test]
fn post_preflight_volume_swap_preserves_projection() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    let junk = directory.path().join("junk");
    fs::write(&junk, b"replacement volume").unwrap();
    let parked = directory.path().join("parked");
    let result = retire_with_hook(&root, || {
        fs::rename(root.join(CANONICAL_VOLUME), &parked).unwrap();
        fs::rename(&junk, root.join(CANONICAL_VOLUME)).unwrap();
        fs::rename(&parked, root.join("a-earlier")).unwrap();
    });
    assert!(result.is_err());
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"replacement volume"
    );
    assert_eq!(
        fs::read(root.join("a-earlier")).unwrap(),
        b"canonical media"
    );
}

#[test]
fn portable_red_control_volume_swap_deletes_real_volume() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    let junk = directory.path().join("junk");
    fs::write(&junk, b"replacement volume").unwrap();
    let parked = directory.path().join("parked");
    let _result = retire_portable_red_control(&root, || {
        fs::rename(root.join(CANONICAL_VOLUME), &parked).unwrap();
        fs::rename(&junk, root.join(CANONICAL_VOLUME)).unwrap();
        fs::rename(&parked, root.join("a-earlier")).unwrap();
    });
    assert!(!root.join("a-earlier").exists());
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"replacement volume"
    );
}

#[test]
fn post_preflight_junction_swap_preserves_outside_sentinel() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir_all(root.join("z-child")).unwrap();
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"original").unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"outside").unwrap();
    let moved = directory.path().join("moved");
    let result = retire_with_hook(&root, || {
        fs::rename(root.join("z-child"), &moved).unwrap();
        junction(&root.join("z-child"), &outside);
    });
    assert!(result.is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
    assert_eq!(fs::read(outside.join("sentinel")).unwrap(), b"outside");
}

#[test]
fn portable_red_control_junction_swap_loses_earlier_or_outside() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    let outside = directory.path().join("outside");
    fs::create_dir_all(root.join("z-child")).unwrap();
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"original").unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("sentinel"), b"outside").unwrap();
    let moved = directory.path().join("moved");
    let _result = retire_portable_red_control(&root, || {
        fs::rename(root.join("z-child"), &moved).unwrap();
        junction(&root.join("z-child"), &outside);
    });
    let earlier_gone = !root.join("a-earlier").exists();
    let outside_gone = !outside.join("sentinel").exists();
    assert!(earlier_gone || outside_gone);
}

#[test]
fn public_retire_lists_once_per_directory_not_per_child() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    volume(root);
    for number in 0..32 {
        fs::write(root.join(format!("projection-{number}")), b"projection").unwrap();
    }
    reset_directory_list_count();
    crate::dirs::retire_projection_root(root).unwrap();
    assert_eq!(directory_list_count(), 3);
    assert_eq!(fs::read_dir(root).unwrap().count(), 1);
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"canonical media"
    );
}

#[test]
fn canonical_volume_is_only_survivor() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    volume(root);
    fs::create_dir(root.join("projection")).unwrap();
    fs::write(root.join("projection").join("state"), b"projection").unwrap();
    fs::write(root.join("astrid.volume.extra"), b"projection").unwrap();
    crate::dirs::retire_projection_root(root).unwrap();
    let mut names = fs::read_dir(root)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    names.sort();
    assert_eq!(names, [OsString::from(CANONICAL_VOLUME)]);
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"canonical media"
    );
}

#[test]
fn case_folded_canonical_volume_is_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("ASTRID.VOLUME"), b"canonical media").unwrap();
    fs::write(root.join("a-earlier"), b"projection").unwrap();
    crate::dirs::retire_projection_root(&root).unwrap();
    assert_eq!(
        fs::read(root.join("ASTRID.VOLUME")).unwrap(),
        b"canonical media"
    );
    assert!(!root.join("a-earlier").exists());
}

#[test]
fn canonical_volume_must_be_a_regular_file() {
    let directory = tempfile::tempdir().unwrap();
    fs::create_dir(directory.path().join(CANONICAL_VOLUME)).unwrap();
    fs::write(directory.path().join("a-earlier"), b"keep").unwrap();
    assert!(crate::dirs::retire_projection_root(directory.path()).is_err());
    assert!(directory.path().join("a-earlier").exists());
}

#[test]
fn colliding_canonical_volume_names_fail_closed() {
    let mut seen = false;
    super::note_canonical_volume(OsStr::new("ASTRID.VOLUME"), EntryKind::File, &mut seen).unwrap();
    assert!(
        super::note_canonical_volume(OsStr::new("astrid.volume"), EntryKind::File, &mut seen)
            .is_err()
    );
    let mut unseen = false;
    assert!(
        super::note_canonical_volume(
            OsStr::new("ASTRID.VOLUME"),
            EntryKind::Directory,
            &mut unseen
        )
        .is_err()
    );
}

#[test]
fn public_retire_preserves_files_when_directory_flush_fails() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("z-child")).unwrap();
    volume(&root);
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"nested").unwrap();
    let _restore = RestoreDirectoryFlush;
    fail_directory_flush(true);
    let error = crate::dirs::retire_projection_root(&root).unwrap_err();
    assert_eq!(error.to_string(), "test: directory flush failed");
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
    assert_eq!(fs::read(root.join("z-child/state")).unwrap(), b"nested");
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"canonical media"
    );
}

#[test]
fn projection_root_handle_can_request_flush() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    OpenedDirectory::open_existing(&root)
        .unwrap()
        .sync_all()
        .unwrap();
}

struct RestoreRetirementHooks;

impl Drop for RestoreRetirementHooks {
    fn drop(&mut self) {
        super::BEFORE_DISPOSITION.with_borrow_mut(|hook| *hook = None);
        crate::platform_fs::windows_projection::remote_volume_after_open(false);
        fail_directory_flush(false);
    }
}

#[test]
fn public_retire_rejects_remote_opened_volume_before_inventory() {
    use crate::platform_fs::windows_projection::remote_volume_after_open;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    fs::write(root.join("projection"), b"preserve").unwrap();
    let _restore = RestoreRetirementHooks;
    reset_directory_list_count();
    // The real root handle has already been opened when the injected remote
    // characteristic is consumed. A pre-open path classification cannot pass
    // this guard, including when its drive mapping changes before open.
    remote_volume_after_open(true);
    let error = crate::dirs::retire_projection_root(&root).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("not a local writable disk volume")
    );
    assert_eq!(directory_list_count(), 0);
    assert_eq!(fs::read(root.join("projection")).unwrap(), b"preserve");
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"canonical media"
    );
}

#[test]
fn public_retire_accepts_canonicalized_local_volume_path() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    fs::write(root.join("projection"), b"remove").unwrap();
    let canonical = fs::canonicalize(&root).unwrap();
    crate::dirs::retire_projection_root(&canonical).unwrap();
    assert!(!root.join("projection").exists());
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"canonical media"
    );
}

#[test]
fn public_retire_locks_file_and_directory_names_through_disposition() {
    use std::cell::Cell;
    use std::rc::Rc;

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    fs::write(root.join("file"), b"captured file").unwrap();
    fs::create_dir(root.join("nested")).unwrap();
    let _restore = RestoreRetirementHooks;
    let attempts = Rc::new(Cell::new(0_usize));
    let observed = Rc::clone(&attempts);
    let captured_root = root.clone();
    let outside = directory.path().join("outside");
    super::BEFORE_DISPOSITION.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |name| {
            // This is after the final parent-relative identity check. The
            // retained delete handle must deny rename until disposition.
            assert!(fs::rename(captured_root.join(name), &outside).is_err());
            assert!(captured_root.join(name).exists());
            assert!(!outside.exists());
            observed.set(observed.get().strict_add(1));
        }));
    });
    crate::dirs::retire_projection_root(&root).unwrap();
    assert_eq!(attempts.get(), 2);
    assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
}

#[test]
fn public_retire_rejects_existing_directory_delete_authority_without_unlinking() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir_all(root.join("z-child")).unwrap();
    volume(&root);
    fs::write(root.join("a-earlier"), b"keep").unwrap();
    fs::write(root.join("z-child/state"), b"nested").unwrap();
    let parent = OpenedDirectory::open_existing(&root).unwrap();
    // Production delete open, not a path-based second opener. Exclusive DELETE
    // omits FILE_SHARE_DELETE, so retirement cannot reopen this namespace.
    let existing = parent.open_directory(OsStr::new("z-child"), true).unwrap();
    assert!(crate::dirs::retire_projection_root(&root).is_err());
    assert_eq!(fs::read(root.join("a-earlier")).unwrap(), b"keep");
    assert_eq!(fs::read(root.join("z-child/state")).unwrap(), b"nested");
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"canonical media"
    );
    drop(existing);
    crate::dirs::retire_projection_root(&root).unwrap();
}

#[test]
fn public_retire_rejects_existing_delete_authority_without_unlinking() {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    let file = root.join("a-file");
    fs::write(&file, b"preserve").unwrap();
    let existing = fs::OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(&file)
        .unwrap();
    assert!(crate::dirs::retire_projection_root(&root).is_err());
    assert_eq!(fs::read(&file).unwrap(), b"preserve");
    drop(existing);
    crate::dirs::retire_projection_root(&root).unwrap();
}

#[test]
fn public_retire_retains_security_error_when_final_flush_also_fails() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("root");
    fs::create_dir(&root).unwrap();
    volume(&root);
    fs::write(root.join("projection"), b"remove").unwrap();
    let _restore = RestoreRetirementHooks;
    let captured_root = root.clone();
    super::BEFORE_DISPOSITION.with_borrow_mut(|hook| {
        *hook = Some(Box::new(move |_| {
            fs::write(captured_root.join("unreceipted"), b"preserve").unwrap();
            fail_directory_flush(true);
        }));
    });
    let error = crate::dirs::retire_projection_root(&root).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(
        error
            .to_string()
            .contains("projection changed during retirement")
    );
    assert_eq!(fs::read(root.join("unreceipted")).unwrap(), b"preserve");
    assert_eq!(
        fs::read(root.join(CANONICAL_VOLUME)).unwrap(),
        b"canonical media"
    );
}

#[test]
fn final_flush_failure_preserves_original_os_error() {
    let error = super::finish_retirement(
        Err(io::Error::from_raw_os_error(5)),
        Err(io::Error::other("secondary flush failure")),
    )
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(5));
    let flush_only =
        super::finish_retirement(Ok(()), Err(io::Error::from_raw_os_error(6))).unwrap_err();
    assert_eq!(flush_only.raw_os_error(), Some(6));
}
