use std::process::{Command, Output};
use std::sync::mpsc;
use std::time::Duration;

use super::*;

const CHILD_PATH: &str = "ASTRID_STORAGE_TEST_FOREIGN_OPEN";

#[test]
#[ignore = "subprocess entry point"]
fn foreign_process_cannot_open_owned_volume() {
    let path = std::env::var_os(CHILD_PATH).expect("subprocess fixture path");
    let error = HostedFileVolume::open(PathBuf::from(path)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
}

fn try_foreign_open(path: &std::path::Path) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "volume::hosted::open_tests::foreign_process_cannot_open_owned_volume",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD_PATH, path)
        .output()
        .unwrap()
}

#[test]
fn foreign_open_cannot_remove_in_flight_reclaim_artifacts() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let staged = reclaim::temp_path(&path);
    std::fs::write(&staged, b"in-flight fixture").unwrap();
    let output = try_foreign_open(&path);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(std::fs::read(&staged).unwrap(), b"in-flight fixture");
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    assert!(!staged.exists());
    drop(reopened);
}

#[test]
fn foreign_open_is_fenced_during_reclaim_inode_swap() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let region = VolumeRegion::new("objects").unwrap();
    let volume = HostedFileVolume::open(&path).unwrap();
    volume.create_region(&region, true).unwrap();
    volume.write_region_at(&region, 0, b"protected").unwrap();
    volume.sync().unwrap();
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    reclaim::set_test_swap_hook(
        path.clone(),
        Box::new(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        }),
    );
    let reclaiming = Arc::clone(&volume);
    let task = std::thread::spawn(move || reclaiming.reclaim());
    entered_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let output = try_foreign_open(&path);
    let staged_survives = reclaim::temp_path(&path).exists();
    release_tx.send(()).unwrap();
    task.join().unwrap().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(staged_survives);
    drop(volume);
    let reopened = HostedFileVolume::open(&path).unwrap();
    let mut bytes = [0; 9];
    reopened.read_region_at(&region, 0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"protected");
}

#[test]
fn opener_rejects_a_retired_descriptor_after_atomic_replacement() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let stale = super::open::open_regular(&path, false).unwrap();
    volume.reclaim().unwrap();
    fs2::FileExt::try_lock_exclusive(&stale).unwrap();
    assert_eq!(
        super::open::require_current(&stale, &path)
            .unwrap_err()
            .kind(),
        io::ErrorKind::WouldBlock
    );
    let output = try_foreign_open(&path);
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn artifact_promotion_transfers_the_locked_open_description() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    drop(HostedFileVolume::open(&path).unwrap());
    std::fs::rename(&path, reclaim::previous_path(&path)).unwrap();
    let promoted = reclaim::recover_artifacts(&path).unwrap();
    // A fork can temporarily inherit this open description even with
    // close-on-exec enabled. Reusing it must not contend with its own lock.
    let inherited = promoted.try_clone().unwrap();
    #[cfg(unix)]
    fs2::FileExt::try_lock_exclusive(&promoted).unwrap();
    super::open::require_current(&promoted, &path).unwrap();
    assert!(try_foreign_open(&path).status.success());
    fs2::FileExt::unlock(&promoted).unwrap();
    drop(inherited);
    drop(promoted);
    drop(HostedFileVolume::open(&path).unwrap());
    assert!(!reclaim::previous_path(&path).exists());
}

#[test]
fn first_create_contender_opens_existing_inode_without_modifying_it() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("astrid.volume");
    let volume = HostedFileVolume::open(&path).unwrap();
    let before = std::fs::read(&path).unwrap();
    let contender = super::open::open_regular(&path, true).unwrap();
    super::open::require_current(&contender, &path).unwrap();
    assert!(fs2::FileExt::try_lock_exclusive(&contender).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    drop(volume);
}
