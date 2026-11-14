//! Public append seam: lazy namespace creation and independent file ownership.

use crate::platform_fs::{
    PrivateAppendRoot, PrivateProjectionInspection, ensure_private_directory,
};
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::Path;
use std::sync::Arc;

// Windows fault injectors share the native test lock. Keep it for the test,
// and use a root whose ACL is private before the public API admits it.
fn private_root() -> (
    tempfile::TempDir,
    Option<std::sync::MutexGuard<'static, ()>>,
) {
    #[cfg(windows)]
    {
        let guard = crate::platform_fs::windows::private_test_guard();
        (
            crate::platform_fs::windows::private_test_directory(),
            Some(guard),
        )
    }
    #[cfg(unix)]
    {
        (tempfile::tempdir().unwrap(), None)
    }
}

fn root(path: &Path) -> PrivateAppendRoot {
    ensure_private_directory(path).unwrap();
    PrivateProjectionInspection::try_open(path)
        .unwrap()
        .capture_append_root()
        .unwrap()
}

#[test]
fn append_authority_and_returned_file_are_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PrivateAppendRoot>();
    assert_send_sync::<std::fs::File>();
}

#[test]
fn capture_is_lazy_and_first_open_preserves_atomic_append_after_seek() {
    let (dir, _native_guard) = private_root();
    let append = root(dir.path());
    assert!(!dir.path().join("log").exists());
    let name = Path::new("log/principals/uid/capsule/day.log");
    let mut first = append.open_private_append(name).unwrap();
    assert_eq!(std::fs::metadata(dir.path().join(name)).unwrap().len(), 0);
    first.write_all(b"first\n").unwrap();
    let mut second = append.open_private_append(name).unwrap();
    second.seek(SeekFrom::Start(0)).unwrap();
    second.write_all(b"second\n").unwrap();
    first.write_all(b"third\n").unwrap();
    assert_eq!(
        std::fs::read(dir.path().join(name)).unwrap(),
        b"first\nsecond\nthird\n"
    );
}

#[test]
fn append_root_can_cross_threads_without_a_shared_write_lock() {
    let (dir, _native_guard) = private_root();
    let append = Arc::new(root(dir.path()));
    let threads = (0..4)
        .map(|index| {
            let append = Arc::clone(&append);
            std::thread::spawn(move || {
                let mut file = append
                    .open_private_append(Path::new(&format!("log/{index}/day.log")))
                    .unwrap();
                file.write_all(b"line\n").unwrap();
            })
        })
        .collect::<Vec<_>>();
    for thread in threads {
        thread.join().unwrap();
    }
    for index in 0..4 {
        assert_eq!(
            std::fs::read(dir.path().join(format!("log/{index}/day.log"))).unwrap(),
            b"line\n"
        );
    }
}

#[test]
fn invalid_names_and_nonregular_leaves_fail_without_writing() {
    let (dir, _native_guard) = private_root();
    let append = root(dir.path());
    for name in ["", "../outside", "/absolute"] {
        assert!(append.open_private_append(Path::new(name)).is_err());
    }
    ensure_private_directory(&dir.path().join("directory")).unwrap();
    assert!(append.open_private_append(Path::new("directory")).is_err());
    assert!(!dir.path().join("outside").exists());
}

#[test]
fn ordinary_returned_file_propagates_write_source_errors() {
    struct Failed;
    impl std::io::Read for Failed {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("source failure"))
        }
    }
    let (dir, _native_guard) = private_root();
    let append = root(dir.path());
    let mut file = append.open_private_append(Path::new("day.log")).unwrap();
    let error = std::io::copy(&mut Failed, &mut file).unwrap_err();
    assert!(error.to_string().contains("source failure"));
    assert_eq!(
        std::fs::metadata(dir.path().join("day.log")).unwrap().len(),
        0
    );
}
