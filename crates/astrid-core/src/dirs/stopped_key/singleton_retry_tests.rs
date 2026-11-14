//! Singleton ownership residue does not carry projection authority.

use crate::{dirs::AstridHome, platform_fs};
use std::{
    fs,
    io::Write as _,
    path::{Path, PathBuf},
};

fn fixture(volume: bool) -> (tempfile::TempDir, AstridHome) {
    #[cfg(windows)]
    let directory = tempfile::tempdir_in(std::env::var_os("LOCALAPPDATA").unwrap()).unwrap();
    #[cfg(not(windows))]
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path().join("home"));
    platform_fs::create_private_directory(home.root()).unwrap();
    if volume {
        #[cfg(windows)]
        let mut file =
            platform_fs::create_new_private_file_shared(&home.storage_volume_path()).unwrap();
        #[cfg(unix)]
        let mut file = {
            use std::os::unix::fs::OpenOptionsExt as _;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(home.storage_volume_path())
                .unwrap()
        };
        file.write_all(b"owned media").unwrap();
    }
    (directory, home)
}

fn singleton(home: &AstridHome) {
    let writer = platform_fs::PrivateFileProjection::open(home.root()).unwrap();
    writer.write(Path::new("run/system.lock"), b"").unwrap();
    writer.sync().unwrap();
}

#[derive(Debug, PartialEq, Eq)]
struct Entry {
    path: PathBuf,
    kind: &'static str,
    bytes: Vec<u8>,
    target: Option<PathBuf>,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    identity: (u64, u64, u32, u32, i64, i64),
}

fn snapshot(root: &Path) -> Vec<Entry> {
    fn visit(root: &Path, path: &Path, entries: &mut Vec<Entry>) {
        let metadata = fs::symlink_metadata(path).unwrap();
        let (kind, bytes, target) = if metadata.file_type().is_symlink() {
            ("link", vec![], Some(fs::read_link(path).unwrap()))
        } else if metadata.is_dir() {
            ("directory", vec![], None)
        } else {
            ("file", fs::read(path).unwrap(), None)
        };
        entries.push(Entry {
            path: path.strip_prefix(root).unwrap().to_path_buf(),
            kind,
            bytes,
            target,
            modified: metadata.modified().unwrap(),
            #[cfg(unix)]
            identity: {
                use std::os::unix::fs::MetadataExt as _;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.uid(),
                    metadata.mode(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
        });
        if metadata.is_dir() {
            let mut children = fs::read_dir(path)
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            children.sort_by_key(fs::DirEntry::file_name);
            for child in children {
                visit(root, &child.path(), entries);
            }
        }
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries);
    entries
}

#[test]
fn stopped_volume_and_exact_singleton_admission_is_read_only() {
    let (_directory, home) = fixture(true);
    singleton(&home);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(home.root(), fs::Permissions::from_mode(0o755)).unwrap();
    }
    let before = snapshot(home.root());
    home.ensure().unwrap();
    assert_eq!(
        snapshot(home.root()),
        before,
        "stopped admission must not repair permissions or materialize authority"
    );
    assert!(home.validate_runtime_identity_provisioning().is_err());
}

#[test]
fn fresh_exact_singleton_does_not_invent_durable_authority() {
    let (_directory, home) = fixture(false);
    singleton(&home);
    home.ensure().unwrap();
    assert_eq!(fs::read_dir(home.root()).unwrap().count(), 1);
    assert!(!home.storage_volume_path().exists());
    assert!(!home.layout_version_path().exists());
    assert!(!home.runtime_key_path().exists());
}

#[test]
fn empty_or_extra_run_entries_remain_rejected_without_mutation() {
    for volume in [false, true] {
        for extra in [None, Some("system.ready"), Some("foreign")] {
            let (_directory, home) = fixture(volume);
            if let Some(extra) = extra {
                if extra == "foreign" {
                    platform_fs::create_private_directory(&home.root().join("run")).unwrap();
                } else {
                    singleton(&home);
                }
                let writer = platform_fs::PrivateFileProjection::open(home.root()).unwrap();
                writer
                    .write(&Path::new("run").join(extra), b"unadmitted")
                    .unwrap();
                writer.sync().unwrap();
            } else {
                platform_fs::create_private_directory(&home.root().join("run")).unwrap();
            }
            let before = snapshot(home.root());
            assert_eq!(
                home.ensure().unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(snapshot(home.root()), before);
        }
    }
}

#[cfg(unix)]
#[test]
fn redirected_run_or_singleton_remain_rejected_without_mutation() {
    use std::os::unix::fs::symlink;
    for redirect_run in [false, true] {
        let (_directory, home) = fixture(true);
        singleton(&home);
        let outside = tempfile::tempdir().unwrap();
        let original = if redirect_run {
            home.root().join("run")
        } else {
            home.root().join("run/system.lock")
        };
        let saved = outside.path().join("saved");
        fs::rename(&original, &saved).unwrap();
        symlink(&saved, &original).unwrap();
        let before = snapshot(home.root());
        let outside_before = snapshot(outside.path());
        assert!(home.ensure().is_err());
        assert_eq!(snapshot(home.root()), before);
        assert_eq!(snapshot(outside.path()), outside_before);
    }
}

#[test]
fn nonprivate_singleton_remains_rejected_without_acl_repair() {
    let (_directory, home) = fixture(true);
    singleton(&home);
    let lock = home.root().join("run/system.lock");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o644)).unwrap();
    }
    #[cfg(windows)]
    {
        fs::remove_file(&lock).unwrap();
        fs::write(&lock, b"").unwrap(); // Inherited ACL is not ExactPrivate.
    }
    assert!(platform_fs::validate_private_file(&lock).is_err());
    let before = snapshot(home.root());
    assert!(home.ensure().is_err());
    assert_eq!(snapshot(home.root()), before);
    assert!(platform_fs::validate_private_file(&lock).is_err());
}

#[test]
fn nonprivate_run_remains_rejected_without_acl_repair() {
    let (_directory, home) = fixture(true);
    singleton(&home);
    let run = home.root().join("run");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&run, fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    {
        // Keep the private file; replace only its parent with an inherited-ACL directory.
        let saved = home.root().join("saved.lock");
        fs::rename(run.join("system.lock"), &saved).unwrap();
        fs::remove_dir(&run).unwrap();
        fs::create_dir(&run).unwrap();
        fs::rename(saved, run.join("system.lock")).unwrap();
    }
    assert!(platform_fs::validate_private_directory(&run).is_err());
    let before = snapshot(home.root());
    assert!(home.ensure().is_err());
    assert_eq!(snapshot(home.root()), before);
    assert!(platform_fs::validate_private_directory(&run).is_err());
}
