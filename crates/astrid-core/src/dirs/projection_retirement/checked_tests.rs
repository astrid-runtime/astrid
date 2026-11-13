//! Byte verification shares retirement authority without imposing private-file modes.

use std::fs::{self, File};
use std::io;
use std::path::Path;

use super::{CANONICAL_VOLUME, PreparedProjectionRetirement};

fn root() -> (tempfile::TempDir, std::path::PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("home");
    fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    set_mode(&root, 0o700);
    fs::write(root.join(CANONICAL_VOLUME), b"durable authority").unwrap();
    (directory, root)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    fs::metadata(path).unwrap().permissions().mode() & 0o777
}

fn require_bytes(file: &mut File, expected: &[u8]) -> io::Result<()> {
    if !PreparedProjectionRetirement::matches_file_from(
        file,
        u64::try_from(expected.len()).unwrap(),
        &mut io::Cursor::new(expected),
    )? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "source bytes differ",
        ));
    }
    Ok(())
}

#[test]
fn checked_capture_accepts_readable_runtime_modes_without_repair() {
    let (_directory, root) = root();
    let nested = root.join("nested");
    fs::create_dir(&nested).unwrap();
    let path = nested.join("state");
    fs::write(&path, b"captured generation").unwrap();
    #[cfg(unix)]
    {
        set_mode(&nested, 0o755);
        set_mode(&path, 0o644);
    }
    let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
    let mut checked = Vec::new();
    let prepared = PreparedProjectionRetirement::prepare_checked(
        &root,
        |_| true,
        |relative, source| {
            checked.push(relative.to_path_buf());
            require_bytes(source, b"captured generation")
        },
    )
    .unwrap();
    assert_eq!(checked, [Path::new("nested").join("state")]);
    assert_eq!(
        prepared.regular_files().collect::<Vec<_>>(),
        [Path::new("nested/state")]
    );
    #[cfg(unix)]
    {
        assert_eq!(mode(&root), 0o700);
        assert_eq!(mode(&nested), 0o755);
        assert_eq!(mode(&path), 0o644);
    }
    prepared.retire(&volume).unwrap();
    assert_eq!(fs::read_dir(root).unwrap().count(), 1);
}

#[test]
fn late_byte_mismatch_preserves_every_preflight_entry() {
    let (_directory, root) = root();
    fs::write(root.join("a"), b"earlier").unwrap();
    fs::write(root.join("z"), b"later").unwrap();
    let result = PreparedProjectionRetirement::prepare_checked(
        &root,
        |_| true,
        |relative, source| {
            if relative == Path::new("a") {
                require_bytes(source, b"earlier")
            } else {
                require_bytes(source, b"wrong")
            }
        },
    );
    let error = result
        .err()
        .expect("later source mismatch must fail preflight");
    assert!(error.to_string().contains("source bytes differ"), "{error}");
    assert_eq!(fs::read(root.join("a")).unwrap(), b"earlier");
    assert_eq!(fs::read(root.join("z")).unwrap(), b"later");
    assert_eq!(fs::read_dir(root).unwrap().count(), 3);
}

#[test]
fn checked_leaf_replacement_is_refused_after_callback() {
    let (_directory, root) = root();
    fs::write(root.join("a"), b"untouched").unwrap();
    fs::write(root.join("z"), b"captured").unwrap();
    let result = PreparedProjectionRetirement::prepare_checked(
        &root,
        |relative| relative == Path::new("z"),
        |_, source| {
            require_bytes(source, b"captured")?;
            fs::rename(root.join("z"), root.join("moved"))?;
            fs::write(root.join("z"), b"replacement")
        },
    );
    assert!(
        result.is_err(),
        "a matching stream cannot authorize a replacement"
    );
    assert_eq!(fs::read(root.join("a")).unwrap(), b"untouched");
    assert_eq!(fs::read(root.join("z")).unwrap(), b"replacement");
    assert_eq!(fs::read(root.join("moved")).unwrap(), b"captured");
}

#[test]
fn unchecked_sources_do_not_gain_a_content_read_requirement() {
    let (_directory, root) = root();
    fs::write(root.join("excluded"), b"metadata-only").unwrap();
    fs::write(root.join("selected"), b"content-checked").unwrap();
    #[cfg(unix)]
    set_mode(&root.join("excluded"), 0o000);
    let volume = File::open(root.join(CANONICAL_VOLUME)).unwrap();
    let mut checked = Vec::new();
    let prepared = PreparedProjectionRetirement::prepare_checked(
        &root,
        |relative| relative != Path::new("excluded"),
        |relative, source| {
            checked.push(relative.to_path_buf());
            require_bytes(source, b"content-checked")
        },
    )
    .unwrap();
    assert_eq!(checked, [Path::new("selected")]);
    #[cfg(unix)]
    assert_eq!(mode(&root.join("excluded")), 0o000);
    prepared.retire(&volume).unwrap();
    assert_eq!(fs::read_dir(root).unwrap().count(), 1);
}

#[test]
fn callback_error_cannot_delete_earlier_verified_entries() {
    let (_directory, root) = root();
    fs::write(root.join("a"), b"untouched").unwrap();
    fs::write(root.join("z"), b"also untouched").unwrap();
    let result = PreparedProjectionRetirement::prepare_checked(
        &root,
        |_| true,
        |relative, _| {
            if relative == Path::new("z") {
                Err(io::Error::other("injected verification failure"))
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(fs::read(root.join("a")).unwrap(), b"untouched");
    assert_eq!(fs::read(root.join("z")).unwrap(), b"also untouched");
}

#[cfg(unix)]
#[test]
fn checked_parent_replacement_is_refused_before_returning_plan() {
    let (_directory, root) = root();
    fs::create_dir(root.join("nested")).unwrap();
    fs::write(root.join("nested/state"), b"captured").unwrap();
    fs::write(root.join("a"), b"untouched").unwrap();
    let result = PreparedProjectionRetirement::prepare_checked(
        &root,
        |_| true,
        |relative, source| {
            if relative == Path::new("nested/state") {
                require_bytes(source, b"captured")?;
                fs::rename(root.join("nested"), root.join("moved"))?;
                fs::create_dir(root.join("nested"))?;
                fs::write(root.join("nested/state"), b"replacement")?;
            }
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(fs::read(root.join("a")).unwrap(), b"untouched");
    assert_eq!(fs::read(root.join("nested/state")).unwrap(), b"replacement");
    assert_eq!(fs::read(root.join("moved/state")).unwrap(), b"captured");
}
