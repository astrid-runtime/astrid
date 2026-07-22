//! Filesystem persistence for Ed25519 signing keys.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

use crate::KeyPair;

const SECRET_KEY_LEN: usize = 32;
const PARTIAL_READ_RETRIES: usize = 25;
const PARTIAL_READ_DELAY: Duration = Duration::from_millis(10);

/// Load an Ed25519 keypair from `key_path`, or atomically claim the path and
/// create a new owner-only key when it does not exist.
///
/// The generated key is synced to an owner-only temporary file, then linked
/// into place without replacement. If another process wins the race, this
/// function reads and returns the winner's key.
///
/// # Errors
///
/// Returns an I/O error when the key cannot be read or persisted, or when an
/// existing file is not exactly one valid 32-byte Ed25519 secret key.
pub fn load_or_generate_keypair(key_path: &Path) -> io::Result<KeyPair> {
    match fs::read(key_path) {
        Ok(bytes) => return decode_key_after_concurrent_create(key_path, &bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error),
    }

    let parent = key_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let keypair = KeyPair::generate();
    let temporary_path = parent.join(format!(
        ".astrid-runtime-key-{}.tmp",
        hex::encode(keypair.public_key_bytes())
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(&temporary_path)?;
    let write_result = (|| {
        file.write_all(&keypair.secret_key_bytes())?;
        file.sync_all()
    })();
    drop(file);
    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary_path);
        return Err(error);
    }

    let link_result = fs::hard_link(&temporary_path, key_path);
    let _ = fs::remove_file(&temporary_path);
    match link_result {
        Ok(()) => {
            sync_parent_directory(parent)?;
            Ok(keypair)
        },
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            read_key_after_concurrent_create(key_path)
        },
        Err(error) => Err(error),
    }
}

fn decode_key_after_concurrent_create(key_path: &Path, bytes: &[u8]) -> io::Result<KeyPair> {
    if bytes.len() == SECRET_KEY_LEN {
        return decode_key(key_path, bytes);
    }

    for _ in 0..PARTIAL_READ_RETRIES {
        std::thread::sleep(PARTIAL_READ_DELAY);
        let bytes = fs::read(key_path)?;
        if bytes.len() == SECRET_KEY_LEN {
            return decode_key(key_path, &bytes);
        }
    }
    decode_key(key_path, &fs::read(key_path)?)
}

fn read_key_after_concurrent_create(key_path: &Path) -> io::Result<KeyPair> {
    decode_key_after_concurrent_create(key_path, &fs::read(key_path)?)
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> io::Result<()> {
    fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent_directory(_parent: &Path) -> io::Result<()> {
    Ok(())
}

fn decode_key(key_path: &Path, bytes: &[u8]) -> io::Result<KeyPair> {
    KeyPair::from_secret_key(bytes).map_err(|error| {
        io::Error::other(format!(
            "invalid signing key at {}: {error}",
            key_path.display()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/runtime.key");
        let first = load_or_generate_keypair(&path).unwrap();
        let second = load_or_generate_keypair(&path).unwrap();
        assert_eq!(first.public_key_bytes(), second.public_key_bytes());
        assert_eq!(fs::read(path).unwrap().len(), 32);
    }

    #[cfg(unix)]
    #[test]
    fn generated_key_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.key");
        load_or_generate_keypair(&path).unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn malformed_existing_key_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.key");
        fs::write(&path, b"short").unwrap();
        let error = load_or_generate_keypair(&path).unwrap_err();
        assert!(error.to_string().contains("invalid signing key"));
    }

    #[test]
    fn partial_concurrent_create_is_retried() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("runtime.key");
        fs::write(&path, []).unwrap();
        let expected = KeyPair::generate();
        let secret = expected.secret_key_bytes();
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(20));
            fs::write(writer_path, secret).unwrap();
        });

        let loaded = load_or_generate_keypair(&path).unwrap();
        writer.join().unwrap();
        assert_eq!(loaded.public_key_bytes(), expected.public_key_bytes());
    }

    #[test]
    fn concurrent_first_start_uses_one_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = std::sync::Arc::new(dir.path().join("runtime.key"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers = (0..8)
            .map(|_| {
                let path = std::sync::Arc::clone(&path);
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_generate_keypair(&path)
                        .unwrap()
                        .public_key_bytes()
                        .to_owned()
                })
            })
            .collect::<Vec<_>>();
        let identities = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();

        assert!(identities.iter().all(|identity| identity == &identities[0]));
        assert_eq!(fs::read(path.as_ref()).unwrap().len(), SECRET_KEY_LEN);
    }
}
