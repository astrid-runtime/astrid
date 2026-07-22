//! Filesystem persistence for Ed25519 signing keys.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::KeyPair;

/// Load an Ed25519 keypair from `key_path`, or atomically claim the path and
/// create a new owner-only key when it does not exist.
///
/// A `create_new` open prevents two first-start processes from silently
/// replacing one another's runtime identity. If another process wins the
/// race, this function reads and returns the winner's key.
///
/// # Errors
///
/// Returns an I/O error when the key cannot be read or persisted, or when an
/// existing file is not exactly one valid 32-byte Ed25519 secret key.
pub fn load_or_generate_keypair(key_path: &Path) -> io::Result<KeyPair> {
    match fs::read(key_path) {
        Ok(bytes) => return decode_key(key_path, &bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Err(error) => return Err(error),
    }

    if let Some(parent) = key_path.parent() {
        fs::create_dir_all(parent)?;
    }

    let keypair = KeyPair::generate();
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(key_path) {
        Ok(mut file) => {
            file.write_all(&keypair.secret_key_bytes())?;
            file.sync_all()?;
            Ok(keypair)
        },
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let bytes = fs::read(key_path)?;
            decode_key(key_path, &bytes)
        },
        Err(error) => Err(error),
    }
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
}
