//! `FSKit`'s sandbox permits Unix IPC inside its own application container.
//! A security-scoped resource URL grants file access, not Unix socket access.

use std::path::{Path, PathBuf};

use crate::storage_provider::StorageMountId;
use base64::Engine as _;

/// Resolve the registered extension container endpoint for this mount.
///
/// # Errors
/// Returns an error for missing account/container state, aliases, nonprivate
/// directories, or paths exceeding the native socket limit.
pub fn callback_path(mount_id: StorageMountId) -> Result<PathBuf, String> {
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())
        .map_err(|error| format!("resolve FSKit container owner: {error}"))?
        .ok_or_else(|| "FSKit container owner has no account record".to_owned())?;
    socket_in_home(&user.dir, mount_id)
}

fn socket_in_home(home: &Path, mount_id: StorageMountId) -> Result<PathBuf, String> {
    let directory = home.join("Library/Containers/org.astrid.runtime.fs.AppEx/Data/tmp");
    // macOS creates this container when the installed extension is registered.
    // Do not imitate container provisioning or fall back to an inaccessible socket.
    let canonical = directory.canonicalize().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            format!("FSKIT_EXTENSION_UNAVAILABLE: FSKit container is unavailable; enable AstridFS first: {error}")
        } else {
            format!("inspect FSKit callback container: {error}")
        }
    })?;
    if canonical != directory {
        return Err("FSKit callback container must not contain symlink aliases".to_owned());
    }
    crate::platform_fs::validate_private_directory(&directory)
        .map_err(|error| format!("validate private FSKit callback container: {error}"))?;
    // Preserve all UUID bits while fitting more home-directory names into sun_path.
    let name =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mount_id.as_uuid().as_bytes());
    let socket = directory.join(name);
    let address = nix::libc::sockaddr_un {
        sun_len: 0,
        sun_family: 0,
        sun_path: [0; _],
    };
    if socket.as_os_str().as_encoded_bytes().len() >= address.sun_path.len() {
        return Err("FSKit callback container path exceeds the Unix socket path limit".to_owned());
    }
    Ok(socket)
}

/// Validate the exact managed endpoint, including its native socket type and owner.
///
/// # Errors
/// Rejects unavailable containers, a different mount endpoint, redirects,
/// non-sockets, foreign owners, or permissions other than 0600.
pub fn validate_callback_path(mount_id: StorageMountId, path: &Path) -> Result<(), String> {
    validate_endpoint(&callback_path(mount_id)?, path)
}

fn validate_endpoint(expected: &Path, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    if path != expected {
        return Err("FSKit callback path is not the managed mount endpoint".to_owned());
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != nix::unistd::getuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("FSKit callback endpoint must be an owner-private socket".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_is_inside_private_container_and_retains_mount_identity() {
        let home = tempfile::tempdir_in("/private/tmp").unwrap();
        let directory = home
            .path()
            .join("Library/Containers/org.astrid.runtime.fs.AppEx/Data/tmp");
        crate::platform_fs::ensure_private_directory(&directory).unwrap();
        let id = StorageMountId::new();
        let path = socket_in_home(home.path(), id).unwrap();
        assert_eq!(path.parent(), Some(directory.as_path()));
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(path.file_name().unwrap().to_str().unwrap())
            .unwrap();
        assert_eq!(bytes, id.as_uuid().as_bytes());
        assert_ne!(
            path,
            socket_in_home(home.path(), StorageMountId::new()).unwrap()
        );
    }

    #[test]
    fn missing_container_does_not_get_created() {
        let home = tempfile::tempdir_in("/private/tmp").unwrap();
        assert!(
            socket_in_home(home.path(), StorageMountId::new())
                .unwrap_err()
                .contains("FSKIT_EXTENSION_UNAVAILABLE")
        );
        assert!(!home.path().join("Library").exists());
    }

    #[test]
    fn aliased_or_nonprivate_container_is_rejected() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};
        let home = tempfile::tempdir_in("/private/tmp").unwrap();
        let parent = home
            .path()
            .join("Library/Containers/org.astrid.runtime.fs.AppEx/Data");
        let actual = parent.join("actual");
        crate::platform_fs::ensure_private_directory(&actual).unwrap();
        symlink(&actual, parent.join("tmp")).unwrap();
        assert!(socket_in_home(home.path(), StorageMountId::new()).is_err());
        std::fs::remove_file(parent.join("tmp")).unwrap();
        std::fs::rename(&actual, parent.join("tmp")).unwrap();
        std::fs::set_permissions(parent.join("tmp"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(socket_in_home(home.path(), StorageMountId::new()).is_err());
    }

    #[test]
    fn overlong_socket_fails_before_binding() {
        let root = tempfile::tempdir_in("/private/tmp").unwrap();
        let home = root.path().join("long-account-name-for-socket-limit");
        let directory = home.join("Library/Containers/org.astrid.runtime.fs.AppEx/Data/tmp");
        crate::platform_fs::ensure_private_directory(&directory).unwrap();
        assert!(
            socket_in_home(&home, StorageMountId::new())
                .unwrap_err()
                .contains("path limit")
        );
    }

    #[test]
    fn endpoint_requires_exact_identity_private_mode_and_socket_type() {
        use std::os::unix::{
            fs::{PermissionsExt as _, symlink},
            net::UnixListener,
        };
        let root = tempfile::tempdir_in("/private/tmp").unwrap();
        let socket = root.path().join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_endpoint(&socket, &socket).is_ok());
        assert!(validate_endpoint(&root.path().join("wrong-mount"), &socket).is_err());
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(validate_endpoint(&socket, &socket).is_err());
        let alias = root.path().join("alias");
        symlink(&socket, &alias).unwrap();
        assert!(validate_endpoint(&alias, &alias).is_err());
        let regular = root.path().join("regular");
        std::fs::write(&regular, b"not a socket").unwrap();
        std::fs::set_permissions(&regular, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_endpoint(&regular, &regular).is_err());
    }
}
