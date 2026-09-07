//! `FSKit`'s sandbox permits Unix IPC inside its own application container.
//! A security-scoped resource URL grants file access, not Unix socket access.

use std::path::{Path, PathBuf};

use astrid_core::storage_provider::StorageMountId;
use base64::Engine as _;

pub(super) fn callback_path(mount_id: StorageMountId) -> Result<PathBuf, String> {
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
        format!("FSKit container is unavailable; enable AstridFS first: {error}")
    })?;
    if canonical != directory {
        return Err("FSKit callback container must not contain symlink aliases".to_owned());
    }
    astrid_core::platform_fs::validate_private_directory(&directory)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn callback_is_inside_private_container_and_retains_mount_identity() {
        let home = tempfile::tempdir_in("/private/tmp").unwrap();
        let directory = home
            .path()
            .join("Library/Containers/org.astrid.runtime.fs.AppEx/Data/tmp");
        astrid_core::platform_fs::ensure_private_directory(&directory).unwrap();
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
        assert!(socket_in_home(home.path(), StorageMountId::new()).is_err());
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
        astrid_core::platform_fs::ensure_private_directory(&actual).unwrap();
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
        astrid_core::platform_fs::ensure_private_directory(&directory).unwrap();
        assert!(
            socket_in_home(&home, StorageMountId::new())
                .unwrap_err()
                .contains("path limit")
        );
    }
}
