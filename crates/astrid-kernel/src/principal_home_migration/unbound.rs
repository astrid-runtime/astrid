//! Admit or quarantine layout-1 leftover principal homes before cut-over.
//!
//! Released 0.10.4 allowed `home/<alias>` without a durable identity or
//! profile. Layout-2 import enumerates every leftover directory and fail-closes
//! the kernel when `uid_for` has nothing to bind. Valid leftover aliases are
//! minted into ordinary principals so their files import and the operator
//! fleet can adopt them. Names that are not a [`PrincipalId`] are moved out of
//! `home/` without deleting user data.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_core::profile::{AuthMethod, DeviceKey, DeviceScope, PrincipalProfile};
use astrid_storage::{IdentityError, IdentityStore, PrincipalDirectory};

const QUARANTINE_DIR: &str = "unbound-legacy-homes";

/// Mint identities for leftover valid aliases and quarantine invalid names.
///
/// Call this only on the first layout-1 cut-over, before the barrier snapshots
/// admitted bindings. Existing-v2 leftover sources still fail closed later.
pub(crate) async fn admit_unbound_legacy_principal_homes(
    home: &AstridHome,
    directory: &PrincipalDirectory,
    identity: &dyn IdentityStore,
) -> io::Result<()> {
    let source_root = home.home_dir();
    let metadata = match fs::symlink_metadata(&source_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "legacy principal home root is not a regular directory: {}",
                source_root.display()
            ),
        ));
    }
    astrid_core::platform_fs::validate_private_directory(&source_root)?;
    astrid_core::platform_fs::verify_no_redirects(&source_root)?;

    let mut entries = Vec::new();
    for entry in fs::read_dir(&source_root).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("scan {}: {error}", source_root.display()),
        )
    })? {
        entries.push(entry?);
    }
    for entry in entries {
        admit_or_quarantine_entry(home, directory, identity, entry.path(), &entry.file_name())
            .await?;
    }
    Ok(())
}

async fn admit_or_quarantine_entry(
    home: &AstridHome,
    directory: &PrincipalDirectory,
    identity: &dyn IdentityStore,
    path: PathBuf,
    file_name: &OsStr,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return quarantine_entry(
            home,
            &path,
            file_name,
            "legacy principal home entry is not a regular directory",
        );
    }
    let Some(alias_text) = file_name.to_str() else {
        return quarantine_entry(
            home,
            &path,
            file_name,
            "legacy principal directory name is not UTF-8",
        );
    };
    let Ok(alias) = PrincipalId::new(alias_text.to_owned()) else {
        return quarantine_entry(
            home,
            &path,
            file_name,
            "legacy principal directory name is not a valid PrincipalId",
        );
    };
    if let Some(reason) = alias.reserved_reason()
        && alias != PrincipalId::default()
    {
        return quarantine_entry(home, &path, file_name, reason);
    }
    if directory.uid_for(&alias).is_ok() {
        return Ok(());
    }
    mint_valid_leftover(home, identity, &alias).await
}

async fn mint_valid_leftover(
    home: &AstridHome,
    identity: &dyn IdentityStore,
    alias: &PrincipalId,
) -> io::Result<()> {
    ensure_profile_with_genesis_key(home, alias)?;
    let public_key = genesis_public_key_bytes(home, alias)?;
    let user = ensure_durable_identity(identity, alias, public_key).await?;
    tracing::info!(
        principal = %alias,
        user_id = %user.id,
        "minted durable identity for unbound layout-1 principal home"
    );
    Ok(())
}

async fn ensure_durable_identity(
    identity: &dyn IdentityStore,
    alias: &PrincipalId,
    public_key: [u8; 32],
) -> io::Result<astrid_core::AstridUserId> {
    let users = identity
        .list_users()
        .await
        .map_err(|error| identity_io(&error))?;
    if let Some(user) = users.into_iter().find(|user| user.principal == *alias) {
        if identity
            .get_principal_identity(user.id)
            .await
            .map_err(|error| identity_io(&error))?
            .is_none()
        {
            identity
                .bind_principal_identity(user.id, alias.clone(), public_key)
                .await
                .map_err(|error| identity_io(&error))?;
        }
        return Ok(user);
    }
    identity
        .create_principal(alias.clone(), public_key)
        .await
        .map_err(|error| identity_io(&error))
}

fn ensure_profile_with_genesis_key(home: &AstridHome, alias: &PrincipalId) -> io::Result<()> {
    let path = PrincipalProfile::path_for(home, alias);
    let mut profile = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "legacy principal profile is not a regular file: {}",
                    path.display()
                ),
            ));
        },
        Ok(_) => {
            PrincipalProfile::load_required(home, alias).map_err(|error| profile_io(&error))?
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => PrincipalProfile::default(),
        Err(error) => return Err(error),
    };
    let minted = mint_bootstrap_keypair(home, alias, &mut profile)?;
    if minted || !path.is_file() {
        profile
            .save(home, alias)
            .map_err(|error| profile_io(&error))?;
    }
    Ok(())
}

fn mint_bootstrap_keypair(
    home: &AstridHome,
    principal: &PrincipalId,
    profile: &mut PrincipalProfile,
) -> io::Result<bool> {
    if !profile.auth.public_keys.is_empty() {
        return Ok(false);
    }
    let keys_dir = home.keys_dir();
    fs::create_dir_all(&keys_dir)?;
    let key_path = keys_dir.join(format!("{principal}.key"));
    let keypair = astrid_crypto::load_or_generate_keypair(&key_path)?;
    let pubkey_hex = keypair.export_public_key().to_hex();
    if profile.auth.device_by_pubkey(&pubkey_hex).is_none() {
        profile.auth.public_keys.push(DeviceKey::new(
            pubkey_hex,
            DeviceScope::Full,
            None,
            i64::try_from(crate::invite::now_epoch()).unwrap_or(0),
        ));
    }
    if !profile.auth.methods.contains(&AuthMethod::Keypair) {
        profile.auth.methods.push(AuthMethod::Keypair);
    }
    Ok(true)
}

fn genesis_public_key_bytes(home: &AstridHome, alias: &PrincipalId) -> io::Result<[u8; 32]> {
    let profile =
        PrincipalProfile::load_required(home, alias).map_err(|error| profile_io(&error))?;
    let device = profile
        .auth
        .public_keys
        .iter()
        .min_by_key(|device| (device.created_at, device.key_id.as_str()))
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("principal {alias} has no Ed25519 key for genesis identity"),
            )
        })?;
    let public_key = astrid_crypto::PublicKey::from_hex(&device.pubkey).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("principal {alias} has an invalid genesis public key: {error}"),
        )
    })?;
    Ok(public_key.into())
}

fn quarantine_entry(
    home: &AstridHome,
    source: &Path,
    file_name: &OsStr,
    reason: &str,
) -> io::Result<()> {
    let quarantine_root = home.migrations_dir().join(QUARANTINE_DIR);
    astrid_core::platform_fs::ensure_private_directory(&quarantine_root)?;
    let destination = unique_quarantine_path(&quarantine_root, file_name)?;
    let source_parent = source.parent().map(Path::to_path_buf);
    fs::rename(source, &destination).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "quarantine {} to {}: {error}",
                source.display(),
                destination.display()
            ),
        )
    })?;
    if let Some(parent) = source_parent.as_deref() {
        sync_directory(parent)?;
    }
    sync_parent(&destination)?;
    let sidecar = destination.with_file_name(format!(
        "{}.original-name",
        destination
            .file_name()
            .map_or("leftover", |name| name.to_str().unwrap_or("leftover"))
    ));
    astrid_core::platform_fs::atomic_write_private_file(&sidecar, &os_str_bytes(file_name))?;
    tracing::warn!(
        leftover = %file_name.to_string_lossy(),
        reason,
        destination = %destination.display(),
        "quarantined unbound layout-1 home directory so layout-2 verify does not fail closed"
    );
    Ok(())
}

fn unique_quarantine_path(root: &Path, file_name: &OsStr) -> io::Result<PathBuf> {
    let encoded = encoded_file_name(file_name);
    for index in 0_u32..1024 {
        let candidate = if index == 0 {
            root.join(&encoded)
        } else {
            root.join(format!("{encoded}-{index}"))
        };
        match fs::symlink_metadata(&candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(candidate),
            Ok(_) => {},
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::other(
        "exhausted unique names for quarantined legacy home directory",
    ))
}

fn encoded_file_name(name: &OsStr) -> String {
    const MAX_SAFE_NAME: usize = 64;
    match name.to_str() {
        Some(text)
            if !text.is_empty()
                && text.len() <= MAX_SAFE_NAME
                && text != "."
                && text != ".."
                && text
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_') =>
        {
            text.to_owned()
        },
        _ => format!("invalid-{}", blake3::hash(&os_str_bytes(name)).to_hex()),
    }
}

fn os_str_bytes(name: &OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;
        name.as_bytes().to_vec()
    }
    #[cfg(not(unix))]
    {
        name.to_string_lossy().as_bytes().to_vec()
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        sync_directory(parent)?;
    }
    Ok(())
}

#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn identity_io(error: &IdentityError) -> io::Error {
    io::Error::other(format!("unbound layout-1 principal identity: {error}"))
}

fn profile_io(error: &astrid_core::ProfileError) -> io::Error {
    io::Error::other(format!("unbound layout-1 principal profile: {error}"))
}
