//! Canonical records and content identities for home-layout migration.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{AstridHome, LEGACY_LAYOUT_VERSION};

pub(super) const LAYOUT_MIGRATION_SCHEMA: u32 = 1;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LayoutTreeIdentityV1 {
    pub(super) path_encoding: String,
    pub(super) physical_path_hex: String,
    pub(super) inventory_algorithm: String,
    pub(super) inventory_digest: String,
    pub(super) entries: u64,
    pub(super) bytes: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LayoutMigrationMaterialV1 {
    pub(super) migration: String,
    pub(super) from_layout: String,
    pub(super) to_layout: String,
    pub(super) source: LayoutTreeIdentityV1,
    pub(super) target_path_encoding: String,
    pub(super) target_physical_path_hex: String,
    pub(super) target_store_format: String,
    pub(super) binary_identity: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LayoutMigrationRecordV1 {
    pub(super) schema: u32,
    pub(super) transaction_id: String,
    pub(super) material: LayoutMigrationMaterialV1,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LayoutMigrationReceiptV1 {
    pub(super) schema: u32,
    pub(super) transaction_id: String,
    pub(super) intent: LayoutMigrationRecordV1,
    pub(super) destination: LayoutTreeIdentityV1,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LayoutRetirementV1 {
    pub(super) schema: u32,
    pub(super) transaction_id: String,
    pub(super) source: LayoutTreeIdentityV1,
}

impl LayoutMigrationRecordV1 {
    pub(super) fn has_recomputable_identity(&self) -> bool {
        self.schema == LAYOUT_MIGRATION_SCHEMA
            && self.transaction_id == layout_transaction_id(&self.material).unwrap_or_default()
            && self.material.migration == "astrid-home-layout"
            && self.material.from_layout == LEGACY_LAYOUT_VERSION
            && self.material.to_layout == super::LAYOUT_VERSION
            && self.material.source.path_encoding == "os-str-encoded-bytes-v1"
            && self.material.source.inventory_algorithm == "blake3-derive-key-v1"
            && self.material.target_path_encoding == "os-str-encoded-bytes-v1"
    }

    pub(super) fn capture(
        home: &AstridHome,
        target: &super::LayoutMigrationTarget,
    ) -> io::Result<Self> {
        let material = LayoutMigrationMaterialV1 {
            migration: "astrid-home-layout".to_owned(),
            from_layout: LEGACY_LAYOUT_VERSION.to_owned(),
            to_layout: super::LAYOUT_VERSION.to_owned(),
            source: inventory_tree(&home.state_db_path())?,
            target_path_encoding: "os-str-encoded-bytes-v1".to_owned(),
            target_physical_path_hex: physical_path_hex(&home.storage_volume_path())?,
            target_store_format: target.store_format(),
            binary_identity: target.binary_identity(),
        };
        Ok(Self {
            schema: LAYOUT_MIGRATION_SCHEMA,
            transaction_id: layout_transaction_id(&material)?,
            material,
        })
    }
}

pub(super) fn layout_transaction_id(material: &LayoutMigrationMaterialV1) -> io::Result<String> {
    let material_bytes = serde_json::to_vec(material).map_err(io::Error::other)?;
    Ok(hex::encode(blake3::derive_key(
        "astrid home layout migration transaction v1",
        &material_bytes,
    )))
}

pub(super) fn admit_or_write_canonical<T>(
    path: &Path,
    expected: &T,
    allow_create: bool,
) -> io::Result<()>
where
    T: DeserializeOwned + PartialEq + Serialize,
{
    let mut expected_bytes = serde_json::to_vec(expected).map_err(io::Error::other)?;
    expected_bytes.push(b'\n');
    match std::fs::read(path) {
        Ok(actual) => {
            let parsed: T = serde_json::from_slice(&actual).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "invalid layout migration record {}: {error}",
                        path.display()
                    ),
                )
            })?;
            if parsed != *expected || actual != expected_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout migration record does not match this transaction: {}",
                        path.display()
                    ),
                ));
            }
            Ok(())
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound && allow_create => {
            super::atomic_write(path, &expected_bytes)
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("layout migration intent is missing: {}", path.display()),
        )),
        Err(error) => Err(error),
    }
}

pub(super) fn read_canonical_record<T>(path: &Path) -> io::Result<T>
where
    T: DeserializeOwned + PartialEq + Serialize,
{
    let actual = std::fs::read(path)?;
    let parsed: T = serde_json::from_slice(&actual).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid layout migration record {}: {error}",
                path.display()
            ),
        )
    })?;
    let mut expected = serde_json::to_vec(&parsed).map_err(io::Error::other)?;
    expected.push(b'\n');
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration record is not canonical: {}",
                path.display()
            ),
        ));
    }
    Ok(parsed)
}

pub(super) fn verify_receipt_destination_authority(
    destination: &LayoutTreeIdentityV1,
) -> io::Result<()> {
    let path = physical_path(destination)?;
    let metadata = std::fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration destination is redirected or not a regular file: {}",
                path.display()
            ),
        ));
    }
    crate::platform_fs::verify_no_redirects(&path)
}

pub(super) fn verify_receipt_destination_is_live_path(
    destination: &LayoutTreeIdentityV1,
    live_path: &Path,
) -> io::Result<()> {
    let parent = live_path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "live Astrid volume has no parent",
        )
    })?;
    let file_name = live_path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "live Astrid volume has no name",
        )
    })?;
    let canonical_parent = std::fs::canonicalize(parent)?;
    if physical_path(destination)? != canonical_parent.join(file_name) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "layout migration receipt destination path does not match the live Astrid volume",
        ));
    }
    verify_receipt_destination_authority(destination)
}

fn physical_path(destination: &LayoutTreeIdentityV1) -> io::Result<PathBuf> {
    let bytes = hex::decode(&destination.physical_path_hex)
        .map_err(|error| io::Error::other(format!("decode layout destination path: {error}")))?;
    encoded_bytes_to_os_string(bytes).map(PathBuf::from)
}

#[cfg(unix)]
#[expect(
    clippy::unnecessary_wraps,
    reason = "the cross-platform receipt decoder has one fallible signature"
)]
pub(super) fn encoded_bytes_to_os_string(bytes: Vec<u8>) -> io::Result<OsString> {
    use std::os::unix::ffi::OsStringExt as _;

    // Unix receipts commit to the raw OsStr byte sequence, including paths
    // that are not UTF-8. Decoding must therefore preserve every byte.
    Ok(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
pub(super) fn encoded_bytes_to_os_string(bytes: Vec<u8>) -> io::Result<OsString> {
    let text = String::from_utf8(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("layout destination path is not portable UTF-8: {error}"),
        )
    })?;
    let path = OsString::from(&text);
    if path.as_encoded_bytes() != text.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "layout destination path cannot be represented losslessly on this platform",
        ));
    }
    Ok(path)
}

pub(super) fn inventory_tree(path: &Path) -> io::Result<LayoutTreeIdentityV1> {
    let mut hasher = blake3::Hasher::new_derive_key("astrid layout source inventory v1");
    let mut entries = 0_u64;
    let mut bytes = 0_u64;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            hasher.update(b"absent");
        },
        Err(error) => return Err(error),
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "layout migration source is redirected or not a directory: {}",
                    path.display()
                ),
            ));
        },
        Ok(_) => {
            crate::platform_fs::verify_no_redirects(path)?;
            inventory_directory(path, path, &mut hasher, &mut entries, &mut bytes)?;
        },
    }
    Ok(LayoutTreeIdentityV1 {
        path_encoding: "os-str-encoded-bytes-v1".to_owned(),
        physical_path_hex: physical_path_hex(path)?,
        inventory_algorithm: "blake3-derive-key-v1".to_owned(),
        inventory_digest: hasher.finalize().to_hex().to_string(),
        entries,
        bytes,
    })
}

pub(super) fn inventory_regular_file(path: &Path) -> io::Result<LayoutTreeIdentityV1> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration destination is redirected or not a regular file: {}",
                path.display()
            ),
        ));
    }
    crate::platform_fs::verify_no_redirects(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration destination changed type: {}",
                path.display()
            ),
        ));
    }
    let mut hasher = blake3::Hasher::new_derive_key("astrid layout destination inventory v1");
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut bytes = 0_u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("layout destination length overflow"))?;
        hasher.update(&buffer[..read]);
    }
    if bytes != metadata.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "layout migration destination changed while inventoried: {}",
                path.display()
            ),
        ));
    }
    Ok(LayoutTreeIdentityV1 {
        path_encoding: "os-str-encoded-bytes-v1".to_owned(),
        physical_path_hex: physical_path_hex(path)?,
        inventory_algorithm: "blake3-derive-key-v1".to_owned(),
        inventory_digest: hasher.finalize().to_hex().to_string(),
        entries: 1,
        bytes,
    })
}

fn inventory_directory(
    root: &Path,
    directory: &Path,
    hasher: &mut blake3::Hasher,
    entries: &mut u64,
    bytes: &mut u64,
) -> io::Result<()> {
    let mut children = std::fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    children.sort_by_key(std::fs::DirEntry::file_name);
    for child in children {
        let child_path = child.path();
        let relative = child_path.strip_prefix(root).map_err(io::Error::other)?;
        let relative_bytes = relative.as_os_str().as_encoded_bytes();
        let metadata = std::fs::symlink_metadata(&child_path)?;
        if metadata.file_type().is_symlink() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "layout migration source contains a redirect: {}",
                    child_path.display()
                ),
            ));
        }
        super::retirement::validate_legacy_surrealkv_entry(
            relative,
            metadata.is_dir(),
            metadata.is_file(),
        )?;
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| io::Error::other("layout inventory entry count overflow"))?;
        hash_inventory_field(hasher, b"path", relative_bytes);
        if metadata.is_dir() {
            hasher.update(b"directory");
            inventory_directory(root, &child_path, hasher, entries, bytes)?;
        } else if metadata.is_file() {
            hasher.update(b"file");
            hasher.update(&metadata.len().to_le_bytes());
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;

                options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK);
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt as _;
                use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;

                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            let mut file = options.open(&child_path)?;
            if !file.metadata()?.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout migration source changed type: {}",
                        child_path.display()
                    ),
                ));
            }
            let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
            let mut file_bytes = 0_u64;
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                *bytes = bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("layout inventory byte count overflow"))?;
                file_bytes = file_bytes
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("layout inventory file length overflow"))?;
                hasher.update(&buffer[..read]);
            }
            if file_bytes != metadata.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "layout migration source changed while inventoried: {}",
                        child_path.display()
                    ),
                ));
            }
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "layout migration source contains a special file: {}",
                    child_path.display()
                ),
            ));
        }
    }
    Ok(())
}

fn hash_inventory_field(hasher: &mut blake3::Hasher, label: &[u8], value: &[u8]) {
    hasher.update(&(label.len() as u64).to_le_bytes());
    hasher.update(label);
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

pub(super) fn physical_path_hex(path: &Path) -> io::Result<String> {
    let absolute = if path.exists() {
        std::fs::canonicalize(path)?
    } else {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("layout path has no parent"))?;
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("layout path has no name"))?;
        std::fs::canonicalize(parent)?.join(name)
    };
    Ok(hex::encode(absolute.as_os_str().as_encoded_bytes()))
}
