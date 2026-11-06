//! Opaque directory identity for platform filesystem receipts.
//!
//! Windows captured directories fill this type from
//! `GetFileInformationByHandleEx(FileIdInfo)`: a 128-bit file ID plus the
//! volume serial. Other platforms may embed the same layout in a tagged
//! receipt; Unix identity wrapping is owned by the caller.

use serde::{Deserialize, Serialize};

/// Opaque filesystem directory identity.
///
/// On Windows this is a 128-bit file ID plus volume serial from
/// `GetFileInformationByHandleEx(FileIdInfo)`. Fields stay private so receipts
/// cannot widen or truncate the identifier. The byte layout is the stable
/// serde schema; it is not a durable MOVE receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DirectoryIdentity {
    volume: u64,
    file_id: [u8; 16],
}

impl DirectoryIdentity {
    #[cfg(windows)]
    pub(in crate::platform_fs) const fn from_windows_file_id(
        volume: u64,
        file_id: [u8; 16],
    ) -> Self {
        Self { volume, file_id }
    }
}
