//! Presentation metadata from the authenticated kernel, never synthetic capacity.

use std::time::{Duration, SystemTime};

use astrid_core::storage_filesystem::{StorageFilesystemOperationV1, StorageFilesystemSuccessV1};
use fuser::Errno;
use serde::Deserialize;

use crate::callback::{CallbackClient, callback_errno};

#[derive(Debug, Deserialize)]
pub(super) struct VolumeInfo {
    pub(super) volume_name: String,
    pub(super) block_size: u32,
    pub(super) total_blocks: u64,
    pub(super) free_blocks: u64,
    pub(super) available_blocks: u64,
    created_secs: Option<u64>,
    modified_secs: Option<u64>,
}

impl VolumeInfo {
    pub(super) fn read(callback: &CallbackClient) -> Result<Self, Errno> {
        match callback
            .call(StorageFilesystemOperationV1::VolumeInfo)
            .map_err(callback_errno)?
        {
            StorageFilesystemSuccessV1::Data(bytes) => Self::parse(&bytes),
            _ => Err(Errno::EIO),
        }
    }

    fn parse(bytes: &[u8]) -> Result<Self, Errno> {
        let info: Self = serde_json::from_slice(bytes).map_err(|_| Errno::EIO)?;
        if info.block_size == 0
            || info.available_blocks > info.free_blocks
            || info.free_blocks > info.total_blocks
            || info.volume_name.trim().is_empty()
            || info.volume_name.chars().any(char::is_control)
        {
            return Err(Errno::EIO);
        }
        Ok(info)
    }

    pub(super) fn created(&self) -> Result<SystemTime, Errno> {
        timestamp(self.created_secs)
    }

    pub(super) fn modified(&self) -> Result<SystemTime, Errno> {
        timestamp(self.modified_secs)
    }
}

fn timestamp(seconds: Option<u64>) -> Result<SystemTime, Errno> {
    // An unavailable backing timestamp stays unknown, rather than changing on
    // every getattr and appearing to be a freshly modified file.
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(seconds.unwrap_or_default()))
        .ok_or(Errno::EIO)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture() -> serde_json::Value {
        serde_json::json!({
            "volume_name": "AOS", "block_size": 4096,
            "total_blocks": 100, "free_blocks": 80, "available_blocks": 70,
            "created_secs": 1000, "modified_secs": 2000
        })
    }

    #[test]
    fn preserves_backing_counts_name_and_dates() {
        let info = VolumeInfo::parse(fixture().to_string().as_bytes()).unwrap();
        assert_eq!(info.volume_name, "AOS");
        assert_eq!(info.block_size, 4096);
        assert_eq!((info.total_blocks, info.free_blocks, info.available_blocks), (100, 80, 70));
        assert_eq!(info.created().unwrap(), SystemTime::UNIX_EPOCH + Duration::from_secs(1000));
        assert_eq!(info.modified().unwrap(), SystemTime::UNIX_EPOCH + Duration::from_secs(2000));
    }

    #[test]
    fn refuses_malformed_or_inconsistent_capacity() {
        for (key, value) in [
            ("block_size", serde_json::json!(0)),
            ("block_size", serde_json::json!(u64::MAX)),
            ("available_blocks", serde_json::json!(81)),
            ("free_blocks", serde_json::json!(101)),
            ("volume_name", serde_json::json!("\n")),
        ] {
            let mut data = fixture();
            data[key] = value;
            assert!(VolumeInfo::parse(data.to_string().as_bytes()).is_err(), "{key}");
        }
        assert!(VolumeInfo::parse(b"{}").is_err());
        assert!(VolumeInfo::parse(b"not json").is_err());
    }

    #[test]
    fn missing_dates_remain_unknown() {
        let mut data = fixture();
        data["created_secs"] = serde_json::Value::Null;
        data["modified_secs"] = serde_json::Value::Null;
        let info = VolumeInfo::parse(data.to_string().as_bytes()).unwrap();
        assert_eq!(info.created().unwrap(), SystemTime::UNIX_EPOCH);
        assert_eq!(info.modified().unwrap(), SystemTime::UNIX_EPOCH);
    }
}
