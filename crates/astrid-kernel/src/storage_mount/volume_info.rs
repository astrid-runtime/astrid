//! Native mount presentation and physical backing capacity.
//!
//! Query the filesystem holding the actual volume, not the temporary lease
//! resource directory (which can be on a different device). Available capacity
//! is an observation, not a reservation; normal owner quotas still govern writes.

use super::{Kernel, StorageFilesystemOutcomeV1, StorageFilesystemSuccessV1, failure, io};

pub(super) async fn read(kernel: &Kernel) -> StorageFilesystemOutcomeV1 {
    let home = kernel.astrid_home.clone();
    match tokio::task::spawn_blocking(move || snapshot(home.root())).await {
        Ok(Ok(bytes)) => {
            StorageFilesystemOutcomeV1::Success(StorageFilesystemSuccessV1::Data(bytes))
        },
        Ok(Err(error)) => failure("unavailable", &error.to_string()),
        Err(error) => failure("internal", &error.to_string()),
    }
}

#[cfg(unix)]
fn snapshot(root: &std::path::Path) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let config = astrid_config::Config::load_with_home(None, root).map_err(io::Error::other)?;
    let stats = nix::sys::statvfs::statvfs(root).map_err(io::Error::other)?;
    let metadata = std::fs::metadata(root.join("astrid.volume"))?;
    let block_size = stats.fragment_size();
    if block_size == 0 {
        return Err(io::Error::other(
            "backing filesystem reported a zero block size",
        ));
    }
    // POSIX st_blocks counts allocated 512-byte units, not the sparse file's
    // logical length. Both owner views share this growable physical container.
    // Unrelated files on the host disk must not appear as Astrid's used space.
    let allocated = metadata
        .blocks()
        .checked_mul(512)
        .ok_or_else(|| io::Error::other("allocated volume size overflow"))?;
    let used_blocks = allocated.div_ceil(block_size);
    let available = stats.blocks_available();
    let total = u64::try_from(u128::from(used_blocks).strict_add(u128::from(available)))
        .map_err(|_| io::Error::other("growable volume capacity overflow"))?;
    serde_json::to_vec(&serde_json::json!({
        "volume_name": config.config.filesystem.volume_name,
        "block_size": block_size,
        "total_blocks": total,
        "free_blocks": available,
        "available_blocks": available,
        "created_secs": timestamp(metadata.created()),
        "modified_secs": timestamp(metadata.modified()),
    }))
    .map_err(io::Error::other)
}

#[cfg(unix)]
fn timestamp(value: io::Result<std::time::SystemTime>) -> Option<u64> {
    value
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
}

#[cfg(not(unix))]
fn snapshot(_root: &std::path::Path) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native capacity query is unavailable on this platform",
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn reports_actual_backing_capacity_and_configured_label() {
        use std::os::unix::fs::MetadataExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("astrid.volume"), [42; 8192]).unwrap();
        std::fs::write(
            root.path().join("config.toml"),
            "[filesystem]\nvolume_name = 'AOS'\n",
        )
        .unwrap();
        let result: serde_json::Value =
            serde_json::from_slice(&snapshot(root.path()).unwrap()).unwrap();
        let expected = nix::sys::statvfs::statvfs(root.path()).unwrap();
        assert_eq!(result["volume_name"], "AOS");
        assert_eq!(result["block_size"], expected.fragment_size());
        let allocated = std::fs::metadata(root.path().join("astrid.volume"))
            .unwrap()
            .blocks()
            * 512;
        assert_eq!(
            result["total_blocks"].as_u64().unwrap() - result["free_blocks"].as_u64().unwrap(),
            allocated.div_ceil(expected.fragment_size())
        );
        assert_eq!(result["free_blocks"], result["available_blocks"]);
        assert!(result["modified_secs"].as_u64().unwrap() > 0);
        assert!(result["available_blocks"].as_u64().unwrap() > 0);
        assert!(
            u128::from(result["available_blocks"].as_u64().unwrap())
                <= u128::from(expected.blocks())
        );
    }
}
