//! Native mount presentation and physical backing capacity.
//!
//! Query the filesystem holding the actual volume, not the temporary lease
//! resource directory (which can be on a different device). Available capacity
//! is an observation, not a reservation; normal owner quotas still govern writes.

use super::*;

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
    let config = astrid_config::Config::load_with_home(None, root).map_err(io::Error::other)?;
    let stats = nix::sys::statvfs::statvfs(root).map_err(io::Error::other)?;
    serde_json::to_vec(&serde_json::json!({
        "volume_name": config.config.filesystem.volume_name,
        "block_size": stats.fragment_size(),
        "total_blocks": stats.blocks(),
        "free_blocks": stats.blocks_free(),
        "available_blocks": stats.blocks_available(),
    }))
    .map_err(io::Error::other)
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
        let root = tempfile::tempdir().unwrap();
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
        assert_eq!(result["total_blocks"], expected.blocks());
        assert!(result["available_blocks"].as_u64().unwrap() > 0);
        assert!(
            u128::from(result["available_blocks"].as_u64().unwrap())
                <= u128::from(expected.blocks())
        );
    }
}
