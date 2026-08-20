//! Reproducible native-filesystem and principal-store I/O measurements.
//!
//! This deliberately uses no statistical benchmarking framework. Storage
//! measurements need explicit byte counts, durability boundaries, source
//! volumes, and retained machine-readable results more than sub-microsecond
//! loop calibration.

#![deny(unsafe_code)]

use std::error::Error;
use std::path::Path;

#[path = "storage_io/config.rs"]
mod config;
#[path = "storage_io/provenance.rs"]
mod provenance;
#[path = "storage_io/report.rs"]
mod report;
#[path = "storage_io/workloads.rs"]
mod workloads;

use config::Config;
use provenance::RunProvenance;
use report::Report;

type BenchResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> BenchResult<()> {
    let config = Config::from_args()?;
    let temporary = config.root.is_none().then(tempfile::tempdir).transpose()?;
    let root = match (&config.root, &temporary) {
        (Some(root), _) => root.clone(),
        (None, Some(directory)) => directory.path().to_path_buf(),
        (None, None) => return Err("benchmark root was not selected".into()),
    };
    prepare_root(&root)?;
    let provenance = RunProvenance::capture_for_root(&root)?;
    println!(
        "revision: {} ({})",
        provenance.revision(),
        if provenance.is_clean() {
            "clean"
        } else {
            "dirty"
        }
    );
    println!("{}", provenance.describe_host());
    println!("benchmark root: {}", root.display());
    println!(
        "corpus: {} bytes; block: {} bytes; range: {} bytes; object cache: {}",
        config.bytes,
        config.block_bytes,
        config.range_bytes,
        config
            .object_cache_bytes
            .map_or_else(|| "disabled".to_owned(), |bytes| format!("{bytes} bytes"))
    );

    let source = root.join("source.bin");
    workloads::prepare_source(&source, config.bytes, config.block_bytes)?;
    let source_digest = workloads::hash_native(&source, config.block_bytes)?;
    let mut report = Report::new(config.clone(), provenance);
    workloads::run(&config, &root, &source, source_digest, &mut report).await?;

    report.print_table();
    let encoded = report.encode_evidence()?;
    if let Some(output) = &config.output {
        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(output, &encoded)?;
        println!("machine-readable report: {}", output.display());
    }
    println!("--- JSON ---");
    println!("{}", String::from_utf8(encoded)?);
    Ok(())
}

fn prepare_root(path: &Path) -> BenchResult<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            return Err(format!(
                "benchmark root {} is redirected or not a directory",
                path.display()
            )
            .into());
        },
        Ok(_) if std::fs::read_dir(path)?.next().is_some() => {
            return Err(format!(
                "benchmark root {} is not empty; refusing to overwrite it",
                path.display()
            )
            .into());
        },
        Ok(_) => {},
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path)?;
        },
        Err(error) => return Err(error.into()),
    }
    Ok(())
}
