use std::env;
use std::num::NonZeroUsize;
use std::path::PathBuf;

use serde::Serialize;

use crate::BenchResult;

pub(super) const MEBIBYTE: u64 = 1024 * 1024;
const DEFAULT_BYTES: u64 = 256 * MEBIBYTE;
const DEFAULT_BLOCK_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_RANGE_BYTES: usize = 1024 * 1024;
const DEFAULT_SAMPLES: usize = 3;
const DEFAULT_SMALL_FILES: usize = 64;
const DEFAULT_SMALL_FILE_BYTES: usize = 4096;
const DEFAULT_CONCURRENT_PRINCIPALS: usize = 4;
const DEFAULT_BULK_FILES: usize = 100;

/// Existing workloads remain the default; the new probe is explicitly selected.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Selection {
    #[default]
    Existing,
    EvolvingKv,
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct Config {
    pub(super) selection: Selection,
    pub(super) bytes: u64,
    pub(super) block_bytes: usize,
    pub(super) range_bytes: usize,
    pub(super) samples: usize,
    pub(super) small_files: usize,
    pub(super) small_file_bytes: usize,
    pub(super) concurrent_principals: usize,
    pub(super) bulk_workers: usize,
    pub(super) bulk_files: usize,
    pub(super) object_cache_bytes: Option<u64>,
    pub(super) root: Option<PathBuf>,
    pub(super) output: Option<PathBuf>,
}

impl Config {
    pub(super) fn from_args() -> BenchResult<Self> {
        Self::from_arguments(env::args().skip(1))
    }

    pub(super) fn from_arguments(arguments: impl Iterator<Item = String>) -> BenchResult<Self> {
        let mut config = Self {
            selection: Selection::Existing,
            bytes: DEFAULT_BYTES,
            block_bytes: DEFAULT_BLOCK_BYTES,
            range_bytes: DEFAULT_RANGE_BYTES,
            samples: DEFAULT_SAMPLES,
            small_files: DEFAULT_SMALL_FILES,
            small_file_bytes: DEFAULT_SMALL_FILE_BYTES,
            concurrent_principals: DEFAULT_CONCURRENT_PRINCIPALS,
            bulk_workers: std::thread::available_parallelism().map_or(1, NonZeroUsize::get),
            bulk_files: DEFAULT_BULK_FILES,
            object_cache_bytes: None,
            root: None,
            output: None,
        };
        let mut arguments = arguments;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                // Cargo supplies this marker to custom benchmark executables.
                "--bench" => {},
                "--only" => {
                    let value = arguments.next().ok_or("--only requires a workload")?;
                    config.selection = match value.as_str() {
                        "evolving-kv" => Selection::EvolvingKv,
                        _ => return Err(format!("unsupported --only workload {value:?}").into()),
                    };
                },
                "--bytes" => config.bytes = parse_u64(&mut arguments, "--bytes")?,
                "--block-bytes" => {
                    config.block_bytes = parse_usize(&mut arguments, "--block-bytes")?;
                },
                "--range-bytes" => {
                    config.range_bytes = parse_usize(&mut arguments, "--range-bytes")?;
                },
                "--samples" => config.samples = parse_usize(&mut arguments, "--samples")?,
                "--small-files" => {
                    config.small_files = parse_usize(&mut arguments, "--small-files")?;
                },
                "--small-file-bytes" => {
                    config.small_file_bytes = parse_usize(&mut arguments, "--small-file-bytes")?;
                },
                "--concurrent-principals" => {
                    config.concurrent_principals =
                        parse_usize(&mut arguments, "--concurrent-principals")?;
                },
                "--bulk-workers" => {
                    config.bulk_workers = parse_usize(&mut arguments, "--bulk-workers")?;
                },
                "--bulk-files" => {
                    config.bulk_files = parse_usize(&mut arguments, "--bulk-files")?;
                },
                "--object-cache-bytes" => {
                    config.object_cache_bytes =
                        Some(parse_u64(&mut arguments, "--object-cache-bytes")?);
                },
                "--root" => config.root = Some(parse_path(&mut arguments, "--root")?),
                "--output" => config.output = Some(parse_path(&mut arguments, "--output")?),
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                },
                unknown => return Err(format!("unknown argument {unknown:?}; use --help").into()),
            }
        }
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> BenchResult<()> {
        if self.bytes == 0 {
            return Err("--bytes must be greater than zero".into());
        }
        if self.object_cache_bytes == Some(0) {
            return Err("--object-cache-bytes must be greater than zero".into());
        }
        for (name, value) in [
            ("--block-bytes", self.block_bytes),
            ("--range-bytes", self.range_bytes),
            ("--samples", self.samples),
            ("--small-files", self.small_files),
            ("--small-file-bytes", self.small_file_bytes),
            ("--concurrent-principals", self.concurrent_principals),
            ("--bulk-workers", self.bulk_workers),
            ("--bulk-files", self.bulk_files),
        ] {
            if NonZeroUsize::new(value).is_none() {
                return Err(format!("{name} must be greater than zero").into());
            }
        }
        Ok(())
    }
}

fn parse_u64(arguments: &mut impl Iterator<Item = String>, name: &str) -> BenchResult<u64> {
    arguments
        .next()
        .ok_or_else(|| format!("{name} requires a value").into())
        .and_then(|value| {
            value
                .parse()
                .map_err(|error| format!("invalid {name} value {value:?}: {error}").into())
        })
}

fn parse_usize(arguments: &mut impl Iterator<Item = String>, name: &str) -> BenchResult<usize> {
    arguments
        .next()
        .ok_or_else(|| format!("{name} requires a value").into())
        .and_then(|value| {
            value
                .parse()
                .map_err(|error| format!("invalid {name} value {value:?}: {error}").into())
        })
}

fn parse_path(arguments: &mut impl Iterator<Item = String>, name: &str) -> BenchResult<PathBuf> {
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| format!("{name} requires a path").into())
}

fn print_help() {
    println!(
        "Usage: cargo bench -p astrid-storage --bench storage_io -- [options]\n\
         \n\
         Options:\n\
           --only evolving-kv    only evolving 512 KiB/8 MiB KV probe; skip source/bulk I/O\n\
           --bytes N             large-file corpus bytes (default {DEFAULT_BYTES})\n\
           --block-bytes N       native copy buffer bytes (default {DEFAULT_BLOCK_BYTES})\n\
           --range-bytes N       published range-read bytes (default {DEFAULT_RANGE_BYTES})\n\
           --samples N           samples per repeatable workload (default {DEFAULT_SAMPLES})\n\
           --small-files N       small-file operation count (default {DEFAULT_SMALL_FILES})\n\
           --small-file-bytes N  bytes per small file (default {DEFAULT_SMALL_FILE_BYTES})\n\
           --concurrent-principals N\n\
                                 shared-content concurrency (default {DEFAULT_CONCURRENT_PRINCIPALS})\n\
           --bulk-workers N      bounded ingest workers (default host available CPUs)\n\
           --bulk-files N        files in the bulk corpus (default {DEFAULT_BULK_FILES})\n\
           --object-cache-bytes N decoded-object/projection cache budget (default disabled)\n\
           --root PATH           retain benchmark data under PATH\n\
           --output PATH         write the JSON report to PATH\n"
    );
}
