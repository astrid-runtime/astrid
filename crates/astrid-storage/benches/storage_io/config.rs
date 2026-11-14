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
const MATCHED_CHECKPOINT_OVERWRITES: usize = 4096;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Config {
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
    pub(super) partial_verification_clone: bool,
    pub(super) checkpoint_overwrites: Option<NonZeroUsize>,
    pub(super) root: Option<PathBuf>,
    pub(super) output: Option<PathBuf>,
}

impl Config {
    pub(super) fn from_args() -> BenchResult<Self> {
        Self::from_args_iter(env::args().skip(1))
    }

    pub(super) fn from_args_iter(arguments: impl IntoIterator<Item = String>) -> BenchResult<Self> {
        let mut config = Self {
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
            partial_verification_clone: false,
            checkpoint_overwrites: None,
            root: None,
            output: None,
        };
        let mut arguments = arguments.into_iter();
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                // Cargo supplies this marker to custom benchmark executables.
                "--bench" => {},
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
                "--partial-verification-clone" => {
                    config.partial_verification_clone = true;
                },
                "--checkpoint-overwrites" => {
                    config.checkpoint_overwrites = Some(parse_nonzero_usize(
                        &mut arguments,
                        "--checkpoint-overwrites",
                    )?);
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
        config.validate()
    }

    fn validate(self) -> BenchResult<Self> {
        if self.bytes == 0 {
            return Err("--bytes must be greater than zero".into());
        }
        if self.object_cache_bytes == Some(0) {
            return Err("--object-cache-bytes must be greater than zero".into());
        }
        if self.partial_verification_clone && self.object_cache_bytes.is_none() {
            return Err(
                "--partial-verification-clone requires nonzero --object-cache-bytes".into(),
            );
        }
        if self.checkpoint_overwrites.is_some() && self.partial_verification_clone {
            return Err(
                "--checkpoint-overwrites cannot be combined with --partial-verification-clone"
                    .into(),
            );
        }
        if self.checkpoint_overwrites.is_some() && self.object_cache_bytes.is_some() {
            return Err(
                "--checkpoint-overwrites uses the runtime object-cache default; do not pass --object-cache-bytes"
                    .into(),
            );
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
        Ok(self)
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

fn parse_nonzero_usize(
    arguments: &mut impl Iterator<Item = String>,
    name: &str,
) -> BenchResult<NonZeroUsize> {
    let value = parse_usize(arguments, name)?;
    NonZeroUsize::new(value).ok_or_else(|| format!("{name} must be greater than zero").into())
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
           --partial-verification-clone\n\
                                 run only matched cold read() vs windowed\n\
                                 read_range(--range-bytes) (requires --object-cache-bytes)\n\
           --checkpoint-overwrites N\n\
                                 exclusive 256-byte content overwrite profile; omit\n\
                                 for the existing full bench. Rejects 0. Matched arms\n\
                                 use {MATCHED_CHECKPOINT_OVERWRITES}. Uses production\n\
                                 open_runtime_principal_store cache/policy.\n\
           --root PATH           retain benchmark data under PATH\n\
           --output PATH         write the JSON report to PATH\n"
    );
}
