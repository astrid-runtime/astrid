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

#[derive(Clone, Debug, Serialize)]
pub(super) struct Config {
    pub(super) bytes: u64,
    pub(super) block_bytes: usize,
    pub(super) range_bytes: usize,
    pub(super) samples: usize,
    pub(super) small_files: usize,
    pub(super) small_file_bytes: usize,
    pub(super) root: Option<PathBuf>,
    pub(super) output: Option<PathBuf>,
}

impl Config {
    pub(super) fn from_args() -> BenchResult<Self> {
        let mut config = Self {
            bytes: DEFAULT_BYTES,
            block_bytes: DEFAULT_BLOCK_BYTES,
            range_bytes: DEFAULT_RANGE_BYTES,
            samples: DEFAULT_SAMPLES,
            small_files: DEFAULT_SMALL_FILES,
            small_file_bytes: DEFAULT_SMALL_FILE_BYTES,
            root: None,
            output: None,
        };
        let mut arguments = env::args().skip(1);
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
                "--root" => config.root = Some(parse_path(&mut arguments, "--root")?),
                "--output" => config.output = Some(parse_path(&mut arguments, "--output")?),
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                },
                unknown => return Err(format!("unknown argument {unknown:?}; use --help").into()),
            }
        }
        if config.bytes == 0 {
            return Err("--bytes must be greater than zero".into());
        }
        for (name, value) in [
            ("--block-bytes", config.block_bytes),
            ("--range-bytes", config.range_bytes),
            ("--samples", config.samples),
            ("--small-files", config.small_files),
            ("--small-file-bytes", config.small_file_bytes),
        ] {
            if NonZeroUsize::new(value).is_none() {
                return Err(format!("{name} must be greater than zero").into());
            }
        }
        Ok(config)
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
           --bytes N             large-file corpus bytes (default {DEFAULT_BYTES})\n\
           --block-bytes N       native copy buffer bytes (default {DEFAULT_BLOCK_BYTES})\n\
           --range-bytes N       published range-read bytes (default {DEFAULT_RANGE_BYTES})\n\
           --samples N           native large-write samples (default {DEFAULT_SAMPLES})\n\
           --small-files N       small-file operation count (default {DEFAULT_SMALL_FILES})\n\
           --small-file-bytes N  bytes per small file (default {DEFAULT_SMALL_FILE_BYTES})\n\
           --root PATH           retain benchmark data under PATH\n\
           --output PATH         write the JSON report to PATH\n"
    );
}
