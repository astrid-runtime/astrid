use std::env;
use std::num::NonZeroUsize;
use std::time::Duration;

use serde::Serialize;

use super::config::{Config, MEBIBYTE};

#[derive(Debug, Serialize)]
pub(super) struct Report {
    format: &'static str,
    package_version: &'static str,
    os: &'static str,
    architecture: &'static str,
    logical_cpus: usize,
    config: Config,
    metrics: Vec<Metric>,
}

impl Report {
    pub(super) fn new(config: Config) -> Self {
        Self {
            format: "astrid-storage-io-benchmark-v1",
            package_version: env!("CARGO_PKG_VERSION"),
            os: env::consts::OS,
            architecture: env::consts::ARCH,
            logical_cpus: std::thread::available_parallelism().map_or(1, NonZeroUsize::get),
            config,
            metrics: Vec::new(),
        }
    }

    pub(super) fn record_bytes(&mut self, name: &'static str, bytes: u64, samples: Vec<Duration>) {
        self.metrics.push(Metric::bytes(name, bytes, samples));
    }

    pub(super) fn record_operations(
        &mut self,
        name: &'static str,
        operations: usize,
        samples: Vec<Duration>,
    ) {
        self.metrics
            .push(Metric::operations(name, operations, samples));
    }

    pub(super) fn print_table(&self) {
        println!(
            "{:<38} {:>12} {:>12} {:>12}",
            "metric", "median ms", "MiB/s", "ops/s"
        );
        for metric in &self.metrics {
            println!(
                "{:<38} {:>12.3} {:>12} {:>12}",
                metric.name,
                metric.median_milliseconds,
                optional_number(metric.median_mib_per_second),
                optional_number(metric.median_operations_per_second),
            );
        }
    }
}

#[derive(Debug, Serialize)]
struct Metric {
    name: &'static str,
    bytes_per_sample: Option<u64>,
    operations_per_sample: Option<usize>,
    samples_nanoseconds: Vec<u128>,
    minimum_milliseconds: f64,
    median_milliseconds: f64,
    maximum_milliseconds: f64,
    median_mib_per_second: Option<f64>,
    median_operations_per_second: Option<f64>,
}

impl Metric {
    fn bytes(name: &'static str, bytes: u64, samples: Vec<Duration>) -> Self {
        Self::new(name, Some(bytes), None, samples)
    }

    fn operations(name: &'static str, operations: usize, samples: Vec<Duration>) -> Self {
        Self::new(name, None, Some(operations), samples)
    }

    fn new(
        name: &'static str,
        bytes: Option<u64>,
        operations: Option<usize>,
        mut samples: Vec<Duration>,
    ) -> Self {
        samples.sort_unstable();
        let minimum = samples.first().copied().unwrap_or(Duration::ZERO);
        let median = samples
            .get(samples.len() / 2)
            .copied()
            .unwrap_or(Duration::ZERO);
        let maximum = samples.last().copied().unwrap_or(Duration::ZERO);
        let seconds = median.as_secs_f64();
        Self {
            name,
            bytes_per_sample: bytes,
            operations_per_sample: operations,
            samples_nanoseconds: samples.iter().map(Duration::as_nanos).collect(),
            minimum_milliseconds: duration_milliseconds(minimum),
            median_milliseconds: duration_milliseconds(median),
            maximum_milliseconds: duration_milliseconds(maximum),
            median_mib_per_second: bytes
                .filter(|_| seconds > 0.0)
                .map(|count| mib_per_second(count, seconds)),
            median_operations_per_second: operations
                .filter(|_| seconds > 0.0)
                .map(|count| operations_per_second(count, seconds)),
        }
    }
}

fn duration_milliseconds(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[allow(clippy::cast_precision_loss)]
fn mib_per_second(bytes: u64, seconds: f64) -> f64 {
    bytes as f64 / MEBIBYTE as f64 / seconds
}

#[allow(clippy::cast_precision_loss)]
fn operations_per_second(operations: usize, seconds: f64) -> f64 {
    operations as f64 / seconds
}

fn optional_number(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |number| format!("{number:.1}"))
}
