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
    substrate_comparisons: Vec<SubstrateComparison>,
    write_amplifications: Vec<WriteAmplification>,
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
            substrate_comparisons: Vec::new(),
            write_amplifications: Vec::new(),
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

    pub(super) fn record_substrate_comparison(
        &mut self,
        name: &'static str,
        astrid_metric: &'static str,
        substrate_metric: &'static str,
    ) -> Result<(), String> {
        let astrid_milliseconds = self
            .metric(astrid_metric)
            .ok_or_else(|| format!("unknown Astrid comparison metric {astrid_metric:?}"))?
            .median_milliseconds;
        let substrate_milliseconds = self
            .metric(substrate_metric)
            .ok_or_else(|| format!("unknown substrate comparison metric {substrate_metric:?}"))?
            .median_milliseconds;
        if substrate_milliseconds <= 0.0 {
            return Err(format!(
                "substrate comparison metric {substrate_metric:?} has zero elapsed time"
            ));
        }
        self.substrate_comparisons.push(SubstrateComparison {
            name,
            astrid_metric,
            substrate_metric,
            median_elapsed_ratio: astrid_milliseconds / substrate_milliseconds,
        });
        Ok(())
    }

    pub(super) fn record_write_amplification(
        &mut self,
        name: &'static str,
        logical_bytes_per_sample: u64,
        mut authoritative_bytes_appended: Vec<u64>,
    ) -> Result<(), String> {
        if logical_bytes_per_sample == 0 {
            return Err(format!(
                "write amplification metric {name:?} has zero logical bytes"
            ));
        }
        if authoritative_bytes_appended.is_empty() {
            return Err(format!(
                "write amplification metric {name:?} has no samples"
            ));
        }
        authoritative_bytes_appended.sort_unstable();
        let minimum = authoritative_bytes_appended
            .first()
            .copied()
            .ok_or_else(|| format!("write amplification metric {name:?} has no minimum"))?;
        let median = authoritative_bytes_appended
            .get(authoritative_bytes_appended.len() / 2)
            .copied()
            .ok_or_else(|| format!("write amplification metric {name:?} has no median"))?;
        let maximum = authoritative_bytes_appended
            .last()
            .copied()
            .ok_or_else(|| format!("write amplification metric {name:?} has no maximum"))?;
        self.write_amplifications.push(WriteAmplification {
            name,
            logical_bytes_per_sample,
            authoritative_bytes_appended,
            minimum_authoritative_bytes_appended: minimum,
            median_authoritative_bytes_appended: median,
            maximum_authoritative_bytes_appended: maximum,
            median_physical_to_logical_ratio: ratio(median, logical_bytes_per_sample),
        });
        Ok(())
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
        if !self.substrate_comparisons.is_empty() {
            println!();
            println!("{:<38} {:>18}", "paired operation", "elapsed/substrate");
            for comparison in &self.substrate_comparisons {
                println!(
                    "{:<38} {:>17.3}×",
                    comparison.name, comparison.median_elapsed_ratio
                );
            }
        }
        if !self.write_amplifications.is_empty() {
            println!();
            println!(
                "{:<38} {:>18} {:>18}",
                "publication", "median appended", "appended/logical"
            );
            for amplification in &self.write_amplifications {
                println!(
                    "{:<38} {:>18} {:>17.3}×",
                    amplification.name,
                    amplification.median_authoritative_bytes_appended,
                    amplification.median_physical_to_logical_ratio
                );
            }
        }
    }

    fn metric(&self, name: &str) -> Option<&Metric> {
        self.metrics.iter().find(|metric| metric.name == name)
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

#[derive(Debug, Serialize)]
struct SubstrateComparison {
    name: &'static str,
    astrid_metric: &'static str,
    substrate_metric: &'static str,
    median_elapsed_ratio: f64,
}

#[derive(Debug, Serialize)]
struct WriteAmplification {
    name: &'static str,
    logical_bytes_per_sample: u64,
    authoritative_bytes_appended: Vec<u64>,
    minimum_authoritative_bytes_appended: u64,
    median_authoritative_bytes_appended: u64,
    maximum_authoritative_bytes_appended: u64,
    median_physical_to_logical_ratio: f64,
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

#[allow(clippy::cast_precision_loss)]
fn ratio(numerator: u64, denominator: u64) -> f64 {
    numerator as f64 / denominator as f64
}

fn optional_number(value: Option<f64>) -> String {
    value.map_or_else(|| "-".to_owned(), |number| format!("{number:.1}"))
}
