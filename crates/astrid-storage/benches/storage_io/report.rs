use std::env;
use std::num::NonZeroUsize;
use std::time::Duration;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::config::{Config, MEBIBYTE};
use super::provenance::RunProvenance;

#[derive(Debug, Serialize)]
pub(super) struct Report {
    provenance: RunProvenance,
    package_version: &'static str,
    os: &'static str,
    architecture: &'static str,
    logical_cpus: usize,
    config: Config,
    metrics: Vec<Metric>,
    substrate_comparisons: Vec<SubstrateComparison>,
    throughput_scaling: Vec<ThroughputScaling>,
    write_amplifications: Vec<WriteAmplification>,
    representation_metadata: Vec<RepresentationMetadata>,
}

impl Report {
    pub(super) fn new(config: Config, provenance: RunProvenance) -> Self {
        Self {
            provenance,
            package_version: env!("CARGO_PKG_VERSION"),
            os: env::consts::OS,
            architecture: env::consts::ARCH,
            logical_cpus: std::thread::available_parallelism().map_or(1, NonZeroUsize::get),
            config,
            metrics: Vec::new(),
            substrate_comparisons: Vec::new(),
            throughput_scaling: Vec::new(),
            write_amplifications: Vec::new(),
            representation_metadata: Vec::new(),
        }
    }

    pub(super) fn encode_evidence(&self) -> serde_json::Result<Vec<u8>> {
        let payload_json = serde_json::to_string(self)?;
        let digest = PayloadDigest {
            algorithm: "sha-256",
            scope: "utf8:payload_json:astrid-storage-io-benchmark-v2",
            hex: hex::encode(Sha256::digest(payload_json.as_bytes())),
        };
        serde_json::to_vec_pretty(&EvidenceEnvelope {
            format: "astrid-storage-io-benchmark-v2",
            payload_digest: digest,
            payload_json: &payload_json,
            payload: self,
        })
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

    pub(super) fn record_throughput_scaling(
        &mut self,
        name: &'static str,
        aggregate_metric: &'static str,
        single_principal_metric: &'static str,
    ) -> Result<(), String> {
        let aggregate_mib_per_second = self
            .metric(aggregate_metric)
            .ok_or_else(|| format!("unknown aggregate scaling metric {aggregate_metric:?}"))?
            .median_mib_per_second
            .ok_or_else(|| format!("aggregate scaling metric {aggregate_metric:?} has no bytes"))?;
        let single_principal_mib_per_second = self
            .metric(single_principal_metric)
            .ok_or_else(|| {
                format!("unknown single-principal scaling metric {single_principal_metric:?}")
            })?
            .median_mib_per_second
            .ok_or_else(|| {
                format!("single-principal scaling metric {single_principal_metric:?} has no bytes")
            })?;
        if single_principal_mib_per_second <= 0.0 {
            return Err(format!(
                "single-principal scaling metric {single_principal_metric:?} has zero throughput"
            ));
        }
        self.throughput_scaling.push(ThroughputScaling {
            name,
            aggregate_metric,
            single_principal_metric,
            median_throughput_ratio: aggregate_mib_per_second / single_principal_mib_per_second,
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
        let median = median_u64(&authoritative_bytes_appended);
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

    pub(super) fn record_representation_metadata(
        &mut self,
        name: &'static str,
        samples: Vec<(u64, u64)>,
    ) -> Result<(), String> {
        if samples.is_empty() {
            return Err(format!(
                "representation metadata metric {name:?} has no samples"
            ));
        }
        if samples.iter().any(|(objects, _)| *objects == 0) {
            return Err(format!(
                "representation metadata metric {name:?} has a zero-object sample"
            ));
        }
        let mut encoded = samples
            .into_iter()
            .map(
                |(new_objects, authoritative_bytes_appended)| RepresentationMetadataSample {
                    new_objects,
                    authoritative_bytes_appended,
                    bytes_per_new_object: ratio(authoritative_bytes_appended, new_objects),
                },
            )
            .collect::<Vec<_>>();
        encoded.sort_by(|left, right| {
            left.bytes_per_new_object
                .total_cmp(&right.bytes_per_new_object)
        });
        let ratios = encoded
            .iter()
            .map(|sample| sample.bytes_per_new_object)
            .collect::<Vec<_>>();
        self.representation_metadata.push(RepresentationMetadata {
            name,
            median_bytes_per_new_object: median_f64(&ratios),
            samples: encoded,
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
        if !self.throughput_scaling.is_empty() {
            println!();
            println!("{:<38} {:>18}", "concurrent workload", "aggregate/single");
            for scaling in &self.throughput_scaling {
                println!(
                    "{:<38} {:>17.3}×",
                    scaling.name, scaling.median_throughput_ratio
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
        if !self.representation_metadata.is_empty() {
            println!();
            println!(
                "{:<38} {:>24}",
                "representation publication", "median bytes/new object"
            );
            for metadata in &self.representation_metadata {
                println!(
                    "{:<38} {:>24.1}",
                    metadata.name, metadata.median_bytes_per_new_object
                );
            }
        }
    }

    fn metric(&self, name: &str) -> Option<&Metric> {
        self.metrics.iter().find(|metric| metric.name == name)
    }
}

#[derive(Debug, Serialize)]
struct EvidenceEnvelope<'a> {
    format: &'static str,
    payload_digest: PayloadDigest,
    payload_json: &'a str,
    payload: &'a Report,
}

#[derive(Debug, Serialize)]
struct PayloadDigest {
    algorithm: &'static str,
    scope: &'static str,
    hex: String,
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
struct ThroughputScaling {
    name: &'static str,
    aggregate_metric: &'static str,
    single_principal_metric: &'static str,
    median_throughput_ratio: f64,
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

#[derive(Debug, Serialize)]
struct RepresentationMetadata {
    name: &'static str,
    samples: Vec<RepresentationMetadataSample>,
    median_bytes_per_new_object: f64,
}

#[derive(Debug, Serialize)]
struct RepresentationMetadataSample {
    new_objects: u64,
    authoritative_bytes_appended: u64,
    bytes_per_new_object: f64,
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
        let median = median_duration(&samples);
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

fn median_duration(sorted: &[Duration]) -> Duration {
    match sorted.len() {
        0 => Duration::ZERO,
        length if length % 2 == 1 => sorted[length / 2],
        length => {
            let middle = length / 2;
            let lower = sorted[middle
                .checked_sub(1)
                .expect("a nonempty even slice has a lower midpoint")];
            let upper = sorted[middle];
            let half_difference = upper
                .checked_sub(lower)
                .and_then(|difference| difference.checked_div(2))
                .expect("sorted durations have a representable midpoint");
            lower
                .checked_add(half_difference)
                .expect("the midpoint is bounded by the upper duration")
        },
    }
}

fn median_u64(sorted: &[u64]) -> u64 {
    match sorted.len() {
        0 => 0,
        length if length % 2 == 1 => sorted[length / 2],
        length => {
            let middle = length / 2;
            let lower = sorted[middle
                .checked_sub(1)
                .expect("a nonempty even slice has a lower midpoint")];
            let upper = sorted[middle];
            let half_difference = upper
                .checked_sub(lower)
                .and_then(|difference| difference.checked_div(2))
                .expect("sorted integers have a representable midpoint");
            lower
                .checked_add(half_difference)
                .expect("the midpoint is bounded by the upper integer")
        },
    }
}

fn median_f64(sorted: &[f64]) -> f64 {
    match sorted.len() {
        0 => 0.0,
        length if length % 2 == 1 => sorted[length / 2],
        length => {
            let middle = length / 2;
            let lower = middle
                .checked_sub(1)
                .expect("a nonempty even slice has a lower midpoint");
            sorted[lower].midpoint(sorted[middle])
        },
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
