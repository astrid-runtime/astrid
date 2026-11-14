#![allow(dead_code)]

use std::error::Error;
use std::num::NonZeroUsize;
use std::path::PathBuf;
use std::time::Duration;

#[path = "../benches/storage_io/config.rs"]
mod config;
#[path = "../benches/storage_io/provenance.rs"]
mod provenance;
#[path = "../benches/storage_io/report.rs"]
mod report;

use config::Config;
use provenance::RunProvenance;
use report::Report;
use sha2::{Digest, Sha256};

type BenchResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

fn config() -> Config {
    Config {
        bytes: 1,
        block_bytes: 1,
        range_bytes: 1,
        samples: 2,
        small_files: 1,
        small_file_bytes: 1,
        concurrent_principals: 4,
        bulk_workers: 4,
        bulk_files: 100,
        object_cache_bytes: None,
        partial_verification_clone: false,
        checkpoint_overwrites: None,
        root: Some(PathBuf::from("unused")),
        output: None,
    }
}

fn provenance() -> RunProvenance {
    RunProvenance::from_evidence(
        "fixture-revision".to_owned(),
        Vec::new(),
        vec!["storage_io".to_owned()],
        0,
        hex::encode(Sha256::digest([])),
    )
}

#[test]
fn even_sample_medians_use_the_two_central_observations() {
    let mut report = Report::new(config(), provenance());
    report.record_bytes(
        "duration",
        1,
        vec![Duration::from_millis(20), Duration::from_millis(10)],
    );
    report
        .record_write_amplification("amplification", 5, vec![20, 10])
        .expect("valid amplification samples");

    let encoded = serde_json::to_value(report).expect("report serializes");
    assert_eq!(encoded["metrics"][0]["median_milliseconds"], 15.0);
    assert_eq!(
        encoded["write_amplifications"][0]["median_authoritative_bytes_appended"],
        15
    );
}

#[test]
fn report_serializes_concurrent_to_single_principal_scaling() {
    let mut report = Report::new(config(), provenance());
    report.record_bytes("single", 100, vec![Duration::from_secs(1)]);
    report.record_bytes("aggregate", 400, vec![Duration::from_secs(2)]);
    report
        .record_throughput_scaling("four_principals", "aggregate", "single")
        .expect("byte metrics can be compared");

    let encoded = serde_json::to_value(report).expect("report serializes");
    let scaling = &encoded["throughput_scaling"][0];
    assert_eq!(scaling["aggregate_metric"], "aggregate");
    assert_eq!(scaling["single_principal_metric"], "single");
    assert_eq!(scaling["median_throughput_ratio"], 2.0);
}

#[test]
fn representation_placeholder_series_stays_empty() {
    let mut report = Report::new(config(), provenance());
    report.record_bytes("duration", 1, vec![Duration::from_millis(1)]);

    let encoded = serde_json::to_value(report).expect("report serializes");
    assert_eq!(encoded["representation_metadata"], serde_json::json!([]));
}

#[test]
fn omitted_checkpoint_flag_keeps_the_existing_full_bench() {
    let parsed = Config::from_args_iter(Vec::<String>::new()).expect("empty args");
    assert!(parsed.checkpoint_overwrites.is_none());
    assert!(parsed.object_cache_bytes.is_none());
    assert!(!parsed.partial_verification_clone);
}

#[test]
fn explicit_zero_checkpoint_overwrites_is_rejected() {
    let error = Config::from_args_iter(["--checkpoint-overwrites".to_owned(), "0".to_owned()])
        .expect_err("zero is not a profile");
    assert!(error.to_string().contains("greater than zero"), "{error}");
}

#[test]
fn checkpoint_overwrites_selects_the_exclusive_runtime_default_profile() {
    let parsed = Config::from_args_iter(["--checkpoint-overwrites".to_owned(), "4096".to_owned()])
        .expect("matched overwrite count");
    assert_eq!(
        parsed.checkpoint_overwrites.map(NonZeroUsize::get),
        Some(4096)
    );
    assert!(parsed.object_cache_bytes.is_none());
}

#[test]
fn checkpoint_overwrites_rejects_cache_and_clone_overrides() {
    let cache = Config::from_args_iter([
        "--checkpoint-overwrites".to_owned(),
        "4096".to_owned(),
        "--object-cache-bytes".to_owned(),
        "1024".to_owned(),
    ])
    .expect_err("cache override is incompatible");
    assert!(cache.to_string().contains("object-cache"), "{cache}");

    let clone = Config::from_args_iter([
        "--checkpoint-overwrites".to_owned(),
        "4096".to_owned(),
        "--partial-verification-clone".to_owned(),
        "--object-cache-bytes".to_owned(),
        "1024".to_owned(),
    ])
    .expect_err("clone profile is incompatible");
    assert!(
        clone.to_string().contains("partial-verification-clone"),
        "{clone}"
    );
}

#[test]
fn unsorted_count_series_preserves_order_and_stays_out_of_byte_peaks() {
    let mut report = Report::new(config(), provenance());
    report
        .record_counts("generations", vec![5, 1, 3])
        .expect("nonzero count samples are valid");
    report
        .record_counts("regions", vec![8, 2, 6, 4])
        .expect("even count samples are valid");
    report
        .record_resource_peak("metadata_bytes", vec![100, 10])
        .expect("byte samples are valid");

    let encoded = serde_json::to_value(report).expect("report serializes");
    let generations = &encoded["count_samples"][0];
    assert_eq!(generations["name"], "generations");
    assert_eq!(generations["samples_counts"], serde_json::json!([5, 1, 3]));
    assert_eq!(generations["minimum_count"], 1);
    assert_eq!(generations["median_count"], 3);
    assert_eq!(generations["maximum_count"], 5);
    assert!(generations.get("samples_bytes").is_none());
    assert!(generations.get("minimum_bytes").is_none());

    let regions = &encoded["count_samples"][1];
    assert_eq!(regions["samples_counts"], serde_json::json!([8, 2, 6, 4]));
    assert_eq!(regions["minimum_count"], 2);
    assert_eq!(regions["median_count"], 5);
    assert_eq!(regions["maximum_count"], 8);

    let peak = &encoded["resource_peaks"][0];
    assert_eq!(peak["name"], "metadata_bytes");
    assert_eq!(peak["samples_bytes"], serde_json::json!([100, 10]));
    assert_eq!(peak["minimum_bytes"], 10);
    assert_eq!(peak["median_bytes"], 55);
    assert_eq!(peak["maximum_bytes"], 100);
    assert!(peak.get("samples_counts").is_none());
    assert_eq!(encoded["count_samples"].as_array().map(Vec::len), Some(2));
    assert_eq!(encoded["resource_peaks"].as_array().map(Vec::len), Some(1));
}

#[test]
fn empty_count_series_is_rejected() {
    let mut report = Report::new(config(), provenance());
    let error = report
        .record_counts("empty", Vec::new())
        .expect_err("empty count series is invalid");
    assert!(error.contains("no samples"), "{error}");
}

#[test]
fn timing_samples_retain_operation_order_with_sorted_summaries() {
    let mut report = Report::new(config(), provenance());
    report.record_operations(
        "overwrite",
        1,
        vec![
            Duration::from_millis(30),
            Duration::from_millis(10),
            Duration::from_millis(20),
        ],
    );
    let encoded = serde_json::to_value(report).expect("report serializes");
    let metric = &encoded["metrics"][0];
    assert_eq!(
        metric["samples_nanoseconds"],
        serde_json::json!([30_000_000, 10_000_000, 20_000_000])
    );
    assert_eq!(metric["minimum_milliseconds"], 10.0);
    assert_eq!(metric["median_milliseconds"], 20.0);
    assert_eq!(metric["maximum_milliseconds"], 30.0);
}

#[test]
fn evidence_envelope_binds_the_complete_payload() {
    let provenance = provenance();
    let revision = provenance.revision().to_owned();
    let mut report = Report::new(config(), provenance);
    report.record_bytes("bytes", 1, vec![Duration::from_nanos(1)]);
    let payload_json = serde_json::to_string(&report).expect("report payload serializes");
    let expected = hex::encode(Sha256::digest(payload_json.as_bytes()));

    let encoded = report.encode_evidence().expect("evidence serializes");
    let envelope: serde_json::Value =
        serde_json::from_slice(&encoded).expect("evidence is valid JSON");

    assert_eq!(envelope["format"], "astrid-storage-io-benchmark-v2");
    assert_eq!(envelope["payload_digest"]["algorithm"], "sha-256");
    assert_eq!(envelope["payload_digest"]["hex"], expected);
    assert_eq!(envelope["payload_json"], payload_json);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            envelope["payload_json"]
                .as_str()
                .expect("payload_json is a string")
        )
        .expect("payload_json contains JSON"),
        envelope["payload"]
    );
    assert_eq!(envelope["payload"]["provenance"]["git_revision"], revision);
}
