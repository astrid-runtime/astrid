#![allow(dead_code)]

use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

#[path = "../benches/storage_io/config.rs"]
mod config;
#[path = "../benches/storage_io/report.rs"]
mod report;

use config::Config;
use report::Report;

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
        object_cache_bytes: None,
        root: Some(PathBuf::from("unused")),
        output: None,
    }
}

#[test]
fn even_sample_medians_use_the_two_central_observations() {
    let mut report = Report::new(config());
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
    let mut report = Report::new(config());
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
