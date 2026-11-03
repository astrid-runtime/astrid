#![allow(dead_code)]

use std::error::Error;
use std::path::PathBuf;
use std::time::Duration;

#[path = "../benches/storage_io/config.rs"]
mod config;
#[path = "../benches/storage_io/provenance.rs"]
mod provenance;
#[path = "../benches/storage_io/report.rs"]
mod report;
#[path = "../benches/storage_io/workloads.rs"]
mod workloads;

use config::Config;
use provenance::RunProvenance;
use report::Report;
use sha2::{Digest, Sha256};

type BenchResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

fn config() -> Config {
    Config {
        selection: config::Selection::Existing,
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
fn report_serializes_representation_bytes_per_new_object() {
    let mut report = Report::new(config(), provenance());
    report
        .record_representation_metadata("direct", vec![(4, 100), (5, 150)])
        .expect("nonzero object samples are valid");

    let encoded = serde_json::to_value(report).expect("report serializes");
    let metadata = &encoded["representation_metadata"][0];
    assert_eq!(metadata["name"], "direct");
    assert_eq!(metadata["median_bytes_per_new_object"], 27.5);
    assert_eq!(metadata["samples"][0]["new_objects"], 4);
    assert_eq!(metadata["samples"][1]["authoritative_bytes_appended"], 150);
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

#[test]
fn evolving_kv_selection_is_explicit_and_unknown_modes_fail_closed() {
    let existing = Config::from_arguments(std::iter::empty()).expect("defaults parse");
    assert_eq!(existing.selection, config::Selection::Existing);
    let selected = Config::from_arguments(
        ["--only", "evolving-kv", "--samples", "2"]
            .into_iter()
            .map(str::to_owned),
    )
    .expect("probe selection parses");
    assert_eq!(selected.selection, config::Selection::EvolvingKv);
    assert_eq!(selected.samples, 2);
    assert!(Config::from_arguments(["--only"].into_iter().map(str::to_owned)).is_err());
    assert!(
        Config::from_arguments(["--only", "all-but-unknown"].into_iter().map(str::to_owned))
            .is_err()
    );
}

#[test]
fn evolving_kv_growth_covers_closed_sequences_and_reads_are_explicit() {
    let root = tempfile::tempdir().expect("owned benchmark root");
    let mut config = config();
    config.samples = 1;
    config.selection = config::Selection::EvolvingKv;
    let mut report = Report::new(config.clone(), provenance());
    workloads::evolving_kv::run(&config, root.path(), &mut report)
        .expect("public KV writes and reopened exact readback");
    let encoded = serde_json::to_value(report).expect("report serializes");
    let metrics = encoded["metrics"].as_array().expect("metric array");
    assert_eq!(metrics.len(), 14);
    let growth = encoded["write_amplifications"]
        .as_array()
        .expect("growth array");
    assert_eq!(growth.len(), 2);
    for (prefix, final_bytes) in [("kv_512k", 540_672), ("kv_8m", 8_404_992)] {
        assert!(
            metrics
                .iter()
                .any(|row| row["name"] == format!("{prefix}_read_warm"))
        );
        let row = growth
            .iter()
            .find(|row| row["name"] == format!("{prefix}_closed_sequence"))
            .expect("only closed-sequence growth is attributed");
        assert_eq!(row["logical_bytes_per_sample"], final_bytes);
    }
    assert!(!root.path().join("source.bin").exists());
}
