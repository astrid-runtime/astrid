//! Malformed-argv regressions for the release microbench parser.
//!
//! Shares the example's one-pass parser so a typo cannot silently become an
//! n1 measurement. Well-formed ABBA argv remains accepted unchanged.

#[path = "../examples/route_selection_bench_args.rs"]
mod route_selection_bench_args;

use route_selection_bench_args::{BenchArgsError, BenchConfig};

#[test]
fn wellformed_abba_argv_is_unchanged() {
    let cfg = BenchConfig::parse([
        "--label",
        "corrected",
        "--foreign",
        "10000",
        "--iters",
        "2000",
        "--warmups",
        "2",
    ])
    .expect("valid ABBA argv");
    assert_eq!(
        cfg,
        BenchConfig {
            label: "corrected".into(),
            foreign: 10_000,
            iters: 2_000,
            warmups: 2,
        }
    );
}

#[test]
fn unknown_flag_is_rejected() {
    let err = BenchConfig::parse(["--label", "x", "--foregin", "10"]).unwrap_err();
    assert_eq!(err, BenchArgsError::UnknownFlag("--foregin".into()));
}

#[test]
fn missing_label_value_is_rejected() {
    let err = BenchConfig::parse(["--label"]).unwrap_err();
    assert_eq!(err, BenchArgsError::MissingValue("--label"));
}

#[test]
fn label_value_looking_like_flag_is_rejected() {
    let err = BenchConfig::parse(["--label", "--foreign"]).unwrap_err();
    assert_eq!(err, BenchArgsError::MissingValue("--label"));
}

#[test]
fn zero_iters_is_rejected() {
    let err = BenchConfig::parse(["--iters", "0"]).unwrap_err();
    assert_eq!(err, BenchArgsError::ItersMustBePositive);
}

#[test]
fn positional_token_is_rejected() {
    let err = BenchConfig::parse(["oops"]).unwrap_err();
    assert_eq!(err, BenchArgsError::UnknownFlag("oops".into()));
}
