//! Matched public `EventBus` route-selection microbench.
//!
//! Measures `EventBus::publish` + own-route `try_drain` with N foreign exact
//! scoped subscriptions sharing the same wildcard topic. No allocation
//! logging. Intended for standalone release binaries compared across source
//! revisions (ABBA), not as an ordinary unit-test workload.
//!
//! Product-source identity for a frozen binary comes from the external build
//! receipt written when that artifact was produced. This process does not
//! print a git HEAD: the checkout that *invokes* a frozen binary may differ
//! from the astrid-events sources it was linked against.
//!
//! Usage:
//!   cargo run -p astrid-events --release --example `route_selection_bench` -- \
//!     --label corrected --foreign 10000 --iters 2000 --warmups 2

#[path = "route_selection_bench_args.rs"]
mod route_selection_bench_args;

use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use astrid_events::{
    AstridEvent, EventBus, EventMetadata, IpcMessage, IpcPayload, MAX_SUBSCRIPTION_BUDGET_BYTES,
};
use astrid_types::Topic;
use route_selection_bench_args::BenchConfig;
use uuid::Uuid;

fn event_on(topic: &str, principal: Option<&str>) -> AstridEvent {
    let mut message = IpcMessage::new(
        Topic::from_raw(topic),
        IpcPayload::RawJson(serde_json::json!({})),
        Uuid::nil(),
    );
    message.principal = principal.map(str::to_owned);
    AstridEvent::Ipc {
        metadata: EventMetadata::new("route_selection_bench"),
        message,
    }
}

fn assert_own_delivery(expected: &AstridEvent, drained: &[std::sync::Arc<AstridEvent>]) {
    assert_eq!(
        drained.len(),
        1,
        "own route must receive exactly one event per publish"
    );
    let AstridEvent::Ipc {
        metadata: expected_meta,
        message: expected_msg,
    } = expected
    else {
        panic!("bench event must be Ipc");
    };
    let AstridEvent::Ipc {
        metadata: got_meta,
        message: got_msg,
    } = drained[0].as_ref()
    else {
        panic!("drained event must be Ipc");
    };
    assert_eq!(got_meta.event_id, expected_meta.event_id);
    assert_eq!(got_msg.topic.as_str(), expected_msg.topic.as_str());
    assert_eq!(
        got_msg.principal.as_deref(),
        expected_msg.principal.as_deref()
    );
}

fn measure(foreign: usize, iters: u32, warmups: u32) -> (Duration, Duration) {
    let bus = EventBus::new();
    let mut held = Vec::with_capacity(foreign.saturating_add(1));
    for ordinal in 0..foreign {
        held.push(bus.subscribe_topic_routed_scoped(
            Uuid::new_v4(),
            "scale.*",
            "fixture",
            "bench",
            Some(Some(format!("foreign-{ordinal}"))),
        ));
    }
    let mut own = bus.subscribe_topic_routed_scoped(
        Uuid::new_v4(),
        "scale.*",
        "own",
        "bench",
        Some(Some("alice".into())),
    );
    let event = event_on("scale.request", Some("alice"));
    for _ in 0..warmups {
        bus.publish(black_box(event.clone()));
        let drained = own.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES);
        assert_own_delivery(&event, &drained);
        let _ = black_box(drained);
    }
    let start = Instant::now();
    for _ in 0..iters {
        bus.publish(black_box(event.clone()));
        let drained = own.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES);
        assert_own_delivery(&event, &drained);
        let _ = black_box(drained);
    }
    let total = start.elapsed();
    // Parser rejects --iters 0; checked_div keeps clippy arithmetic lint honest.
    let per = total
        .checked_div(iters)
        .expect("iters validated >= 1 by BenchConfig::parse");
    drop(held);
    (total, per)
}

fn main() -> ExitCode {
    let cfg = match BenchConfig::parse(env::args().skip(1)) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("route_selection_bench: {err}");
            return ExitCode::from(2);
        },
    };
    let exe = env::current_exe().map_or_else(|_| "unknown".into(), |p| p.display().to_string());

    let (total, per) = measure(cfg.foreign, cfg.iters, cfg.warmups);
    // Product-source head is recorded in the external frozen-artifact receipt,
    // not inferred from whatever checkout happens to invoke this binary.
    println!(
        "route_selection_bench label={} foreign={} iters={} warmups={} total_ns={} per_publish_ns={} exe={exe}",
        cfg.label,
        cfg.foreign,
        cfg.iters,
        cfg.warmups,
        total.as_nanos(),
        per.as_nanos()
    );
    ExitCode::SUCCESS
}
