//! Matched public EventBus route-selection microbench.
//!
//! Measures a validated iteration: owned-event publish, own-route drain,
//! identity-field assertions, loop overhead and natural per-iteration drops.
//! Caller event cloning is prepared before timing. N foreign exact scoped
//! subscriptions share the same wildcard topic. No allocation
//! logging. Intended for standalone release binaries compared across source
//! revisions (ABBA), not as an ordinary unit-test workload.
//!
//! Product-source identity for a frozen binary comes from the external build
//! receipt written when that artifact was produced. This process does not
//! print a git HEAD: the checkout that *invokes* a frozen binary may differ
//! from the astrid-events sources it was linked against.
//!
//! Usage:
//!   cargo run -p astrid-events --release --example route_selection_bench -- \
//!     --label corrected --foreign 10000 --iters 2000 --warmups 2

use std::env;
use std::hint::black_box;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use astrid_events::{
    AstridEvent, EventBus, EventMetadata, IpcMessage, IpcPayload, MAX_SUBSCRIPTION_BUDGET_BYTES,
};
use astrid_types::Topic;
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

fn parse_u32(flag: &str, default: u32) -> u32 {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == flag {
            return args
                .next()
                .expect("missing value")
                .parse()
                .expect("invalid u32");
        }
    }
    default
}

fn parse_usize(flag: &str, default: usize) -> usize {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == flag {
            return args
                .next()
                .expect("missing value")
                .parse()
                .expect("invalid usize");
        }
    }
    default
}

fn parse_label() -> String {
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--label" {
            return args.next().unwrap_or_else(|| "unlabeled".into());
        }
    }
    "unlabeled".into()
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
    // Prebuild caller-owned events so allocation/string cloning is not charged
    // to routing. Construct the iterator before timing; its backing allocation
    // is released after timing, while drained batches keep their natural drops.
    let prepared: Vec<_> = (0..iters).map(|_| event.clone()).collect();
    let mut events = prepared.into_iter();
    let start = Instant::now();
    for owned_event in events.by_ref() {
        bus.publish(black_box(owned_event));
        let drained = own.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES);
        assert_own_delivery(&event, &drained);
        let _ = black_box(drained);
    }
    let total = start.elapsed();
    let per = total / iters;
    drop(held);
    (total, per)
}

fn main() -> ExitCode {
    let label = parse_label();
    let foreign = parse_usize("--foreign", 0);
    let iters = parse_u32("--iters", 2_000);
    let warmups = parse_u32("--warmups", 2);
    if iters == 0 {
        eprintln!("route_selection_bench: --iters must be >= 1 (got 0)");
        return ExitCode::from(2);
    }
    let exe = env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".into());

    let (total, per) = measure(foreign, iters, warmups);
    // Product-source head is recorded in the external frozen-artifact receipt,
    // not inferred from whatever checkout happens to invoke this binary.
    println!(
        "route_selection_bench label={label} foreign={foreign} iters={iters} warmups={warmups} scope=validated_publish_drain_iteration_v2 total_ns={} per_iteration_ns={} exe={exe}",
        total.as_nanos(),
        per.as_nanos()
    );
    ExitCode::SUCCESS
}
