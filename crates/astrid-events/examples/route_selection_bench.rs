//! Matched public EventBus route-selection microbench.
//!
//! Measures `EventBus::publish` + own-route `try_drain` with N foreign exact
//! scoped subscriptions sharing the same wildcard topic. No allocation
//! logging. Intended for standalone release binaries compared across source
//! revisions (ABBA), not as an ordinary unit-test workload.
//!
//! Usage:
//!   cargo run -p astrid-events --release --example route_selection_bench -- \
//!     --label corrected --foreign 10000 --iters 2000 --warmups 2

use std::env;
use std::hint::black_box;
use std::process::{Command, ExitCode};
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

fn git_head() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .and_then(|out| {
            if out.status.success() {
                Some(String::from_utf8_lossy(&out.stdout).trim().to_owned())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into())
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
        let _ = black_box(own.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES));
    }
    let start = Instant::now();
    for _ in 0..iters {
        bus.publish(black_box(event.clone()));
        let _ = black_box(own.try_drain(MAX_SUBSCRIPTION_BUDGET_BYTES));
    }
    let total = start.elapsed();
    let per = total / iters.max(1);
    drop(held);
    (total, per)
}

fn main() -> ExitCode {
    let label = parse_label();
    let foreign = parse_usize("--foreign", 0);
    let iters = parse_u32("--iters", 2_000);
    let warmups = parse_u32("--warmups", 2);
    let head = git_head();
    let exe = env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "unknown".into());

    let (total, per) = measure(foreign, iters, warmups);
    println!(
        "route_selection_bench label={label} head={head} foreign={foreign} iters={iters} warmups={warmups} total_ns={} per_publish_ns={} exe={exe}",
        total.as_nanos(),
        per.as_nanos()
    );
    ExitCode::SUCCESS
}
