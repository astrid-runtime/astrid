//! Passive event-bus activity monitor.
//!
//! A truly idle daemon publishes almost nothing except the fleet-sized ReAct
//! watchdog fan-out and the 10s capsule health tick. Expected kernel watchdog
//! traffic is excluded from the storm-rate numerator; a *sustained*
//! triple-digit rate from other topics with no client attached is therefore the
//! signature of a feedback loop / event storm:
//! the failure mode that pegs CPU because every published event wakes every
//! broadcast subscriber (the dispatcher plus each capsule run-loop), and the
//! dispatcher re-invokes WASM interceptors for matching topics.
//!
//! This monitor exists so that the *next* such incident is self-diagnosing: it
//! names the hottest topics in the log instead of leaving an operator to guess
//! which publisher ran away. It is a pure observer — it counts on its own
//! subscriber rather than inside [`EventBus::publish`](astrid_events::EventBus),
//! so it adds **zero** overhead to the publish hot path, and it does no WASM
//! work, so it keeps reporting even while a storm saturates the dispatcher and
//! the capsule workers.

use std::collections::HashMap;

use astrid_events::{AstridEvent, EventBus};

/// Rolling window over which publish counts are aggregated before the rate is
/// evaluated and the tally reset.
const BUS_ACTIVITY_WINDOW: std::time::Duration = std::time::Duration::from_secs(5);

/// Sustained publish rate (events/second, averaged over the actual elapsed
/// window) at or above which the monitor escalates from `DEBUG` to a `WARN`
/// that names the hottest topics.
const BUS_STORM_RATE_THRESHOLD: f64 = 100.0;

/// How many of the hottest topics to name in a storm warning.
const BUS_STORM_TOP_TOPICS: usize = 5;

/// Pseudo-topic under which events dropped to broadcast lag are tallied, so an
/// overflow storm is attributed to volume instead of silently vanishing.
const LAGGED_LABEL: &str = "(dropped/lagged)";

/// Verdict for one aggregation window. Pure data so the decision logic is
/// unit-testable without spawning a task or waiting on wall-clock time.
struct WindowSummary {
    /// Total events observed in the window (including dropped/lagged).
    total: u64,
    /// Average events per second over the actual elapsed window.
    rate: f64,
    /// Whether `rate` crossed [`BUS_STORM_RATE_THRESHOLD`].
    is_storm: bool,
    /// `topic=count` for the hottest topics, comma-joined. Empty unless
    /// `is_storm` (we only pay the sort/format cost when escalating).
    top_topics: String,
}

#[derive(Default)]
struct WindowCounts {
    topics: HashMap<String, u64>,
    expected_kernel_watchdogs: u64,
}

/// Evaluates one window's tally. Sorts by count descending, breaking ties by
/// topic name ascending so the output is deterministic.
#[expect(
    clippy::cast_precision_loss,
    reason = "event counts in a 5s window stay far below 2^53, where f64 is exact"
)]
fn summarize_window(counts: &WindowCounts, elapsed_secs: f64) -> WindowSummary {
    let total: u64 = counts.topics.values().copied().sum();
    let storm_events = total.saturating_sub(counts.expected_kernel_watchdogs);
    let rate = if elapsed_secs > 0.0 {
        storm_events as f64 / elapsed_secs
    } else {
        0.0
    };
    let is_storm = rate >= BUS_STORM_RATE_THRESHOLD;

    let top_topics = if is_storm {
        let mut ranked: Vec<(&str, u64)> = counts
            .topics
            .iter()
            .filter_map(|(topic, count)| {
                let observed = if topic == crate::REACT_WATCHDOG_TOPIC {
                    count.saturating_sub(counts.expected_kernel_watchdogs)
                } else {
                    *count
                };
                (observed > 0).then_some((topic.as_str(), observed))
            })
            .collect();
        ranked.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        ranked
            .iter()
            .take(BUS_STORM_TOP_TOPICS)
            .map(|(topic, count)| format!("{topic}={count}"))
            .collect::<Vec<_>>()
            .join(", ")
    } else {
        String::new()
    };

    WindowSummary {
        total,
        rate,
        is_storm,
        top_topics,
    }
}

/// Resolves the tally key for an event without allocating: IPC events key off
/// the message topic, lifecycle events off their `&'static str` `event_type()`.
fn event_topic(event: &AstridEvent) -> &str {
    match event {
        AstridEvent::Ipc { message, .. } => message.topic.as_str(),
        other => other.event_type(),
    }
}

fn is_expected_kernel_watchdog(event: &AstridEvent) -> bool {
    matches!(
        event,
        AstridEvent::Ipc { metadata, message }
            if metadata.source == "kernel" && message.topic.as_str() == crate::REACT_WATCHDOG_TOPIC
    )
}

/// Adds one event to its topic tally. The borrowed `get_mut` lookup keeps the storm
/// hot path allocation-free for already-seen topics — a `String` is only minted
/// the first time a topic appears in the window.
fn bump(counts: &mut WindowCounts, event: &AstridEvent) {
    let topic = event_topic(event);
    if let Some(count) = counts.topics.get_mut(topic) {
        *count = count.saturating_add(1);
    } else {
        counts.topics.insert(topic.to_string(), 1);
    }
    if is_expected_kernel_watchdog(event) {
        counts.expected_kernel_watchdogs = counts.expected_kernel_watchdogs.saturating_add(1);
    }
}

fn bump_lagged(counts: &mut WindowCounts, n: u64) {
    if let Some(count) = counts.topics.get_mut(LAGGED_LABEL) {
        *count = count.saturating_add(n);
    } else {
        counts.topics.insert(LAGGED_LABEL.to_string(), n);
    }
}

/// Spawns the passive bus-activity monitor. See the module docs for rationale.
///
/// The subscription is taken **synchronously** (before the task is spawned) so
/// it is counted in
/// [`INTERNAL_SUBSCRIBER_COUNT`](crate::INTERNAL_SUBSCRIBER_COUNT) by the time
/// `Kernel::new`'s debug-assert runs — mirroring `EventDispatcher::new`.
pub(crate) fn spawn_bus_activity_monitor(event_bus: &EventBus) -> astrid_runtime::JoinHandle<()> {
    let mut receiver = event_bus.subscribe_as("bus_monitor");

    astrid_runtime::spawn(async move {
        let mut counts = WindowCounts::default();
        let mut window_start = astrid_runtime::time::Instant::now();

        let mut tick = astrid_runtime::time::interval(BUS_ACTIVITY_WINDOW);
        // Don't burst-fire missed ticks: under a storm the recv arm starves
        // the tick, and a catch-up burst would flush tiny sub-windows and
        // under-report the rate. Delaying preserves a full window each flush.
        tick.set_missed_tick_behavior(astrid_runtime::time::MissedTickBehavior::Delay);
        // The first tick is immediate — skip it so window one is a full span.
        tick.tick().await;

        loop {
            tokio::select! {
                event = receiver.recv() => {
                    // `recv` only yields `None` when the bus closes (shutdown).
                    let Some(first) = event else { break };
                    bump(&mut counts, &first);
                    // Drain everything else already buffered without re-entering
                    // select! per event — under a storm this batches the work
                    // (one wakeup, many events) and keeps the monitor from
                    // falling behind the publishers.
                    while let Some(ev) = receiver.try_recv() {
                        bump(&mut counts, &ev);
                    }
                    // Fold any events dropped to broadcast lag into the tally
                    // so an overflow spike still surfaces in the rate.
                    let lagged = receiver.drain_lagged();
                    if lagged > 0 {
                        bump_lagged(&mut counts, lagged);
                    }
                },
                _ = tick.tick() => {
                    metrics::counter!(
                        crate::METRIC_BACKGROUND_TICKS_TOTAL,
                        "loop" => "bus_monitor",
                    )
                    .increment(1);
                    let elapsed = window_start.elapsed().as_secs_f64();
                    let summary = summarize_window(&counts, elapsed);
                    if summary.is_storm {
                        tracing::warn!(
                            events_per_sec = summary.rate,
                            window_total = summary.total,
                            top_topics = %summary.top_topics,
                            "Event bus storm detected — sustained high publish rate \
                             (likely a feedback loop); hottest topics listed by volume"
                        );
                    } else if summary.total > 0 {
                        tracing::debug!(
                            events_per_sec = summary.rate,
                            window_total = summary.total,
                            "Event bus activity"
                        );
                    }
                    counts = WindowCounts::default();
                    window_start = astrid_runtime::time::Instant::now();
                },
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watchdog(source: &str) -> AstridEvent {
        AstridEvent::Ipc {
            metadata: astrid_events::EventMetadata::new(source),
            message: astrid_events::ipc::IpcMessage::new(
                astrid_events::ipc::Topic::from_raw(crate::REACT_WATCHDOG_TOPIC),
                astrid_events::ipc::IpcPayload::Custom {
                    data: serde_json::json!({}),
                },
                uuid::Uuid::new_v4(),
            ),
        }
    }

    fn counts(pairs: &[(&str, u64)]) -> WindowCounts {
        WindowCounts {
            topics: pairs
                .iter()
                .map(|(topic, count)| ((*topic).to_string(), *count))
                .collect(),
            expected_kernel_watchdogs: 0,
        }
    }

    #[test]
    fn empty_window_is_not_a_storm() {
        let summary = summarize_window(&WindowCounts::default(), 5.0);
        assert_eq!(summary.total, 0);
        assert!(summary.rate.abs() < f64::EPSILON);
        assert!(!summary.is_storm);
        assert!(summary.top_topics.is_empty());
    }

    #[test]
    fn low_rate_is_not_a_storm_and_skips_topic_formatting() {
        // 3 events over 5s = 0.6/s, well under threshold.
        let summary = summarize_window(&counts(&[("astrid.v1.watchdog.tick", 3)]), 5.0);
        assert!(!summary.is_storm);
        // top_topics is only computed when escalating.
        assert!(summary.top_topics.is_empty());
    }

    #[test]
    fn fleet_watchdog_baseline_is_not_a_storm() {
        let summary = summarize_window(
            &WindowCounts {
                topics: HashMap::from([(crate::REACT_WATCHDOG_TOPIC.to_string(), 5_000)]),
                expected_kernel_watchdogs: 5_000,
            },
            5.0,
        );
        assert_eq!(summary.total, 5_000);
        assert!(summary.rate.abs() < f64::EPSILON);
        assert!(!summary.is_storm);
    }

    #[test]
    fn guest_watchdog_topic_traffic_remains_visible_as_a_storm() {
        let mut window = WindowCounts::default();
        for _ in 0..5_000 {
            bump(&mut window, &watchdog("kernel"));
        }
        for _ in 0..500 {
            bump(&mut window, &watchdog("wasm_guest"));
        }

        let summary = summarize_window(&window, 5.0);
        assert!(summary.is_storm);
        assert!((summary.rate - 100.0).abs() < f64::EPSILON);
        assert_eq!(summary.top_topics, "astrid.v1.watchdog.tick=500");
    }

    #[test]
    fn sustained_high_rate_is_a_storm() {
        // 1000 events over 5s = 200/s, over the 100/s threshold.
        let summary = summarize_window(&counts(&[("react.v1.step", 1000)]), 5.0);
        assert!(summary.is_storm);
        assert_eq!(summary.total, 1000);
        assert!((summary.rate - 200.0).abs() < f64::EPSILON);
        assert_eq!(summary.top_topics, "react.v1.step=1000");
    }

    #[test]
    fn storm_names_hottest_topics_in_deterministic_order() {
        let summary = summarize_window(
            &counts(&[
                ("a.low", 10),
                ("b.high", 900),
                ("c.mid", 100),
                ("d.zero", 1),
            ]),
            5.0,
        );
        assert!(summary.is_storm);
        // Sorted by count desc: b.high, c.mid, a.low, d.zero.
        assert_eq!(
            summary.top_topics,
            "b.high=900, c.mid=100, a.low=10, d.zero=1"
        );
    }

    #[test]
    fn ties_break_on_topic_name_for_determinism() {
        let summary = summarize_window(&counts(&[("zzz", 600), ("aaa", 600)]), 5.0);
        assert!(summary.is_storm);
        // Equal counts → alphabetical: aaa before zzz.
        assert_eq!(summary.top_topics, "aaa=600, zzz=600");
    }

    #[test]
    fn top_topics_is_capped() {
        let pairs: Vec<(String, u64)> = (0..10)
            .map(|i| (format!("topic.{i:02}"), 1000 - i))
            .collect();
        let topics: HashMap<String, u64> = pairs.into_iter().collect();
        let summary = summarize_window(
            &WindowCounts {
                topics,
                expected_kernel_watchdogs: 0,
            },
            5.0,
        );
        assert!(summary.is_storm);
        // Only BUS_STORM_TOP_TOPICS entries are named.
        assert_eq!(summary.top_topics.split(", ").count(), BUS_STORM_TOP_TOPICS);
    }

    #[test]
    fn zero_elapsed_does_not_divide_by_zero() {
        let summary = summarize_window(&counts(&[("x", 5)]), 0.0);
        assert!(summary.rate.abs() < f64::EPSILON);
        assert!(!summary.is_storm);
    }

    #[test]
    fn dropped_events_count_toward_the_rate() {
        // A lag spike is attributed to the pseudo-topic and still trips the
        // storm threshold, so an overflow can't hide the spike.
        let summary = summarize_window(&counts(&[(LAGGED_LABEL, 800)]), 5.0);
        assert!(summary.is_storm);
        assert_eq!(summary.top_topics, format!("{LAGGED_LABEL}=800"));
    }
}
