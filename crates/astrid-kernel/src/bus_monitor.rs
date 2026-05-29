//! Passive event-bus activity monitor.
//!
//! A truly idle daemon publishes almost nothing — the 5s ReAct watchdog tick
//! and the 10s capsule health tick dominate, so the steady-state rate is well
//! under one event per second. A *sustained* triple-digit publish rate with no
//! client attached is therefore the signature of a feedback loop / event storm:
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

/// Evaluates one window's tally. Sorts by count descending, breaking ties by
/// topic name ascending so the output is deterministic.
#[expect(
    clippy::cast_precision_loss,
    reason = "event counts in a 5s window stay far below 2^53, where f64 is exact"
)]
fn summarize_window(counts: &HashMap<String, u64>, elapsed_secs: f64) -> WindowSummary {
    let total: u64 = counts.values().copied().sum();
    let rate = if elapsed_secs > 0.0 {
        total as f64 / elapsed_secs
    } else {
        0.0
    };
    let is_storm = rate >= BUS_STORM_RATE_THRESHOLD;

    let top_topics = if is_storm {
        let mut ranked: Vec<(&String, &u64)> = counts.iter().collect();
        ranked.sort_unstable_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
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

/// Adds `n` to `topic`'s tally. The borrowed `get_mut` lookup keeps the storm
/// hot path allocation-free for already-seen topics — a `String` is only minted
/// the first time a topic appears in the window.
fn bump(counts: &mut HashMap<String, u64>, topic: &str, n: u64) {
    if let Some(count) = counts.get_mut(topic) {
        *count = count.saturating_add(n);
    } else {
        counts.insert(topic.to_string(), n);
    }
}

/// Spawns the passive bus-activity monitor. See the module docs for rationale.
///
/// The subscription is taken **synchronously** (before the task is spawned) so
/// it is counted in
/// [`INTERNAL_SUBSCRIBER_COUNT`](crate::INTERNAL_SUBSCRIBER_COUNT) by the time
/// `Kernel::new`'s debug-assert runs — mirroring `EventDispatcher::new`.
pub(crate) fn spawn_bus_activity_monitor(event_bus: &EventBus) -> tokio::task::JoinHandle<()> {
    let mut receiver = event_bus.subscribe_as("bus_monitor");

    tokio::spawn(async move {
        let mut counts: HashMap<String, u64> = HashMap::new();
        let mut window_start = tokio::time::Instant::now();

        let mut tick = tokio::time::interval(BUS_ACTIVITY_WINDOW);
        // Don't burst-fire missed ticks: under a storm the recv arm starves
        // the tick, and a catch-up burst would flush tiny sub-windows and
        // under-report the rate. Delaying preserves a full window each flush.
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick is immediate — skip it so window one is a full span.
        tick.tick().await;

        loop {
            tokio::select! {
                event = receiver.recv() => {
                    // `recv` only yields `None` when the bus closes (shutdown).
                    let Some(first) = event else { break };
                    bump(&mut counts, event_topic(&first), 1);
                    // Drain everything else already buffered without re-entering
                    // select! per event — under a storm this batches the work
                    // (one wakeup, many events) and keeps the monitor from
                    // falling behind the publishers.
                    while let Some(ev) = receiver.try_recv() {
                        bump(&mut counts, event_topic(&ev), 1);
                    }
                    // Fold any events dropped to broadcast lag into the tally
                    // so an overflow spike still surfaces in the rate.
                    let lagged = receiver.drain_lagged();
                    if lagged > 0 {
                        bump(&mut counts, LAGGED_LABEL, lagged);
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
                    counts.clear();
                    window_start = tokio::time::Instant::now();
                },
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(pairs: &[(&str, u64)]) -> HashMap<String, u64> {
        pairs.iter().map(|(t, c)| ((*t).to_string(), *c)).collect()
    }

    #[test]
    fn empty_window_is_not_a_storm() {
        let summary = summarize_window(&HashMap::new(), 5.0);
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
        let map: HashMap<String, u64> = pairs.into_iter().collect();
        let summary = summarize_window(&map, 5.0);
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
