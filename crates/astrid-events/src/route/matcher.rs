//! Topic-pattern matching + small shared helpers used by the routing
//! demux. Kept separate so the route table itself stays focused on the
//! state machine.

use std::sync::Arc;

use crate::event::AstridEvent;

/// Compiled topic-pattern matcher. Mirrors the segment-aware matching
/// semantics of `EventReceiver::matches` so the broadcast and routed
/// paths agree on what each pattern means.
#[derive(Debug, Clone)]
pub struct TopicMatcher {
    pattern: String,
}

impl TopicMatcher {
    /// Maximum allowed topic depth (dot-separated segments). Matches
    /// the bus-level cap.
    pub const MAX_TOPIC_DEPTH: usize = 20;

    /// Compile a topic pattern. The pattern follows the same grammar as
    /// `subscribe_topic_as`: exact match, trailing `*` for namespace
    /// match, mid-segment `*` for single-segment wildcard.
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
        }
    }

    /// True iff the event matches this pattern. Non-IPC events never
    /// match a routed pattern.
    #[must_use]
    pub fn matches(&self, event: &AstridEvent) -> bool {
        let AstridEvent::Ipc { message, .. } = event else {
            return false;
        };
        self.matches_topic(&message.topic)
    }

    /// True iff `topic` matches this pattern. Thin wrapper over the shared,
    /// allocation-free [`topic_pattern_matches`].
    #[must_use]
    pub fn matches_topic(&self, topic: &str) -> bool {
        topic_pattern_matches(&self.pattern, topic)
    }

    /// Pattern as configured.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// True iff `topic` matches `pattern` using trailing-`*`-is-subtree semantics:
/// a trailing `*` matches one OR MORE remaining segments at any depth, a
/// mid-segment `*` matches exactly one segment, otherwise segment counts must
/// be equal. Allocation-free — iterates the segment splits directly.
///
/// The single source of truth shared by routed delivery ([`TopicMatcher`]),
/// broadcast delivery (`EventReceiver::matches`), and the capsule
/// publish/subscribe ACL authorization, so what a capsule is *allowed* to
/// publish/subscribe can never diverge from what is actually delivered.
/// `topic` is either a concrete published topic or a requested sub-pattern
/// being authorized against an ACL entry.
#[must_use]
pub fn topic_pattern_matches(pattern: &str, topic: &str) -> bool {
    if topic.split('.').count() > TopicMatcher::MAX_TOPIC_DEPTH {
        return false;
    }

    if let Some(prefix_pat) = pattern.strip_suffix(".*") {
        // Trailing `*`: the topic must be strictly deeper than the prefix and
        // every prefix segment must match (the `*` covers 1+ remaining).
        topic.split('.').count() > prefix_pat.split('.').count()
            && prefix_pat
                .split('.')
                .zip(topic.split('.'))
                .all(|(p, t)| p == "*" || p == t)
    } else {
        // Exact: equal segment count, each pair single-segment-wildcard match.
        pattern.split('.').count() == topic.split('.').count()
            && pattern
                .split('.')
                .zip(topic.split('.'))
                .all(|(p, t)| p == "*" || p == t)
    }
}

/// Approximate the byte cost of an event for budget bookkeeping. The
/// `Arc<AstridEvent>` size in memory dwarfs the `IpcPayload` content for
/// small messages; we charge the payload's JSON length so a flood of
/// 1-byte payloads doesn't masquerade as a 0-byte stream. Non-IPC
/// events fall back to a flat constant since they don't route through
/// here in practice.
#[must_use]
pub fn ipc_size_of(event: &Arc<AstridEvent>) -> usize {
    match &**event {
        AstridEvent::Ipc { message, .. } => message
            .payload
            .to_guest_bytes()
            .map_or(0, |v| v.len())
            .saturating_add(message.topic.len()),
        _ => 64,
    }
}

/// Label for telemetry classification. Identical mapping to
/// `astrid_capsule::principal_class::PrincipalClass::as_label` so
/// `principal_class` labels collide across both crates.
#[must_use]
pub fn principal_class_label(principal: Option<&str>) -> &'static str {
    match principal {
        None => "system",
        Some(p) if p.starts_with("agent.") || p.starts_with("agent:") => "agent",
        Some(_) => "user",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventMetadata;
    use crate::ipc::{IpcMessage, IpcPayload, Topic};
    use serde_json::json;
    use uuid::Uuid;

    fn ipc(topic: &str) -> Arc<AstridEvent> {
        let msg = IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(json!({})),
            Uuid::nil(),
        );
        Arc::new(AstridEvent::Ipc {
            metadata: EventMetadata::new("test"),
            message: msg,
        })
    }

    #[test]
    fn topic_matcher_exact() {
        let m = TopicMatcher::new("a.b.c");
        assert!(m.matches(&ipc("a.b.c")));
        assert!(!m.matches(&ipc("a.b.d")));
        assert!(!m.matches(&ipc("a.b")));
        assert!(!m.matches(&ipc("a.b.c.d")));
    }

    #[test]
    fn topic_matcher_trailing_wildcard() {
        let m = TopicMatcher::new("a.b.*");
        assert!(m.matches(&ipc("a.b.c")));
        assert!(m.matches(&ipc("a.b.c.d")));
        assert!(!m.matches(&ipc("a.b")));
        assert!(!m.matches(&ipc("a.c.b")));
    }

    #[test]
    fn topic_matcher_middle_wildcard() {
        let m = TopicMatcher::new("a.*.c");
        assert!(m.matches(&ipc("a.b.c")));
        assert!(m.matches(&ipc("a.zz.c")));
        assert!(!m.matches(&ipc("a.b.d")));
        assert!(!m.matches(&ipc("a.b.c.d")));
    }

    #[test]
    fn matches_topic_subtree_for_acl() {
        // Trailing `*` authorizes the whole subtree at any depth — the ACL
        // semantics that let `astrid.v1.admin.*` cover every admin topic
        // without enumerating each depth.
        let m = TopicMatcher::new("astrid.v1.admin.*");
        assert!(m.matches_topic("astrid.v1.admin.quota"));
        assert!(m.matches_topic("astrid.v1.admin.agent.list"));
        assert!(m.matches_topic("astrid.v1.admin.auth.pair.issue"));
        // The prefix itself is not "under" the namespace.
        assert!(!m.matches_topic("astrid.v1.admin"));
        // A different namespace never matches.
        assert!(!m.matches_topic("astrid.v1.registry.get"));

        // Mid-segment `*` stays single-segment.
        let mid = TopicMatcher::new("tool.v1.execute.*.result");
        assert!(mid.matches_topic("tool.v1.execute.read_file.result"));
        assert!(!mid.matches_topic("tool.v1.execute.a.b.result"));

        // Exact (no `*`) stays equal-segment.
        let exact = TopicMatcher::new("a.b.c");
        assert!(exact.matches_topic("a.b.c"));
        assert!(!exact.matches_topic("a.b.c.d"));
    }

    #[test]
    fn matches_topic_enumerated_patterns_stay_compatible() {
        // Backwards-compat: a depth-enumerated `*.*` / `*.*.*` pattern (as
        // existing manifests declare today) still authorizes every topic it did
        // under the old strict matcher — it now also matches deeper, harmlessly —
        // so no capsule manifest needs to change when this lands.
        let five = TopicMatcher::new("astrid.v1.admin.*.*");
        assert!(five.matches_topic("astrid.v1.admin.agent.list")); // old 5-seg target
        assert!(five.matches_topic("astrid.v1.admin.auth.pair")); // old 5-seg target
        assert!(five.matches_topic("astrid.v1.admin.auth.pair.issue")); // now also deeper
        assert!(!five.matches_topic("astrid.v1.admin.quota")); // 4-seg: below the pattern, as before

        let six = TopicMatcher::new("astrid.v1.admin.*.*.*");
        assert!(six.matches_topic("astrid.v1.admin.auth.pair.issue")); // old 6-seg target
        assert!(!six.matches_topic("astrid.v1.admin.agent.list")); // 5-seg: below the pattern, as before
    }

    #[test]
    fn topic_matcher_rejects_non_ipc() {
        let m = TopicMatcher::new("a.*");
        let lifecycle = Arc::new(AstridEvent::RuntimeStarted {
            metadata: EventMetadata::new("test"),
            version: "1".into(),
        });
        assert!(!m.matches(&lifecycle));
    }

    #[test]
    fn principal_class_label_buckets() {
        assert_eq!(principal_class_label(None), "system");
        assert_eq!(principal_class_label(Some("alice")), "user");
        assert_eq!(principal_class_label(Some("agent.scout")), "agent");
        assert_eq!(principal_class_label(Some("agent:scout")), "agent");
    }
}
