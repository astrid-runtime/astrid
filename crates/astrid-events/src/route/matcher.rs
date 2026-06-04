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
        let topic = &message.topic;
        if topic.split('.').count() > Self::MAX_TOPIC_DEPTH {
            return false;
        }

        if let Some(prefix_pat) = self.pattern.strip_suffix(".*") {
            // Trailing `*` matches 1+ remaining segments after the
            // prefix.
            let prefix_segs: Vec<&str> = prefix_pat.split('.').collect();
            let topic_segs: Vec<&str> = topic.split('.').collect();
            if topic_segs.len() <= prefix_segs.len() {
                return false;
            }
            prefix_segs
                .iter()
                .zip(topic_segs.iter())
                .all(|(p, t)| p == &"*" || p == t)
        } else {
            // Exact: segment counts must match and every segment must
            // pass single-segment wildcard semantics.
            let pat_segs: Vec<&str> = self.pattern.split('.').collect();
            let topic_segs: Vec<&str> = topic.split('.').collect();
            pat_segs.len() == topic_segs.len()
                && pat_segs
                    .iter()
                    .zip(topic_segs.iter())
                    .all(|(p, t)| p == &"*" || p == t)
        }
    }

    /// Pattern as configured.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
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
    use crate::ipc::{IpcMessage, IpcPayload};
    use serde_json::json;
    use uuid::Uuid;

    fn ipc(topic: &str) -> Arc<AstridEvent> {
        let msg = IpcMessage::new(topic, IpcPayload::RawJson(json!({})), Uuid::nil());
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
