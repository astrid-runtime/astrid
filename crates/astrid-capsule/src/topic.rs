//! IPC topic matching for interceptor event patterns.

/// Topic prefix for a tool invocation: `tool.v1.execute.<name>`. Defined here so
/// the ACL scoping ([`crate::access`]) and the load-time route check
/// ([`crate::tool_discovery`]) share one source of truth for the topic scheme.
pub(crate) const TOOL_EXECUTE_PREFIX: &str = "tool.v1.execute.";

/// Returns `true` if `s` has no empty segments — i.e. no leading/trailing dots
/// and no consecutive dots. An empty string is also rejected.
///
/// Used crate-wide: `discovery.rs` (manifest validation) and `engine/wasm/host/ipc.rs`
/// (runtime boundary checks) both depend on this function.
pub(crate) fn has_valid_segments(s: &str) -> bool {
    !s.is_empty() && s.split('.').all(|seg| !seg.is_empty())
}

/// Check if an IPC topic matches an interceptor event pattern.
///
/// Supports exact matches and single-segment wildcards (`*`).
/// Both strings are split on `.` and compared segment by segment.
/// A `*` in the pattern matches exactly one segment.
/// Topics and patterns with empty segments are rejected (defense in depth).
///
/// # Examples
///
/// ```ignore
/// assert!(topic_matches("user.prompt", "user.prompt"));
/// assert!(topic_matches("tool.execute.search.result", "tool.execute.*.result"));
/// assert!(!topic_matches("tool.execute.result", "tool.execute.*.result"));
/// assert!(!topic_matches("user.prompt.extra", "user.prompt"));
/// ```
pub fn topic_matches(topic: &str, pattern: &str) -> bool {
    if !has_valid_segments(topic) || !has_valid_segments(pattern) {
        return false;
    }

    if topic.split('.').count() != pattern.split('.').count() {
        return false;
    }

    topic
        .split('.')
        .zip(pattern.split('.'))
        .all(|(t, p)| p == "*" || t == p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert!(topic_matches("user.prompt", "user.prompt"));
        assert!(topic_matches(
            "llm.stream.anthropic",
            "llm.stream.anthropic"
        ));
    }

    #[test]
    fn wildcard_single_segment() {
        assert!(topic_matches(
            "tool.execute.search.result",
            "tool.execute.*.result"
        ));
        assert!(topic_matches(
            "tool.execute.code-run.result",
            "tool.execute.*.result"
        ));
    }

    #[test]
    fn wildcard_does_not_match_missing_segment() {
        // Pattern has 4 segments but topic has only 3
        assert!(!topic_matches(
            "tool.execute.result",
            "tool.execute.*.result"
        ));
    }

    #[test]
    fn no_match_different_topic() {
        assert!(!topic_matches("user.prompt", "llm.stream.anthropic"));
    }

    #[test]
    fn no_match_extra_segment() {
        assert!(!topic_matches("user.prompt.extra", "user.prompt"));
    }

    #[test]
    fn no_match_fewer_segments() {
        assert!(!topic_matches("user", "user.prompt"));
    }

    #[test]
    fn single_segment_exact() {
        assert!(topic_matches("ping", "ping"));
        assert!(!topic_matches("ping", "pong"));
    }

    #[test]
    fn wildcard_at_start() {
        assert!(topic_matches("foo.bar.baz", "*.bar.baz"));
    }

    #[test]
    fn wildcard_at_end() {
        assert!(topic_matches("foo.bar.baz", "foo.bar.*"));
    }

    #[test]
    fn multiple_wildcards() {
        assert!(topic_matches("a.b.c", "*.b.*"));
        assert!(topic_matches("x.b.z", "*.b.*"));
        assert!(!topic_matches("x.c.z", "*.b.*"));
    }

    #[test]
    fn empty_segments_rejected() {
        // Consecutive dots — empty middle segment
        assert!(!topic_matches("a..b", "a.*.b"));
        assert!(!topic_matches("a.x.b", "a..b"));

        // Leading dot — empty first segment
        assert!(!topic_matches(".a.b", "*.a.b"));
        assert!(!topic_matches("x.a.b", ".a.b"));

        // Trailing dot — empty last segment
        assert!(!topic_matches("a.b.", "a.b.*"));
        assert!(!topic_matches("a.b.x", "a.b."));

        // Single dot — two empty segments
        assert!(!topic_matches(".", "*.*"));

        // Empty string
        assert!(!topic_matches("", ""));
        assert!(!topic_matches("", "a"));
        assert!(!topic_matches("a", ""));
    }

    #[test]
    fn has_valid_segments_accepts_valid() {
        assert!(has_valid_segments("a"));
        assert!(has_valid_segments("a.b"));
        assert!(has_valid_segments("a.b.c"));
        assert!(has_valid_segments("*"));
        assert!(has_valid_segments("a.*.b"));
    }

    #[test]
    fn has_valid_segments_rejects_invalid() {
        assert!(!has_valid_segments(""));
        assert!(!has_valid_segments("."));
        assert!(!has_valid_segments(".."));
        assert!(!has_valid_segments("a..b"));
        assert!(!has_valid_segments(".a"));
        assert!(!has_valid_segments("a."));
        assert!(!has_valid_segments(".a.b"));
        assert!(!has_valid_segments("a.b."));
        assert!(!has_valid_segments("a...b"));
    }
}
