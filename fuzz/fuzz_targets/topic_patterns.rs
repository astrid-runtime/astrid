#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use astrid_events::{TopicMatcher, topic_pattern_matches};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    pattern: String,
    topic: String,
    literal_segments: Vec<String>,
}

fuzz_target!(|data: &[u8]| {
    let mut data = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut data) else {
        return;
    };

    let matched = topic_pattern_matches(&input.pattern, &input.topic);
    assert_eq!(
        matched,
        TopicMatcher::new(input.pattern.clone()).matches_topic(&input.topic)
    );

    if topic_depth(&input.topic) > TopicMatcher::MAX_TOPIC_DEPTH {
        assert!(!matched);
    }

    if !input.pattern.contains('*')
        && input.pattern == input.topic
        && topic_depth(&input.topic) <= TopicMatcher::MAX_TOPIC_DEPTH
    {
        assert!(matched);
    }

    let segments: Vec<String> = input
        .literal_segments
        .into_iter()
        .filter(|s| is_literal_segment(s))
        .take(8)
        .collect();
    if !segments.is_empty() {
        let prefix = segments.join(".");
        let subtree_pattern = format!("{prefix}.*");
        assert!(!topic_pattern_matches(&subtree_pattern, &prefix));
        assert!(topic_pattern_matches(
            &subtree_pattern,
            &format!("{prefix}.child")
        ));
        assert!(topic_pattern_matches(
            &subtree_pattern,
            &format!("{prefix}.child.grandchild")
        ));

        if segments.len() >= 2 {
            let mut mid = segments.clone();
            mid[1] = "*".to_string();
            let mid_pattern = mid.join(".");
            let same_depth = segments.join(".");
            assert!(topic_pattern_matches(&mid_pattern, &same_depth));
            assert!(!topic_pattern_matches(
                &mid_pattern,
                &format!("{same_depth}.extra")
            ));
        }
    }
});

fn topic_depth(topic: &str) -> usize {
    topic.split('.').count()
}

fn is_literal_segment(segment: &str) -> bool {
    !segment.is_empty() && !segment.contains('.') && !segment.contains('*')
}
