use super::markdown_to_spans;
use crate::tui::theme::Theme;

#[test]
fn markdown_numbered_list_styles_single_and_multi_digit_markers() {
    let theme = Theme::default();

    for (line, expected_marker, expected_text) in [
        ("1. first", "1. ", "first"),
        ("9. ninth", "9. ", "ninth"),
        ("10. tenth", "10. ", "tenth"),
        ("  123. last", "  123. ", "last"),
    ] {
        let spans = markdown_to_spans(line, &theme);

        assert_eq!(spans.len(), 2, "unexpected spans for {line:?}");
        assert_eq!(spans[0].content.as_ref(), expected_marker);
        assert_eq!(spans[0].style.fg, Some(theme.tool));
        assert_eq!(spans[1].content.as_ref(), expected_text);
        assert_eq!(spans[1].style.fg, Some(theme.assistant));
    }
}
