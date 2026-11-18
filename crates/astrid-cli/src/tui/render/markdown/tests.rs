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
        ("0. zero", "0. ", "zero"),
        ("10. ", "10. ", ""),
        (
            "123456789012345678901234567890. long",
            "123456789012345678901234567890. ",
            "long",
        ),
        ("01. padded", "01. ", "padded"),
        ("\t10. tabbed", "\t10. ", "tabbed"),
        (
            "\u{2003}10. unicode indent",
            "\u{2003}10. ",
            "unicode indent",
        ),
    ] {
        let spans = markdown_to_spans(line, &theme);

        assert_eq!(spans.len(), 2, "unexpected spans for {line:?}");
        assert_eq!(spans[0].content.as_ref(), expected_marker);
        assert_eq!(spans[0].style.fg, Some(theme.tool));
        assert_eq!(spans[1].content.as_ref(), expected_text);
        assert_eq!(spans[1].style.fg, Some(theme.assistant));
    }
}

#[test]
fn malformed_numbered_markers_stay_plain_text() {
    let theme = Theme::default();
    for line in [
        "",
        ". text",
        "10.text",
        "10.\ttext",
        "-10. text",
        "١٠. text",
        "1é. text",
        "123",
    ] {
        let spans = markdown_to_spans(line, &theme);
        assert_eq!(spans.len(), 1, "unexpected spans for {line:?}");
        assert_eq!(spans[0].content.as_ref(), line);
        assert_eq!(spans[0].style.fg, Some(theme.assistant));
    }
}

#[test]
fn numbered_list_body_keeps_inline_formatting() {
    use ratatui::style::Modifier;

    let theme = Theme::default();
    let spans = markdown_to_spans("10. **bold** and `code`", &theme);
    assert_eq!(spans.len(), 4);
    assert_eq!(spans[0].content.as_ref(), "10. ");
    assert_eq!(spans[0].style.fg, Some(theme.tool));
    assert_eq!(spans[1].content.as_ref(), "bold");
    assert!(spans[1].style.add_modifier.contains(Modifier::BOLD));
    assert_eq!(spans[1].style.fg, Some(theme.assistant));
    assert_eq!(spans[2].content.as_ref(), " and ");
    assert_eq!(spans[3].content.as_ref(), "code");
    assert_eq!(spans[3].style.fg, Some(theme.tool));
}
