//! Crash-selector matching shared by host tests and the standalone guest.

pub const SELECTOR_PREFIX: &[u8] = b"frame:";

/// Matches one ASCII decimal selector in a zero-padded ``fw_cfg`` field.
pub fn selector_matches(selector: &[u8], frame_index: usize) -> bool {
    let Some(digits) = selector.strip_prefix(SELECTOR_PREFIX) else {
        return false;
    };
    let digit_count = digits
        .iter()
        .position(|byte| !byte.is_ascii_digit())
        .unwrap_or(digits.len());
    let Some(delimiter) = digits.get(digit_count) else {
        return false;
    };
    if digit_count == 0
        || *delimiter != 0
        || digits[digit_count + 1..].iter().any(|byte| *byte != 0)
    {
        return false;
    }

    let Ok(expected) = u64::try_from(frame_index) else {
        return false;
    };
    parse_u64(&digits[..digit_count]) == Some(expected)
}

fn parse_u64(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0u64, |value, &byte| {
        let digit = byte.wrapping_sub(b'0');
        if digit > 9 {
            return None;
        }
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(digit)))
    })
}

#[cfg(test)]
mod tests {
    use super::selector_matches;

    #[test]
    fn matches_both_frame_selector_arms_before_flush() {
        assert!(selector_matches(b"frame:0\0", 0));
        assert!(selector_matches(b"frame:8\0", 8));
        assert!(!selector_matches(b"frame:0\0", 1));
        assert!(!selector_matches(b"frame:8\0", 7));
    }

    #[test]
    fn rejects_empty_malformed_and_overflowing_selectors_fail_closed() {
        for (selector, expected) in [
            (&b"before-commit"[..], false),
            (&b"commit-flush-begin"[..], false),
            (&b"frame:"[..], false),
            (&b"frame:+8"[..], false),
            (&b"frame:x"[..], false),
            (&b"frame:8\0noise"[..], false),
            (&b"frame:18446744073709551616"[..], false),
        ] {
            assert_eq!(selector_matches(selector, 8), expected);
        }
    }
}
