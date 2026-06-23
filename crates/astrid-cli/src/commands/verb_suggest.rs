//! Typo guard for the root capsule-verb shorthand (`astrid <verb>`).
//!
//! The root `Commands::External` catch-all turns an unrecognised first
//! token into a capsule-verb lookup. That intentionally disables clap's
//! built-in "did you mean ...?" engine for root tokens, so this module
//! restores it: before any daemon contact, an unrecognised token that is
//! a near-miss of a built-in subcommand is rejected with a suggestion,
//! exactly as clap did before the catch-all existed. A token that is not
//! a near-miss falls through to capsule-verb resolution.
//!
//! [`nearest_builtin`] is pure over `(token, builtin_names)` — no daemon,
//! no clap context — so it is unit-testable with a literal slice.

/// Closest built-in subcommand name to `token`, if one is "close enough"
/// to be a probable typo. Pure over `(token, builtin_names)` so it is
/// unit-testable without a daemon or clap context.
///
/// Returns `Some(builtin)` when the nearest built-in is within an edit
/// distance the user almost certainly meant (Levenshtein `≤ max(2,
/// len/3)`, length-scaled like clap's own heuristic). Returns `None` when
/// nothing is close, so the caller routes the token to capsule-verb
/// resolution.
///
/// The threshold deliberately errs toward routing to the daemon: a real
/// capsule verb that merely rhymes with a built-in must not be stolen by
/// the guard. An exact match can never reach here (clap consumes a
/// declared variant before the external-subcommand catch-all), so a
/// distance of zero is treated as "not a typo" and never suggested — that
/// would short-circuit a name clap already handled. Ties on edit distance
/// break alphabetically so script output is deterministic.
pub(crate) fn nearest_builtin<'a>(token: &str, builtin_names: &[&'a str]) -> Option<&'a str> {
    // An empty token is not a typo of any built-in — you cannot "mean" a
    // command by typing nothing. Clap never yields an empty external
    // vector, but guard it anyway so a degenerate input falls through to
    // capsule resolution (which prints its own "No capsule verb given")
    // rather than nonsensically suggesting a short built-in by edit
    // distance from "".
    if token.is_empty() {
        return None;
    }
    // The threshold scales with the typed token's length: short tokens
    // tolerate a couple of edits, longer ones up to a third of their
    // length. `max(2, len/3)` mirrors the generosity of clap's suggester
    // without pulling in its crate. Division is checked (the divisor is a
    // nonzero literal, so the fallback is unreachable) to satisfy the
    // workspace `arithmetic_side_effects` deny.
    let length_scaled = token.chars().count().checked_div(3).unwrap_or(0);
    let threshold = std::cmp::max(2, length_scaled);

    let mut best: Option<(usize, &'a str)> = None;
    for &name in builtin_names {
        let dist = levenshtein(token, name);
        // Distance 0 is an exact match. Clap would have consumed it before
        // the catch-all, so it cannot legitimately reach here; refuse to
        // "suggest" the name the user typed verbatim.
        if dist == 0 || dist > threshold {
            continue;
        }
        match best {
            // Strictly-smaller distance wins; on a tie, the
            // alphabetically-earlier name wins for determinism.
            Some((best_dist, best_name))
                if dist > best_dist || (dist == best_dist && name >= best_name) => {},
            _ => best = Some((dist, name)),
        }
    }
    best.map(|(_, name)| name)
}

/// Levenshtein edit distance between two strings, counting Unicode scalar
/// values (not bytes) so multi-byte verbs are measured by character.
///
/// Standard two-row dynamic program: O(a·b) time, O(b) space. Arithmetic
/// is saturating throughout — distances are bounded by short verb lengths,
/// so saturation is unreachable in practice and only satisfies the
/// workspace `arithmetic_side_effects` deny without changing the result.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    if a.is_empty() {
        return b.len();
    }
    if b.is_empty() {
        return a.len();
    }

    let width = b.len().saturating_add(1);
    // `prev[j]` = distance between a[..i] and b[..j]; rolled forward per row.
    let mut prev: Vec<usize> = (0..width).collect();
    let mut curr: Vec<usize> = vec![0; width];
    for (i, &ca) in a.iter().enumerate() {
        curr[0] = i.saturating_add(1);
        for (j, &cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            let deletion = curr[j].saturating_add(1);
            let insertion = prev[j.saturating_add(1)].saturating_add(1);
            let substitution = prev[j].saturating_add(cost);
            curr[j.saturating_add(1)] = deletion.min(insertion).min(substitution);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A representative slice of root built-ins. Kept literal (not derived
    /// from clap) so the pure function is tested in isolation, exactly as
    /// the dispatcher feeds it a `&[&str]` harvested once from
    /// `Cli::command()`.
    const BUILTINS: &[&str] = &[
        "chat",
        "run",
        "agent",
        "group",
        "caps",
        "quota",
        "invite",
        "keypair",
        "secret",
        "voucher",
        "trust",
        "audit",
        "budget",
        "session",
        "capsule",
        "mcp",
        "distro",
        "build",
        "init",
        "config",
        "wit",
        "gc",
        "start",
        "status",
        "stop",
        "restart",
        "logs",
        "ps",
        "top",
        "who",
        "doctor",
        "setup",
        "version",
        "completions",
        "update",
    ];

    #[test]
    fn nearest_builtin_flags_obvious_builtin_typo() {
        // A single-character slip off a built-in is a probable typo and
        // must surface the intended built-in rather than booting the daemon.
        assert_eq!(nearest_builtin("statuss", BUILTINS), Some("status"));
        assert_eq!(nearest_builtin("agnet", BUILTINS), Some("agent"));
    }

    #[test]
    fn nearest_builtin_passes_through_real_capsule_verb() {
        // Genuine capsule verbs that are not near-misses of any built-in
        // must return `None` so the dispatcher routes them to the daemon
        // instead of hijacking them with a bogus suggestion.
        assert_eq!(nearest_builtin("identity-export", BUILTINS), None);
        assert_eq!(nearest_builtin("models", BUILTINS), None);
    }

    #[test]
    fn nearest_builtin_exact_builtin_is_not_a_suggestion() {
        // An exact built-in is consumed by clap before the catch-all, so it
        // can never reach the guard; distance 0 must not be treated as a
        // typo (otherwise the guard would shadow a name clap already
        // dispatched).
        assert_eq!(nearest_builtin("status", BUILTINS), None);
    }

    #[test]
    fn nearest_builtin_empty_token_is_not_a_suggestion() {
        // A degenerate empty token must not be matched to a short built-in
        // by edit distance; it falls through to capsule resolution.
        assert_eq!(nearest_builtin("", BUILTINS), None);
    }

    #[test]
    fn nearest_builtin_is_deterministic_on_ties() {
        // A token equidistant from two built-ins must return the
        // alphabetically-first so script output is stable across runs. "ab"
        // is edit distance 1 from both "ac" (substitute b→c) and "bb"
        // (substitute a→b); both clear the threshold, so the
        // alphabetically-earlier "ac" must win regardless of slice order.
        let tie: &[&str] = &["bb", "ac"];
        assert_eq!(nearest_builtin("ab", tie), Some("ac"));
        // Reversing the slice must not change the winner.
        let tie_rev: &[&str] = &["ac", "bb"];
        assert_eq!(nearest_builtin("ab", tie_rev), Some("ac"));
    }
}
