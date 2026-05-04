//! Char-boundary-safe string utilities.
//!
//! # Why this exists
//!
//! Wave 1 (2026-05-04 ultrareview): the agent had at least eight call
//! sites that wrote `&s[..N]` against attacker-controlled input
//! (HTTP request paths, SSH usernames, shell commands fed to AI
//! triage prompts, Telegram message previews, agent-guard alerts,
//! kill-chain skill stdout, knowledge-graph edge summaries). Each
//! one panicked when `N` fell inside a UTF-8 multi-byte character
//! (e.g. `é`, `€`, emoji), turning a single attacker-supplied byte
//! into a process-killing DoS.
//!
//! Rust's `String::truncate(n)` does the right thing on owned
//! strings, and `str::is_char_boundary(n)` is the kernel of the
//! safe slice. The pattern that previously lived inline in
//! `crate::ai::local_classifier::truncate` is generalised here so
//! every fix routes through one tested helper. Anti-regression
//! anchors live in this module's `tests` block.

/// Return the longest prefix of `s` whose byte length is `<= max` and
/// that ends on a UTF-8 character boundary.
///
/// Never panics, never allocates. When `max` is 0, returns the empty
/// string. When `max >= s.len()`, returns `s` unchanged. Otherwise
/// walks back from `max` until `is_char_boundary` returns true,
/// guaranteeing the returned slice is a valid `&str`.
///
/// # Examples
///
/// ```ignore
/// use innerwarden_agent::text_util::safe_truncate;
/// // Plain ASCII: byte index works as char index.
/// assert_eq!(safe_truncate("hello world", 5), "hello");
/// // Multi-byte: walks back to the boundary BEFORE the split char.
/// // `é` is two bytes (0xC3 0xA9), so `&s[..3]` would split it and
/// // panic; safe_truncate returns the slice up to byte 2 ("café"
/// // truncated to "caf").
/// assert_eq!(safe_truncate("café", 3), "caf");
/// // Same string, max big enough for the whole word.
/// assert_eq!(safe_truncate("café", 5), "café");
/// // max == 0 returns "".
/// assert_eq!(safe_truncate("café", 0), "");
/// ```
pub fn safe_truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wave 1 anchors (AUDIT-WAVE1-UTF8) ─────────────────────────────
    //
    // The 2026-05-04 ultrareview surfaced eight `&s[..N]` panic sites
    // across the agent. All now route through `safe_truncate`. These
    // tests pin the contract that protects every caller.

    #[test]
    fn ascii_under_max_returns_input_unchanged() {
        // No allocation, no copy, just the same `&str`.
        let s = "hello";
        let out = safe_truncate(s, 100);
        assert_eq!(out, "hello");
        // Identity: same slice, same pointer.
        assert!(std::ptr::eq(s.as_ptr(), out.as_ptr()));
    }

    #[test]
    fn ascii_over_max_truncates_to_max_bytes() {
        assert_eq!(safe_truncate("hello world", 5), "hello");
        assert_eq!(safe_truncate("hello world", 0), "");
        assert_eq!(safe_truncate("hello world", 1), "h");
    }

    #[test]
    fn multibyte_split_at_char_boundary_does_not_panic() {
        // `é` is U+00E9, two bytes in UTF-8 (0xC3 0xA9). If `max`
        // lands on byte 1 of the codepoint, the naive `&s[..max]`
        // panics with "byte index N is not a char boundary". The
        // safe walker returns the slice ending at byte 0 ("").
        let s = "é"; // 2 bytes
        assert_eq!(s.len(), 2);
        assert_eq!(safe_truncate(s, 1), "");
        assert_eq!(safe_truncate(s, 2), "é");
        assert_eq!(safe_truncate(s, 5), "é");
    }

    #[test]
    fn three_byte_codepoint_splits_walk_back_correctly() {
        // `€` is U+20AC, three bytes (0xE2 0x82 0xAC). For max in
        // {1, 2} we walk back to byte 0; for max == 3 we keep it.
        let s = "€"; // 3 bytes
        assert_eq!(s.len(), 3);
        assert_eq!(safe_truncate(s, 1), "");
        assert_eq!(safe_truncate(s, 2), "");
        assert_eq!(safe_truncate(s, 3), "€");
    }

    #[test]
    fn four_byte_codepoint_emoji_splits_walk_back_correctly() {
        // 🦀 (U+1F980) is four bytes. The exact shape an attacker
        // would use to DoS a `&s[..200]` call site if the input is
        // 51 emoji long (51 * 4 = 204 bytes; truncate at 200 lands
        // mid-codepoint of the 51st emoji).
        let s = "🦀"; // 4 bytes
        assert_eq!(s.len(), 4);
        for max in 1..=3 {
            assert_eq!(safe_truncate(s, max), "");
        }
        assert_eq!(safe_truncate(s, 4), "🦀");
    }

    #[test]
    fn long_attacker_string_with_max_inside_multibyte_does_not_panic() {
        // Realistic shape: an HTTP path made entirely of `€` (3 bytes
        // each). For `max == 200`, the naive slice lands at byte 200
        // which is the SECOND byte of the 67th codepoint (66 * 3 =
        // 198, so byte 200 is byte 2 of codepoint #67). The walker
        // must return 198 bytes (the whole 66 codepoints).
        let s = "€".repeat(100); // 300 bytes, 100 codepoints
        let out = safe_truncate(&s, 200);
        assert_eq!(out.len(), 198);
        // Whatever it returned must be valid UTF-8 (Rust's slice
        // guarantees this, but pin the assertion so a future
        // refactor that returns a raw byte view fails the test).
        let _ = out.chars().count();
    }

    #[test]
    fn max_zero_returns_empty_string() {
        assert_eq!(safe_truncate("anything", 0), "");
        assert_eq!(safe_truncate("café", 0), "");
        assert_eq!(safe_truncate("", 0), "");
    }

    #[test]
    fn empty_input_with_any_max_returns_empty_string() {
        assert_eq!(safe_truncate("", 0), "");
        assert_eq!(safe_truncate("", 100), "");
    }

    #[test]
    fn mixed_ascii_and_multibyte_truncates_at_the_first_unsplittable_boundary() {
        // "abc€def" = a b c [E2 82 AC] d e f = 9 bytes.
        // max=3 -> "abc" (boundary).
        // max=4 -> walks back to 3 -> "abc" (byte 4 is mid-€).
        // max=5 -> walks back to 3 -> "abc".
        // max=6 -> "abc€" (byte 6 IS a boundary).
        // max=7 -> "abc€d".
        let s = "abc€def";
        assert_eq!(s.len(), 9);
        assert_eq!(safe_truncate(s, 3), "abc");
        assert_eq!(safe_truncate(s, 4), "abc");
        assert_eq!(safe_truncate(s, 5), "abc");
        assert_eq!(safe_truncate(s, 6), "abc€");
        assert_eq!(safe_truncate(s, 7), "abc€d");
    }
}
