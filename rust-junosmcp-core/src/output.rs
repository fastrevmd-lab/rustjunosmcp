//! Post-process operational-command output: honor the `| match`, `| except`,
//! `| count`, and `| last N` pipe modifiers that rustez drops in NETCONF
//! translation (#105, #177), then apply optional size caps (#106). Pure — no I/O.

/// See module docs. Order: honor pipe modifiers → line cap → byte cap.
/// Returns `raw` unchanged when nothing applies.
///
/// The byte cap runs **last** so it is the outermost bound. Applying it first
/// let the line cap append its own marker afterwards and push the result back
/// over `max_bytes` — with both caps set, the byte budget was not a budget.
/// Running it last can cost the line marker its tail, which is the right
/// trade: `max_bytes` is the limit a caller sizes a context window against.
pub fn process_output(
    command: &str,
    raw: String,
    max_lines: Option<u32>,
    max_bytes: Option<u32>,
    tail: bool,
) -> String {
    let piped = apply_pipe_modifiers(command, raw);
    let line_capped = apply_line_cap(piped, max_lines, tail);
    apply_byte_cap(line_capped, max_bytes, tail)
}

/// Apply the `| match`, `| except`, `| count`, and `| last N` modifiers rustez
/// drops. Splits on the Junos pipe boundary `" | "` (space-pipe-space) so a `|`
/// inside a `match`/`except` regex argument (`| match "up|count"`, `| match
/// up|count`) is NOT mistaken for a modifier. All filter modifiers are applied
/// server-side over the FULL pipe chain, left-to-right. Non-filter modifiers
/// (`display *`, `no-more`, `trim`, `hold`, unrecognized) are left untouched
/// (the device honors format modifiers; pager directives are irrelevant over
/// NETCONF). (#105, #177)
fn apply_pipe_modifiers(command: &str, raw: String) -> String {
    /// Quote-aware pipe splitter. Splits on " | " (space-pipe-space) ONLY when
    /// not inside single or double quotes. Returns trimmed segments.
    fn split_pipes(s: &str) -> Vec<String> {
        let mut segments = Vec::new();
        let mut current = String::new();
        let mut in_double = false;
        let mut in_single = false;
        let chars: Vec<char> = s.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let ch = chars[i];

            // Inside a quote, a backslash escapes the next char (including a
            // quote), so it cannot toggle quote state or be seen as a boundary.
            if (in_double || in_single) && ch == '\\' && i + 1 < chars.len() {
                current.push(ch);
                current.push(chars[i + 1]);
                i += 2;
                continue;
            }

            // Toggle quote state
            if ch == '"' && !in_single {
                in_double = !in_double;
                current.push(ch);
                i += 1;
            } else if ch == '\'' && !in_double {
                in_single = !in_single;
                current.push(ch);
                i += 1;
            } else if !in_double && !in_single && i + 2 < chars.len() {
                // Check for " | " boundary at quote-depth zero
                if ch == ' ' && chars[i + 1] == '|' && chars[i + 2] == ' ' {
                    segments.push(current.trim().to_string());
                    current.clear();
                    i += 3; // skip " | "
                } else {
                    current.push(ch);
                    i += 1;
                }
            } else {
                current.push(ch);
                i += 1;
            }
        }

        if !current.is_empty() {
            segments.push(current.trim().to_string());
        }

        segments
    }

    /// Strip one surrounding pair of double OR single quotes, if present.
    /// Guards against panic for one-char patterns like `"` or `'`.
    fn strip_quotes(s: &str) -> &str {
        let trimmed = s.trim();
        if trimmed.len() >= 2 {
            let first = trimmed.chars().next();
            let last = trimmed.chars().last();
            if first == last && (first == Some('"') || first == Some('\'')) {
                return &trimmed[1..trimmed.len() - 1];
            }
        }
        trimmed
    }

    /// Panic-free line filter: compiles regex or falls back to literal contains.
    enum LineFilter {
        Re(regex::Regex),
        Literal(String),
    }

    impl LineFilter {
        fn compile(pat: &str) -> Self {
            match regex::Regex::new(pat) {
                Ok(re) => LineFilter::Re(re),
                Err(_) => LineFilter::Literal(pat.to_string()),
            }
        }

        fn is_match(&self, line: &str) -> bool {
            match self {
                LineFilter::Re(re) => re.is_match(line),
                LineFilter::Literal(lit) => line.contains(lit.as_str()),
            }
        }
    }

    /// Extract first whitespace-delimited word and remainder (trimmed).
    fn split_first_word(s: &str) -> (String, String) {
        let trimmed = s.trim();
        if let Some(pos) = trimmed.find(|c: char| c.is_whitespace()) {
            let word = trimmed[..pos].to_string();
            let rest = trimmed[pos..].trim().to_string();
            (word, rest)
        } else {
            (trimmed.to_string(), String::new())
        }
    }

    let segments = split_pipes(command);
    if segments.len() < 2 {
        return raw; // no pipe modifiers (the command itself is segment 0)
    }
    let modifiers = &segments[1..];

    let mut out = raw;
    for seg in modifiers {
        let lower = seg.to_ascii_lowercase();
        let (first_word, remainder) = split_first_word(&lower);

        if first_word == "count" {
            // Count current lines (may already be filtered by prior match/except).
            let n = out.lines().count();
            out = format!("Count: {n} lines\n");
        } else if first_word == "last" {
            if let Ok(n) = remainder.trim().parse::<usize>() {
                let lines: Vec<&str> = out.lines().collect();
                let start = lines.len().saturating_sub(n);
                out = lines[start..].join("\n");
                if !out.is_empty() {
                    out.push('\n');
                }
            }
        } else if first_word == "match" {
            if remainder.is_empty() {
                // Bare `| match` with no pattern — malformed, leave out unchanged.
                continue;
            }
            // Extract pattern from the ORIGINAL seg (not lowercased) to preserve case.
            let (_, orig_pat_str) = split_first_word(seg);
            let pat = strip_quotes(&orig_pat_str);
            let filter = LineFilter::compile(pat);
            let matched: Vec<&str> = out.lines().filter(|line| filter.is_match(line)).collect();
            out = if matched.is_empty() {
                String::new()
            } else {
                matched.join("\n") + "\n"
            };
        } else if first_word == "except" {
            if remainder.is_empty() {
                // Bare `| except` with no pattern — malformed, leave out unchanged.
                continue;
            }
            // Extract pattern from the ORIGINAL seg (not lowercased) to preserve case.
            let (_, orig_pat_str) = split_first_word(seg);
            let pat = strip_quotes(&orig_pat_str);
            let filter = LineFilter::compile(pat);
            let kept: Vec<&str> = out.lines().filter(|line| !filter.is_match(line)).collect();
            out = if kept.is_empty() {
                String::new()
            } else {
                kept.join("\n") + "\n"
            };
        }
        // Anything else (display *, no-more, trim, hold, unrecognized) → leave out unchanged.
    }
    out
}

/// Truncate to at most `max_bytes` on a UTF-8 char boundary, with a marker.
///
/// The marker is counted against the budget, not added on top of it: `max_bytes`
/// is advertised as a hard cap, and a caller sizing a context window cannot use
/// a limit that is overshot by however long the marker happens to be. Requests
/// below `helpers::MIN_MAX_BYTES` are refused by the tools precisely so the
/// marker always fits.
///
/// `tail` selects which end survives. A caller who asked for the last N lines
/// wants the newest output, so trimming to fit the byte budget has to drop the
/// oldest bytes — cutting the prefix, not the suffix — and the marker moves to
/// the front to say so.
fn apply_byte_cap(s: String, max_bytes: Option<u32>, tail: bool) -> String {
    let Some(cap) = max_bytes.map(|c| c as usize) else {
        return s;
    };
    if s.len() <= cap {
        return s;
    }

    // The marker's length depends on the omitted count, which depends on where
    // the cut lands, which depends on the marker's length. Reserve the worst
    // case (everything omitted) so a single pass is always within budget.
    let reserved = byte_marker(s.len()).len() + 1; // + the separating newline
    let content_budget = cap.saturating_sub(reserved);

    // `content_budget < cap < s.len()`, so both cuts are in range.
    let out = if tail {
        let mut start = s.len() - content_budget;
        while !s.is_char_boundary(start) {
            start += 1;
        }
        format!("{}\n{}", byte_marker(start), &s[start..])
    } else {
        let mut end = content_budget;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}\n{}", &s[..end], byte_marker(s.len() - end))
    };

    debug_assert!(
        out.len() <= cap || cap < reserved,
        "byte cap overshot: {} > {cap}",
        out.len()
    );
    out
}

/// The byte-cap truncation marker, without its separating newline. Kept in one
/// place so its length can be reserved from the budget before the cut is made.
fn byte_marker(omitted: usize) -> String {
    format!("… (truncated, {omitted} bytes omitted)")
}

/// Keep the first `max_lines` lines (or the last N when `tail`), with a marker.
///
/// As with the byte cap, the marker line counts against `max_lines` rather than
/// being added beyond it, so a response never exceeds the line budget the caller
/// asked for. A cap of 1 therefore yields the marker alone.
///
/// Deliberately does not collect every line: this runs before the byte cap, so
/// on a large response the working set would otherwise scale with the device's
/// output rather than with the caller's budget. Counting is allocation-free and
/// the tail path keeps a ring bounded by the budget.
fn apply_line_cap(s: String, max_lines: Option<u32>, tail: bool) -> String {
    let Some(cap) = max_lines.map(|c| c as usize) else {
        return s;
    };
    let total = s.lines().count();
    if total <= cap {
        return s;
    }

    let content_budget = cap.saturating_sub(1); // one line for the marker
    let more = total - content_budget;
    let marker = format!("… (truncated, {more} more lines)");
    if content_budget == 0 {
        return marker;
    }

    let kept: Vec<&str> = if tail {
        let mut ring: std::collections::VecDeque<&str> =
            std::collections::VecDeque::with_capacity(content_budget);
        for line in s.lines() {
            if ring.len() == content_budget {
                ring.pop_front();
            }
            ring.push_back(line);
        }
        ring.into_iter().collect()
    } else {
        s.lines().take(content_budget).collect()
    };

    // In tail mode the omitted lines are the *older* ones, so the marker belongs
    // above what survives. That is how a reader expects elided output to read,
    // and it is load-bearing: the byte cap runs afterwards and preserves the
    // suffix in tail mode, so a marker at the end would be what survives while
    // the newest lines — the ones `tail` was asked for — got cut.
    let body = kept.join("\n");
    if tail {
        format!("{marker}\n{body}")
    } else {
        format!("{body}\n{marker}")
    }
}

#[cfg(test)]
mod tests {
    use super::process_output;

    fn none() -> Option<u32> {
        None
    }

    #[test]
    fn passthrough_when_all_off() {
        let raw = "line1\nline2\nline3".to_string();
        assert_eq!(
            process_output("show foo", raw.clone(), none(), none(), false),
            raw
        );
    }

    #[test]
    fn count_pipe_reports_line_count() {
        let raw = "a\nb\nc\n".to_string();
        assert_eq!(
            process_output("show x | count", raw, none(), none(), false),
            "Count: 3 lines\n"
        );
    }

    #[test]
    fn count_pipe_on_empty_is_zero() {
        assert_eq!(
            process_output("show x | count", String::new(), none(), none(), false),
            "Count: 0 lines\n"
        );
    }

    #[test]
    fn last_pipe_keeps_last_n_lines() {
        let raw = (1..=25)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let out = process_output("show x | last 10", raw, none(), none(), false);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 10);
        assert_eq!(lines.first().copied(), Some("16"));
        assert_eq!(lines.last().copied(), Some("25"));
    }

    #[test]
    fn last_pipe_unparseable_n_is_ignored() {
        let raw = "a\nb".to_string();
        assert_eq!(
            process_output("show x | last", raw.clone(), none(), none(), false),
            raw
        );
    }

    /// The marker line counts against `max_lines`: a cap of 5 yields 4 content
    /// lines plus the marker, for 5 lines total. Previously it yielded 6, so a
    /// caller sizing a budget got one line more than it asked for.
    #[test]
    fn max_lines_head_with_marker() {
        let raw = (1..=10)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let out = process_output("show x", raw, Some(5), none(), false);
        assert_eq!(out.lines().count(), 5, "cap must include the marker: {out}");
        assert!(out.starts_with("1\n2\n3\n4"), "got: {out}");
        assert!(out.contains("… (truncated, 6 more lines)"), "got: {out}");
    }

    #[test]
    fn max_lines_tail_keeps_last_n() {
        let raw = (1..=10)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let out = process_output("show x", raw, Some(3), none(), true);
        assert_eq!(out.lines().count(), 3, "cap must include the marker: {out}");
        let body: Vec<&str> = out.lines().filter(|l| !l.contains("truncated")).collect();
        assert_eq!(body, vec!["9", "10"]);
    }

    /// The property that matters, over a range of caps and inputs: the response
    /// never exceeds what the caller asked for.
    #[test]
    fn caps_are_never_exceeded() {
        let raw = (1..=200)
            .map(|n| format!("line {n} with some padding"))
            .collect::<Vec<_>>()
            .join("\n");

        for cap in [1_u32, 2, 3, 17, 199, 200, 201] {
            for tail in [false, true] {
                let out = process_output("show x", raw.clone(), Some(cap), none(), tail);
                assert!(
                    out.lines().count() <= cap as usize,
                    "max_lines={cap} tail={tail} produced {} lines",
                    out.lines().count()
                );
            }
        }

        for cap in [64_u32, 65, 100, 1000, 5000, 100_000] {
            let out = process_output("show x", raw.clone(), none(), Some(cap), false);
            assert!(
                out.len() <= cap as usize,
                "max_bytes={cap} produced {} bytes",
                out.len()
            );
        }
    }

    /// The cut must land on a char boundary. `MIN_MAX_BYTES` is the smallest
    /// cap a tool accepts, so the budget is sized just past the marker to leave
    /// a content allowance that straddles a multibyte char.
    #[test]
    fn max_bytes_cuts_on_char_boundary() {
        // 65 ASCII bytes, then a two-byte 'é' occupying bytes 65..67, then
        // enough trailing bytes that the cap actually bites.
        let raw = format!("{}é{}", "x".repeat(65), "y".repeat(256));
        // The implementation reserves the worst-case marker (everything
        // omitted) from the budget, so mirror that to land the cut at byte 66 —
        // one byte into 'é'.
        let cap = super::byte_marker(raw.len()).len() + 1 + 66;
        let out = process_output("show x", raw, none(), Some(cap as u32), false);

        assert!(
            out.is_char_boundary(out.len()),
            "output must be valid UTF-8"
        );
        assert!(
            !out.contains('é'),
            "must back off rather than include a split char: {out}"
        );
        assert!(out.contains("bytes omitted"), "got: {out}");
        assert!(out.len() <= cap, "cap must include the marker: {out}");
    }

    #[test]
    fn max_bytes_passthrough_when_under_cap() {
        let raw = "short".to_string();
        assert_eq!(
            process_output("show x", raw.clone(), none(), Some(1000), false),
            raw
        );
    }

    #[test]
    fn pipe_then_cap_interaction() {
        // `| last 20` keeps 20; then max_lines=5 head caps to 5 with marker.
        let raw = (1..=30)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let out = process_output("show x | last 20", raw, Some(5), none(), false);
        assert_eq!(out.lines().count(), 5, "cap must include the marker: {out}");
        let body: Vec<&str> = out.lines().filter(|l| !l.contains("truncated")).collect();
        // last 20 of 1..=30 = 11..=30; head 4 (the 5th line is the marker).
        assert_eq!(body, vec!["11", "12", "13", "14"]);
    }

    // NEW tests proving the fix for #177 — match/except server-side filtering

    #[test]
    fn match_filters_lines_server_side() {
        let raw = "ge-0/0/0\nlo0\nlo0.0\nfxp0".to_string();
        let out = process_output("show x | match lo0", raw, none(), none(), false);
        assert_eq!(out, "lo0\nlo0.0\n");
    }

    #[test]
    fn except_filters_lines_server_side() {
        let raw = "ge-0/0/0\nfxp0\nlo0".to_string();
        let out = process_output("show x | except fxp", raw, none(), none(), false);
        assert_eq!(out, "ge-0/0/0\nlo0\n");
    }

    #[test]
    fn match_anchored_regex() {
        let raw =
            "set system host-name a\nset interfaces ge-0/0/0\nset system services".to_string();
        let out = process_output(
            "show config | display set | match \"^set system\"",
            raw,
            none(),
            none(),
            false,
        );
        assert_eq!(out, "set system host-name a\nset system services\n");
    }

    #[test]
    fn match_alternation() {
        let raw = "ok line\nerr here\nwarn there\nfine".to_string();
        let out = process_output("show log | match \"err|warn\"", raw, none(), none(), false);
        assert_eq!(out, "err here\nwarn there\n");
    }

    #[test]
    fn match_then_count() {
        let raw = "ge0\nlo0\nlo1\nfxp0".to_string();
        let out = process_output("show x | match lo | count", raw, none(), none(), false);
        assert_eq!(out, "Count: 2 lines\n");
    }

    #[test]
    fn except_then_last() {
        let raw = "foo1\nbar1\nfoo2\nbar2\nfoo3\nbar3".to_string();
        let out = process_output("show x | except foo | last 2", raw, none(), none(), false);
        assert_eq!(out, "bar2\nbar3\n");
    }

    #[test]
    fn match_invalid_regex_falls_back_to_literal() {
        let raw = "a(b\ncd\ne(f".to_string();
        let out = process_output("show x | match \"(\"", raw, none(), none(), false);
        assert_eq!(out, "a(b\ne(f\n");
    }

    #[test]
    fn match_quoted_pattern_strips_quotes() {
        let raw = "host name\nhostname\nhost-name".to_string();
        let out = process_output("show x | match \"host name\"", raw, none(), none(), false);
        assert_eq!(out, "host name\n");
    }

    // UPDATED tests — correcting the assumption that device already applied match/except

    #[test]
    fn quoted_match_alternation_not_mistaken_for_count() {
        // Interior `count` in `match "err|count|warn"` is NOT a count modifier.
        // Now filters: raw has no err/count/warn → empty result (not "Count: 3 lines\n").
        let raw = "l1\nl2\nl3".to_string();
        assert_eq!(
            process_output(
                "show log | match \"err|count|warn\"",
                raw,
                None,
                None,
                false
            ),
            ""
        );
    }

    #[test]
    fn unquoted_match_alternation_ending_in_count_not_honored() {
        // `match up|count` on raw with no "up" or "count" → empty (not Count line).
        let raw = "l1\nl2\nl3".to_string();
        assert_eq!(
            process_output("show int | match up|count", raw, None, None, false),
            ""
        );
    }

    #[test]
    fn interior_last_in_regex_ignored() {
        // `match "a|last5|b"` on raw with no a/last5/b → empty (proves interior last5 isn't a modifier).
        let raw = "l1\nl2\nl3\nl4\nl5".to_string();
        assert_eq!(
            process_output("show x | match \"a|last5|b\"", raw, None, None, false),
            ""
        );
    }

    #[test]
    fn trailing_last_after_match_still_honored() {
        // Match filters first, then `last 2` on the filtered set.
        let raw = "up1\ndown\nup2\nup3\ndown2".to_string();
        let out = process_output("show x | match up | last 2", raw, None, None, false);
        assert_eq!(out.lines().collect::<Vec<_>>(), vec!["up2", "up3"]);
    }

    #[test]
    fn last_pipe_after_match_applies_to_already_filtered_text() {
        // All lines contain 'm', so match keeps all; last 2 → m3, m4.
        let raw = "m1\nm2\nm3\nm4".to_string();
        let out = process_output("show x | match m | last 2", raw, none(), none(), false);
        assert_eq!(out.lines().collect::<Vec<_>>(), vec!["m3", "m4"]);
    }

    // Code review fixes — quote-aware splitting, panic-free fallback, bare keywords

    #[test]
    fn quoted_spaced_alternation_not_split() {
        // Pattern contains " | " (space-pipe-space) inside quotes → must NOT split.
        let raw = "aaa\nbbb".to_string();
        let out = process_output(r#"show x | match "foo | count""#, raw, None, None, false);
        // No line contains "foo " or " count" → empty, NOT a Count line.
        assert_eq!(out, "");
    }

    #[test]
    fn escaped_quote_inside_quotes_does_not_split_boundary() {
        // A backslash-escaped quote must not close the quote state, so the
        // interior " | " stays part of the pattern and is not split off (which
        // would misparse `count` as a modifier — a #177 false negative).
        let raw = "aaa\nbbb".to_string();
        let out = process_output(r#"show x | match "foo\" | count""#, raw, None, None, false);
        // Pattern is the literal-ish `foo\" | count`; no line matches → empty,
        // and crucially NOT a "Count:" line.
        assert_eq!(out, "");
        assert!(!out.starts_with("Count:"));
    }

    #[test]
    fn quoted_spaced_alternation_matches_correctly() {
        // Pattern `foo | count` inside quotes alternates "foo " or " count".
        let raw = "aaa\nfoo | count here\nbbb".to_string();
        let out = process_output(r#"show x | match "foo | count""#, raw, None, None, false);
        assert_eq!(out, "foo | count here\n");
    }

    #[test]
    fn lone_quote_pattern_does_not_panic() {
        // Pattern that is a single quote character, properly quoted: match '"'
        // Tests that strip_quotes doesn't panic on a 3-char string (quote, char, quote).
        // Also test a single-quote inside doubles.
        let raw = r#"line with "
line without"#
            .to_string();
        let out = process_output(r#"show x | match '"'"#, raw, None, None, false);
        // Pattern is `"` after stripping outer single quotes.
        assert_eq!(out, "line with \"\n");
    }

    #[test]
    fn match_tab_separated_works() {
        // `match\tlo` (TAB separator) should be recognized.
        let raw = "ge-0/0/0\nlo0\nfxp0".to_string();
        let out = process_output("show x | match\tlo", raw, None, None, false);
        assert_eq!(out, "lo0\n");
    }

    #[test]
    fn bare_match_keyword_is_noop_no_panic() {
        // Bare `| match` with no pattern → malformed, leave output unchanged.
        let raw = "a\nb\nc".to_string();
        let out = process_output("show x | match", raw.clone(), None, None, false);
        assert_eq!(out, raw);
    }

    #[test]
    fn bare_except_keyword_is_noop_no_panic() {
        // Bare `| except` with no pattern → malformed, leave output unchanged.
        let raw = "a\nb\nc".to_string();
        let out = process_output("show x | except", raw.clone(), None, None, false);
        assert_eq!(out, raw);
    }

    #[test]
    fn match_is_case_sensitive() {
        // `match Lo0` does NOT match line `lo0` (Junos is case-sensitive).
        let raw = "lo0\nLo0".to_string();
        let out = process_output("show x | match Lo0", raw, None, None, false);
        assert_eq!(out, "Lo0\n");
    }

    #[test]
    fn match_is_unanchored() {
        // `match 0/0` matches mid-line occurrence like `ge-0/0/0 up`.
        let raw = "ge-0/0/0 up\nge-0/0/1 down".to_string();
        let out = process_output("show x | match 0/0", raw, None, None, false);
        assert_eq!(out, "ge-0/0/0 up\nge-0/0/1 down\n");
    }
}

#[cfg(test)]
mod combined_cap_tests {
    use super::process_output;

    /// Regression: with both caps set, the byte cap ran first and the line cap
    /// then appended its marker on top, pushing the result back over the byte
    /// budget. The byte cap is the outermost bound and must be applied last.
    #[test]
    fn both_caps_together_respect_the_byte_budget() {
        let raw = "x\n".repeat(32);
        let out = process_output("show x", raw, Some(31), Some(64), false);
        assert!(
            out.len() <= 64,
            "byte cap must survive line capping: {} bytes — {out:?}",
            out.len()
        );
        assert!(out.lines().count() <= 31, "line cap must hold too: {out:?}");
    }

    #[test]
    fn both_caps_hold_across_a_range_of_budgets() {
        let raw = (1..=400)
            .map(|n| format!("line {n} padded out a little"))
            .collect::<Vec<_>>()
            .join("\n");

        for lines in [1_u32, 5, 50, 399, 400, 401] {
            for bytes in [64_u32, 100, 1000, 20_000] {
                for tail in [false, true] {
                    let out = process_output("show x", raw.clone(), Some(lines), Some(bytes), tail);
                    assert!(
                        out.len() <= bytes as usize,
                        "max_bytes={bytes} max_lines={lines} tail={tail}: {} bytes",
                        out.len()
                    );
                    assert!(
                        out.lines().count() <= lines as usize,
                        "max_bytes={bytes} max_lines={lines} tail={tail}: {} lines",
                        out.lines().count()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tail_cap_tests {
    use super::process_output;

    /// Regression: with both caps tight and `tail` set, the byte cap trimmed
    /// from the front of the string — discarding exactly the newest lines the
    /// caller asked for and keeping the oldest. `tail` means "the end of the
    /// output"; every cap has to agree on which end that is.
    #[test]
    fn tail_keeps_the_newest_lines_when_the_byte_cap_also_bites() {
        let raw = (1..=20)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let out = process_output("show x", raw, Some(19), Some(64), true);

        assert!(out.len() <= 64, "byte cap: {} bytes — {out:?}", out.len());
        assert!(
            out.contains("line 20"),
            "the newest line must survive: {out:?}"
        );
        assert!(
            !out.contains("line 1\n"),
            "the oldest lines are what should be dropped: {out:?}"
        );
    }

    /// The line cap runs before the byte cap, so it must not build a working set
    /// proportional to the device's output. This does not measure allocation —
    /// it pins the behaviour that lets the implementation stay bounded: a tail
    /// request only ever needs the last `max_lines` lines.
    #[test]
    fn a_tail_cap_over_a_large_response_returns_only_the_budget() {
        let raw = (1..=100_000)
            .map(|n| format!("line {n}"))
            .collect::<Vec<_>>()
            .join("\n");
        let out = process_output("show x", raw, Some(5), None, true);

        assert_eq!(out.lines().count(), 5);
        assert!(out.contains("line 100000"), "got: {out:?}");
    }
}
