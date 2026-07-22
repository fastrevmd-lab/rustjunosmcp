//! Post-process operational-command output: honor the `| match`, `| except`,
//! `| count`, and `| last N` pipe modifiers that rustez drops in NETCONF
//! translation (#105, #177), then apply optional size caps (#106). Pure — no I/O.

/// See module docs. Order: honor pipe modifiers → byte cap → line cap.
/// Returns `raw` unchanged when nothing applies.
pub fn process_output(
    command: &str,
    raw: String,
    max_lines: Option<u32>,
    max_bytes: Option<u32>,
    tail: bool,
) -> String {
    let piped = apply_pipe_modifiers(command, raw);
    let byte_capped = apply_byte_cap(piped, max_bytes);
    apply_line_cap(byte_capped, max_lines, tail)
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

/// Truncate to at most `max_bytes` on a UTF-8 char boundary, appending a marker.
fn apply_byte_cap(s: String, max_bytes: Option<u32>) -> String {
    let Some(cap) = max_bytes.map(|c| c as usize) else {
        return s;
    };
    if s.len() <= cap {
        return s;
    }
    let mut end = cap;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let omitted = s.len() - end;
    let mut out = s[..end].to_string();
    out.push_str(&format!("\n… (truncated, {omitted} bytes omitted)"));
    out
}

/// Keep the first `max_lines` lines (or the last N when `tail`), with a marker.
fn apply_line_cap(s: String, max_lines: Option<u32>, tail: bool) -> String {
    let Some(cap) = max_lines.map(|c| c as usize) else {
        return s;
    };
    let lines: Vec<&str> = s.lines().collect();
    if lines.len() <= cap {
        return s;
    }
    let more = lines.len() - cap;
    let kept: Vec<&str> = if tail {
        lines[lines.len() - cap..].to_vec()
    } else {
        lines[..cap].to_vec()
    };
    let mut out = kept.join("\n");
    out.push_str(&format!("\n… (truncated, {more} more lines)"));
    out
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

    #[test]
    fn max_lines_head_with_marker() {
        let raw = (1..=10)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let out = process_output("show x", raw, Some(5), none(), false);
        assert!(out.starts_with("1\n2\n3\n4\n5"), "got: {out}");
        assert!(out.contains("… (truncated, 5 more lines)"), "got: {out}");
    }

    #[test]
    fn max_lines_tail_keeps_last_n() {
        let raw = (1..=10)
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let out = process_output("show x", raw, Some(3), none(), true);
        let body: Vec<&str> = out.lines().filter(|l| !l.contains("truncated")).collect();
        assert_eq!(body, vec!["8", "9", "10"]);
    }

    #[test]
    fn max_bytes_cuts_on_char_boundary() {
        // Multibyte char (é = 2 bytes) straddling the cap must not split.
        let raw = "aéb".to_string(); // bytes: 'a'(1) 'é'(2) 'b'(1) = 4 bytes
        let out = process_output("show x", raw, none(), Some(2), false);
        // cap=2 lands mid-'é'; must back off to a boundary (keep just "a").
        assert!(out.starts_with('a'));
        assert!(
            !out.starts_with("aé"),
            "must not include a split char: {out}"
        );
        assert!(out.contains("bytes omitted"), "got: {out}");
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
        let body: Vec<&str> = out.lines().filter(|l| !l.contains("truncated")).collect();
        assert_eq!(body.len(), 5);
        // last 20 of 1..=30 = 11..=30; head 5 = 11,12,13,14,15
        assert_eq!(body, vec!["11", "12", "13", "14", "15"]);
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
