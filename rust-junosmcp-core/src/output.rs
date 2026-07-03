//! Post-process operational-command output: honor the trailing `| count` /
//! `| last N` pipe modifiers that rustez drops in NETCONF translation (#105),
//! then apply optional size caps (#106). Pure — no I/O.

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

/// Apply the trailing `| count` / `| last N` modifiers rustez drops. Other
/// modifiers (`match`, `except`, …) were already applied upstream, so they are
/// skipped here. Modifiers are applied left-to-right.
fn apply_pipe_modifiers(command: &str, raw: String) -> String {
    let mut segments = command.split('|');
    let _base = segments.next(); // the command itself
    let mut out = raw;
    for seg in segments {
        let seg = seg.trim();
        let lower = seg.to_ascii_lowercase();
        if lower == "count" {
            let n = out.lines().count();
            out = format!("Count: {n} lines\n");
        } else if let Some(rest) = lower.strip_prefix("last") {
            if let Ok(n) = rest.trim().parse::<usize>() {
                let lines: Vec<&str> = out.lines().collect();
                let start = lines.len().saturating_sub(n);
                out = lines[start..].join("\n");
                if !out.is_empty() {
                    out.push('\n');
                }
            }
            // unparseable N → leave `out` unchanged
        }
        // any other modifier: already applied by rustez → skip
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
    fn last_pipe_after_match_applies_to_already_filtered_text() {
        // rustez already applied `| match`; raw is the matched text. We only apply `last`.
        let raw = "m1\nm2\nm3\nm4".to_string();
        let out = process_output("show x | match m | last 2", raw, none(), none(), false);
        assert_eq!(out.lines().collect::<Vec<_>>(), vec!["m3", "m4"]);
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
}
