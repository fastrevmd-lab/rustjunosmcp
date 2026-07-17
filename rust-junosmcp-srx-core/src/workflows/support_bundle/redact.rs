//! Redaction rules applied when `redact=true` (default) on
//! `collect_jtac_support_bundle`. Strips known-sensitive elements from
//! captured `get-configuration` and per-RPC XML payloads before they're
//! written into the on-device tarball.
//!
//! Locked rule list (Phase 3 design doc § "Redact rules"):
//! * `pre-shared-key` — IKE PSKs (`security ike policy ... pre-shared-key`)
//! * `secret` / `simple-password` / `encrypted-password` — local-user,
//!   RADIUS, TACACS, snmp-v3, IPsec-mfg secrets
//! * `community` under `snmp` — SNMP v1/v2c community strings
//! * `radius-server` `secret` — RADIUS shared-secret
//! * `tacplus-server` `secret` — TACACS+ shared-secret
//! * `hmac-key` — routing-options authentication-key HMAC
//!
//! XML payloads are redacted by element name — every matching element has
//! its text content replaced with `<REDACTED>` while preserving the XML
//! structure so JTAC can still see *where* a secret was configured
//! ([`redact_xml`]).
//!
//! Non-XML artefacts (the `/var/log/*` files archived since #82) are redacted
//! by a conservative line-oriented pass ([`redact_log_text`]) that scrubs the
//! same key set from config-style log syntax. [`redact_log_artefact`] routes
//! each artefact to the right pass based on XML well-formedness (#89).

/// Element names whose text content is replaced with `<REDACTED>`.
/// Matching is exact on the local element name (namespace-stripped).
pub const REDACT_ELEMENT_NAMES: &[&str] = &[
    "pre-shared-key",
    "secret",
    "simple-password",
    "encrypted-password",
    "community",
    "hmac-key",
];

/// Replacement string used in redacted element text.
pub const REDACTED_MARKER: &str = "<REDACTED>";

/// Redact known-sensitive element text content from an XML payload.
/// Returns the redacted XML string. If the input cannot be parsed,
/// returns the input unchanged (callers should treat parse failures as
/// non-fatal and log them).
pub fn redact_xml(input: &str) -> String {
    use quick_xml::events::{BytesText, Event};
    use quick_xml::reader::Reader;
    use quick_xml::writer::Writer;

    // Gate on well-formedness first: quick-xml's streaming reader is lenient
    // (it silently tolerates unclosed tags), so use roxmltree as a strict
    // parse check. Real `get-configuration` replies carry undeclared `junos:`
    // attribute prefixes (`junos:changed-seconds`, ...) on the root, which
    // roxmltree rejects as unbound; accept the input when the namespace-
    // sanitized form parses (see #91). Redaction below still runs over the
    // *original* input because quick-xml treats `junos:foo` as an opaque
    // attribute name. On a genuine parse failure return the input unchanged —
    // callers treat that as non-fatal.
    if roxmltree::Document::parse(input).is_err()
        && roxmltree::Document::parse(&crate::xml::sanitize_rustez_xml(input)).is_err()
    {
        return input.to_string();
    }

    let mut reader = Reader::from_str(input);
    let mut writer = Writer::new(Vec::new());

    // Whether each currently-open element matched a redacted name, and a
    // count of open matched ancestors. While `redact_depth > 0` every text
    // node (the matched element's own text or any descendant's) is replaced
    // with the marker, but all element tags are emitted verbatim so the XML
    // structure is preserved.
    let mut matched_stack: Vec<bool> = Vec::new();
    let mut redact_depth: usize = 0;
    // True once a REDACTED marker has been emitted for the current contiguous
    // run of redacted text/entity events. Reset at each element boundary so a
    // value split across Text/GeneralRef events (quick-xml 0.38+) collapses to
    // a single marker instead of repeating it.
    let mut redacted_run = false;

    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let matched = REDACT_ELEMENT_NAMES
                    .iter()
                    .any(|name| e.local_name().as_ref() == name.as_bytes());
                if writer.write_event(Event::Start(e)).is_err() {
                    return input.to_string();
                }
                if matched {
                    redact_depth += 1;
                }
                matched_stack.push(matched);
                redacted_run = false;
            }
            Ok(Event::End(e)) => {
                if writer.write_event(Event::End(e)).is_err() {
                    return input.to_string();
                }
                if matched_stack.pop().unwrap_or(false) {
                    redact_depth = redact_depth.saturating_sub(1);
                }
                redacted_run = false;
            }
            // Under redaction, replace text and SUPPRESS entity references
            // (GeneralRef). Without the GeneralRef arm an entity inside a
            // redacted secret would fall through to the catch-all and be
            // written verbatim (partial leak). Collapse the whole run to one
            // marker via `redacted_run`.
            Ok(Event::Text(_)) | Ok(Event::CData(_)) | Ok(Event::GeneralRef(_))
                if redact_depth > 0 =>
            {
                if !redacted_run {
                    if writer
                        .write_event(Event::Text(BytesText::new(REDACTED_MARKER)))
                        .is_err()
                    {
                        return input.to_string();
                    }
                    redacted_run = true;
                }
            }
            Ok(event) => {
                if writer.write_event(event).is_err() {
                    return input.to_string();
                }
            }
            Err(_) => return input.to_string(),
        }
    }

    String::from_utf8(writer.into_inner()).unwrap_or_else(|_| input.to_string())
}

/// Format qualifiers that may sit between a sensitive key and its value in
/// Junos config/log syntax (e.g. `pre-shared-key ascii-text "$9$..."`). When
/// present they are preserved and the *following* token is redacted.
const VALUE_QUALIFIERS: &[&str] = &["ascii-text", "hexadecimal", "plain-text", "encrypted"];

/// Route a captured artefact through the appropriate redactor. Well-formed XML
/// payloads use the element-name redactor ([`redact_xml`]); everything else
/// (log files archived since #82) is treated as plain text and routed through
/// the line-oriented redactor ([`redact_log_text`]). Previously non-XML
/// artefacts failed the XML well-formedness gate and were emitted verbatim,
/// leaking secrets embedded in log lines (#89).
pub fn redact_log_artefact(input: &str) -> String {
    let is_xml = roxmltree::Document::parse(input).is_ok()
        || roxmltree::Document::parse(&crate::xml::sanitize_rustez_xml(input)).is_ok();
    if is_xml {
        redact_xml(input)
    } else {
        redact_log_text(input)
    }
}

/// Redact secrets embedded in plain-text log lines. For each name in
/// [`REDACT_ELEMENT_NAMES`] appearing as a whole word, the value that follows
/// is replaced with [`REDACTED_MARKER`] when a config-syntax signal is present
/// (an `=`, surrounding quotes, a format qualifier, a trailing `;`, a Junos
/// crypt-hash value, or a `set ...` config line). Bare prose mentions of a key
/// name with no such signal are left untouched to avoid false positives.
pub fn redact_log_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    // `split_inclusive` keeps the line terminator attached, preserving the
    // exact newline structure (including any final newline) on rejoin.
    for line in input.split_inclusive('\n') {
        out.push_str(&redact_log_line(line));
    }
    out
}

/// Characters that form part of a Junos identifier token. Used for whole-word
/// matching of key names (so `community` does not match inside `community-name`
/// and `secret` does not match inside `secretary`).
fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// A bare value is treated as a secret with no further context when it is a
/// Junos crypt hash (`$1$`, `$5$`, `$6$`, `$8$`, `$9$`, ...): a `$` followed by
/// a digit. Such tokens never occur in ordinary prose.
fn is_junos_hash(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 2 && bytes[0] == b'$' && bytes[1].is_ascii_digit()
}

/// Redact a single log line (which may include a trailing `\n`).
fn redact_log_line(line: &str) -> String {
    // `set:` is the Junos audit marker (`UI_CFG_AUDIT_SET`); when present the
    // whole line is config context. Otherwise set-context is decided per-key by
    // [`set_statement_precedes`], which also catches a `set` statement echoed
    // mid-line (e.g. a `UI_CMDLINE_READ_LINE` syslog) — see #92.
    let audit_context = line.contains("set:");

    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut idx = 0;
    while idx < bytes.len() {
        let at_boundary = idx == 0 || !is_word_char(bytes[idx - 1]);
        let mut matched = false;
        if at_boundary {
            for key in REDACT_ELEMENT_NAMES {
                let klen = key.len();
                let end = idx + klen;
                if end <= bytes.len()
                    && &line[idx..end] == *key
                    && (end == bytes.len() || !is_word_char(bytes[end]))
                {
                    let set_context = audit_context || set_statement_precedes(line, idx);
                    if let Some((value_start, value_end)) = redactable_value(line, end, set_context)
                    {
                        out.push_str(&line[idx..value_start]);
                        out.push_str(REDACTED_MARKER);
                        idx = value_end;
                        matched = true;
                    }
                    break;
                }
            }
        }
        if !matched {
            // Push the current char (respecting UTF-8 boundaries).
            let ch = line[idx..].chars().next().unwrap();
            out.push(ch);
            idx += ch.len_utf8();
        }
    }
    out
}

/// English determiners/possessives that, when sitting between a `set` token and
/// a sensitive key, indicate prose ("we set the secret aside") rather than a
/// Junos `set` config statement. Used to suppress false positives (#92).
const SET_CONTEXT_STOPWORDS: &[&str] = &[
    "the", "a", "an", "this", "that", "these", "those", "my", "your", "our", "his", "her", "its",
    "their",
];

/// True when `token` looks like a Junos config path element: non-empty and made
/// up solely of identifier characters (alphanumerics plus `-_/.:`). Tokens with
/// spaces, quotes, or punctuation are not config identifiers.
fn is_config_identifier(token: &str) -> bool {
    !token.is_empty()
        && token.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'-'
                || byte == b'_'
                || byte == b'/'
                || byte == b'.'
                || byte == b':'
        })
}

/// Decide whether a Junos `set` config statement precedes the key at byte offset
/// `key_start` on this line. Returns true when a whole-word `set` token appears
/// earlier on the line and every whitespace-separated token between that `set`
/// and the key is a config identifier (not a stopword). This catches both a
/// line that starts with `set ...` and a `set ...` statement echoed mid-line
/// (e.g. a `UI_CMDLINE_READ_LINE` syslog: `... load-configuration set snmp
/// community VALUE ...`), while leaving prose like "we set the secret aside"
/// untouched because the intervening "the" is a stopword (#92).
fn set_statement_precedes(line: &str, key_start: usize) -> bool {
    let prefix = &line[..key_start];
    let tokens: Vec<&str> = prefix.split_whitespace().collect();
    let Some(set_idx) = tokens.iter().rposition(|&token| token == "set") else {
        return false;
    };
    tokens[set_idx + 1..]
        .iter()
        .all(|&token| is_config_identifier(token) && !SET_CONTEXT_STOPWORDS.contains(&token))
}

/// Given the byte offset just past a matched key, decide whether the following
/// value should be redacted and return its `[start, end)` byte range (the slice
/// to replace with the marker, excluding any trailing `;`). Returns `None` when
/// there is no config signal, leaving prose mentions untouched.
fn redactable_value(line: &str, after_key: usize, set_context: bool) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut pos = after_key;

    // Equals form: optional spaces, `=`, optional spaces, then the value.
    let mut scan = pos;
    while scan < bytes.len() && (bytes[scan] == b' ' || bytes[scan] == b'\t') {
        scan += 1;
    }
    if scan < bytes.len() && bytes[scan] == b'=' {
        scan += 1;
        while scan < bytes.len() && (bytes[scan] == b' ' || bytes[scan] == b'\t') {
            scan += 1;
        }
        return value_token(line, scan);
    }

    // Space form: require at least one space after the key.
    if pos >= bytes.len() || (bytes[pos] != b' ' && bytes[pos] != b'\t') {
        return None;
    }
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos >= bytes.len() {
        return None;
    }

    // Optional format qualifier (e.g. `ascii-text`): preserved, value follows.
    let mut qualifier_present = false;
    let (tok_start, tok_end) = token_bounds(line, pos);
    if VALUE_QUALIFIERS.contains(&&line[tok_start..tok_end]) {
        qualifier_present = true;
        pos = tok_end;
        while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
            pos += 1;
        }
        if pos >= bytes.len() {
            return None;
        }
    }

    let (value_start, value_end) = value_token(line, pos)?;
    let quoted = bytes[value_start] == b'"' || bytes[value_start] == b'\'';
    let terminated = value_end < bytes.len() && bytes[value_end] == b';';
    let hash = is_junos_hash(&line[value_start..value_end]);

    if quoted || qualifier_present || terminated || hash || set_context {
        Some((value_start, value_end))
    } else {
        None
    }
}

/// Locate the value token starting at `pos`, returning its `[start, end)` byte
/// range. A quoted token spans to its matching closing quote; a bare token runs
/// until whitespace or a `;` terminator. Returns `None` at end-of-line.
fn value_token(line: &str, pos: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    if pos >= bytes.len() {
        return None;
    }
    let first = bytes[pos];
    if first == b'"' || first == b'\'' {
        let mut end = pos + 1;
        while end < bytes.len() && bytes[end] != first {
            end += 1;
        }
        if end < bytes.len() {
            end += 1; // include the closing quote
        }
        return Some((pos, end));
    }
    let (start, end) = token_bounds(line, pos);
    if start == end {
        None
    } else {
        Some((start, end))
    }
}

/// Bare-token bounds starting at `pos`: a run until whitespace, `;`, or EOL.
fn token_bounds(line: &str, pos: usize) -> (usize, usize) {
    let bytes = line.as_bytes();
    let mut end = pos;
    while end < bytes.len()
        && bytes[end] != b' '
        && bytes[end] != b'\t'
        && bytes[end] != b'\n'
        && bytes[end] != b'\r'
        && bytes[end] != b';'
    {
        end += 1;
    }
    (pos, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    // #85: a known-sensitive element's text content is replaced with the
    // redaction marker while the element itself is preserved.
    #[test]
    fn redacts_pre_shared_key_text() {
        let xml = "<ike-policy><pre-shared-key>s3cr3t-psk</pre-shared-key></ike-policy>";
        let out = redact_xml(xml);
        assert!(!out.contains("s3cr3t-psk"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        assert!(
            out.contains("pre-shared-key"),
            "element name dropped: {out}"
        );
    }

    // Every name in the locked list must be redacted.
    #[test]
    fn redacts_every_known_element_name() {
        for name in REDACT_ELEMENT_NAMES {
            let xml = format!("<root><{name}>leak-{name}</{name}></root>");
            let out = redact_xml(&xml);
            assert!(
                !out.contains(&format!("leak-{name}")),
                "secret leaked for <{name}>: {out}"
            );
            assert!(
                out.contains("REDACTED"),
                "marker missing for <{name}>: {out}"
            );
        }
    }

    // Non-sensitive elements are passed through untouched.
    #[test]
    fn leaves_non_sensitive_text_untouched() {
        let xml = "<config><host-name>edge01</host-name></config>";
        let out = redact_xml(xml);
        assert!(out.contains("edge01"), "non-sensitive text mangled: {out}");
        assert!(!out.contains("REDACTED"), "unexpected redaction: {out}");
    }

    // Matching is on the namespace-stripped local name.
    #[test]
    fn matches_namespace_prefixed_local_name() {
        let xml = "<junos:secret xmlns:junos=\"http://x\">topsecret</junos:secret>";
        let out = redact_xml(xml);
        assert!(!out.contains("topsecret"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    // Surrounding structure and sibling text are preserved.
    #[test]
    fn preserves_surrounding_structure() {
        let xml = "<users><user><name>bob</name><secret>pw123</secret></user></users>";
        let out = redact_xml(xml);
        assert!(out.contains("bob"), "sibling text lost: {out}");
        assert!(!out.contains("pw123"), "secret leaked: {out}");
        assert!(out.contains("<name>"), "structure lost: {out}");
        assert!(out.contains("secret"), "redacted element name lost: {out}");
    }

    // Unparseable input is returned unchanged (callers treat as non-fatal).
    #[test]
    fn returns_input_unchanged_on_parse_failure() {
        let bad = "<unclosed><secret>oops";
        assert_eq!(redact_xml(bad), bad);
    }

    // ── #89: plain-text log-line redaction ────────────────────────────────

    // A quoted value after a sensitive key, with a Junos format qualifier, is
    // scrubbed while the key + qualifier are preserved.
    #[test]
    fn log_redacts_qualified_quoted_pre_shared_key() {
        let line = "set security ike policy p pre-shared-key ascii-text \"$9$abcDEF123\"";
        let out = redact_log_text(line);
        assert!(!out.contains("$9$abcDEF123"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        assert!(out.contains("pre-shared-key"), "key dropped: {out}");
        assert!(out.contains("ascii-text"), "qualifier dropped: {out}");
    }

    // A bare quoted value after a sensitive key is scrubbed.
    #[test]
    fn log_redacts_quoted_secret() {
        let line = "secret \"$9$topSEKRET\"";
        let out = redact_log_text(line);
        assert!(!out.contains("$9$topSEKRET"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    // The `key=value` form is scrubbed.
    #[test]
    fn log_redacts_equals_form() {
        let line = "hmac-key=deadbeefcafe1234";
        let out = redact_log_text(line);
        assert!(!out.contains("deadbeefcafe1234"), "secret leaked: {out}");
        assert!(out.contains("hmac-key="), "lhs dropped: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    // A bare value terminated by `;` (config statement) is scrubbed, and the
    // terminator is preserved.
    #[test]
    fn log_redacts_semicolon_terminated_community() {
        let line = "    community s3cr3tCommunity;";
        let out = redact_log_text(line);
        assert!(!out.contains("s3cr3tCommunity"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        assert!(out.trim_end().ends_with(';'), "terminator dropped: {out}");
    }

    // A bare Junos crypt-hash value with no other signal is still scrubbed.
    #[test]
    fn log_redacts_bare_junos_hash() {
        let line = "encrypted-password $6$saltsalt$hashhashhash";
        let out = redact_log_text(line);
        assert!(
            !out.contains("$6$saltsalt$hashhashhash"),
            "secret leaked: {out}"
        );
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    // On a `set ...` config line a bare value is scrubbed even without quotes
    // or a qualifier.
    #[test]
    fn log_redacts_bare_value_on_set_line() {
        let line = "set snmp community privateRO";
        let out = redact_log_text(line);
        assert!(!out.contains("privateRO"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    // Every sensitive key name is covered in a config-style line.
    #[test]
    fn log_redacts_every_known_key() {
        for name in REDACT_ELEMENT_NAMES {
            let line = format!("set foo {name} \"leak-{name}\"");
            let out = redact_log_text(&line);
            assert!(
                !out.contains(&format!("leak-{name}")),
                "secret leaked for {name}: {out}"
            );
            assert!(out.contains("REDACTED"), "marker missing for {name}: {out}");
        }
    }

    // A key name appearing as ordinary prose (no config signal) is untouched.
    #[test]
    fn log_leaves_prose_mention_untouched() {
        let line = "Note: the secret to success is consistent testing.";
        let out = redact_log_text(line);
        assert_eq!(out, line, "prose mention was redacted: {out}");
    }

    // A key name appearing as a substring of a longer token is not matched.
    #[test]
    fn log_leaves_substring_key_untouched() {
        let line = "The secretary updated the community-board listing today";
        let out = redact_log_text(line);
        assert_eq!(out, line, "substring match redacted: {out}");
    }

    // Non-sensitive log lines and overall newline structure are preserved;
    // only the line with a secret is scrubbed.
    #[test]
    fn log_preserves_structure_across_lines() {
        let input = "ts=1 user=admin action=login\nset security ike policy p pre-shared-key ascii-text \"$9$leakme\"\nts=2 user=admin action=logout\n";
        let out = redact_log_text(input);
        assert!(!out.contains("$9$leakme"), "secret leaked: {out}");
        assert!(out.contains("action=login"), "first line lost: {out}");
        assert!(out.contains("action=logout"), "last line lost: {out}");
        assert_eq!(out.lines().count(), 3, "line count changed: {out}");
        assert!(out.ends_with('\n'), "trailing newline lost: {out}");
    }

    // ── #91: redact_xml must handle real get-configuration replies whose
    // root carries undeclared `junos:` attribute prefixes ────────────────────

    // A realistic get-configuration reply starts with a `<configuration>` root
    // bearing `junos:changed-*` attributes whose `junos:` prefix is never
    // declared (no xmlns:junos). roxmltree rejects the unbound prefix, so the
    // old gate returned the whole config verbatim — leaking root password
    // hashes and the SNMP community. redact_xml must still scrub them.
    #[test]
    fn redacts_live_get_configuration_with_unbound_junos_prefix() {
        let xml = concat!(
            "<configuration xmlns=\"http://xml.juniper.net/xnm/1.1/xnm\" ",
            "junos:changed-seconds=\"1700000000\" ",
            "junos:changed-localtime=\"2026-06-05 12:00:00 UTC\">",
            "<system><root-authentication>",
            "<encrypted-password>$6$rootsaltA$rootHASHaaaaaaaaaa</encrypted-password>",
            "</root-authentication>",
            "<login><user><name>admin</name><authentication>",
            "<encrypted-password>$6$usersaltB$userHASHbbbbbbbbbb</encrypted-password>",
            "</authentication></user></login></system>",
            "<snmp><community><name>commLEAK</name></community></snmp>",
            "</configuration>",
        );
        let out = redact_xml(xml);
        assert!(
            !out.contains("$6$rootsaltA$rootHASHaaaaaaaaaa"),
            "root password hash leaked: {out}"
        );
        assert!(
            !out.contains("$6$usersaltB$userHASHbbbbbbbbbb"),
            "user password hash leaked: {out}"
        );
        assert!(!out.contains("commLEAK"), "snmp community leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        // Structure preserved: the (non-sensitive) admin user name survives.
        assert!(out.contains("admin"), "non-sensitive text lost: {out}");
    }

    // ── #92: a `set` config statement echoed mid-line (e.g. in a
    // UI_CMDLINE_READ_LINE syslog) must still trip the set-context rule ───────

    // syslogd echoes the raw RPC command on a UI_CMDLINE_READ_LINE line:
    //   ... load-configuration set snmp community SMOKE89LEAK authorization read-only
    // Here `set snmp community VALUE` is mid-line (not at line start, no `set:`)
    // and the value is bare (no quote/qualifier/;/$hash), so the old line-level
    // set_context missed it. The community value must be redacted.
    #[test]
    fn log_redacts_midline_set_in_cmdline_echo() {
        let line = "Jun  5 12:00:00 host mgd[123]: UI_CMDLINE_READ_LINE: User 'admin', \
                    command 'load-configuration rpc rpc ... set snmp community SMOKE89LEAK \
                    authorization read-only'";
        let out = redact_log_text(line);
        assert!(!out.contains("SMOKE89LEAK"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        assert!(out.contains("community"), "key dropped: {out}");
    }

    // The mid-line `set` rule must not fire on ordinary prose: "we set the
    // secret aside" has the stopword "the" between `set` and the key, so no
    // config context is inferred and the line is left untouched.
    #[test]
    fn log_leaves_prose_set_the_secret_untouched() {
        let line = "Earlier we set the secret aside for review.";
        let out = redact_log_text(line);
        assert_eq!(out, line, "prose set-the-secret was redacted: {out}");
    }

    // The dispatcher routes well-formed XML to the element redactor and
    // non-XML log text to the line redactor.
    #[test]
    fn artefact_dispatcher_routes_by_well_formedness() {
        let xml = "<ike><pre-shared-key>xmlsecret</pre-shared-key></ike>";
        let xout = redact_log_artefact(xml);
        assert!(!xout.contains("xmlsecret"), "xml secret leaked: {xout}");

        let log = "set snmp community logsecret";
        let lout = redact_log_artefact(log);
        assert!(!lout.contains("logsecret"), "log secret leaked: {lout}");
    }

    // ── #103: quick-xml 0.41 streams entities as separate GeneralRef events ──

    #[test]
    fn redacts_entity_split_secret_to_single_marker() {
        // quick-xml 0.41 streams `abc&amp;def` as Text("abc"), GeneralRef("amp"),
        // Text("def"). Under redaction the entity must NOT leak through, and the
        // split value must collapse to exactly one marker.
        //
        // Note: REDACTED_MARKER ("<REDACTED>") is written via `BytesText::new`,
        // which correctly XML-escapes its `<`/`>` to `&lt;`/`&gt;` on write —
        // that's valid serialization (round-trips to the same text on reparse),
        // not a leak, and predates this fix (#85). So we assert on the
        // leak-specific signature (`&amp;`, the re-emitted GeneralRef entity)
        // and the bare "REDACTED" substring (present in both escaped and
        // unescaped form) rather than raw '&' absence or the literal marker.
        let xml = "<config><pre-shared-key>abc&amp;def</pre-shared-key></config>";
        let out = redact_xml(xml);
        assert!(
            !out.contains("&amp;"),
            "entity fragment leaked from redacted element: {out}"
        );
        assert!(!out.contains("abc"), "secret fragment leaked: {out}");
        assert!(!out.contains("def"), "secret fragment leaked: {out}");
        assert_eq!(
            out.matches("REDACTED").count(),
            1,
            "split redacted value must collapse to a single marker: {out}"
        );
        // Structure preserved.
        assert!(
            out.contains("<pre-shared-key>") && out.contains("</pre-shared-key>"),
            "structure lost: {out}"
        );
    }

    #[test]
    fn redacts_pure_entity_secret() {
        // A redacted element whose entire content is an entity streams as a
        // single GeneralRef (no surrounding Text). It must still be redacted to
        // one marker and must not leak the entity.
        let xml = "<config><secret>&amp;</secret></config>";
        let out = redact_xml(xml);
        assert!(
            !out.contains("&amp;"),
            "entity leaked from redacted element: {out}"
        );
        assert_eq!(
            out.matches("REDACTED").count(),
            1,
            "pure-entity redacted value must produce exactly one marker: {out}"
        );
        assert!(
            out.contains("<secret>") && out.contains("</secret>"),
            "structure lost: {out}"
        );
    }

    #[test]
    fn non_redacted_entity_round_trips() {
        // A non-secret element containing an entity must be preserved verbatim
        // (GeneralRef must re-emit &amp; on the passthrough path).
        let xml = "<config><name>edge &amp; core</name></config>";
        let out = redact_xml(xml);
        // Exactly one single-escaped entity — guards against a double-escape
        // regression (&amp;amp; would also satisfy a bare `contains("&amp;")`).
        assert_eq!(
            out.matches("&amp;").count(),
            1,
            "entity must round-trip single-escaped exactly once: {out}"
        );
        assert!(
            !out.contains("&amp;amp;"),
            "entity double-escaped on non-redacted path: {out}"
        );
        assert!(
            out.contains("edge") && out.contains("core"),
            "text lost: {out}"
        );
        assert!(
            !out.contains(REDACTED_MARKER),
            "unexpected redaction: {out}"
        );
    }
}
