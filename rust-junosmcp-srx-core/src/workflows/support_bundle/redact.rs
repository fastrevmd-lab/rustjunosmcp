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
//! * `authentication-key` — routing-protocol (OSPF/RIP/BGP) authentication keys
//! * `authentication-password` / `privacy-password` — SNMPv3 USM auth/priv secrets
//! * `key` — MD5 authentication key text (e.g. OSPF `authentication md5 <id> key`)
//! * `value` — NTP `authentication-key <id> type md5 value` secret
//!
//! XML payloads are redacted by element name — every matching element has
//! its text content replaced with `<REDACTED>` while preserving the XML
//! structure so JTAC can still see *where* a secret was configured
//! ([`redact_xml`]). Independent of element name, [`redact_xml`] also
//! redacts any text node that looks like a Junos crypt hash (`$N$...`) as a
//! catch-all for secrets under element names not on the locked list.
//!
//! Non-XML artefacts (the `/var/log/*` files archived since #82) are redacted
//! by a conservative line-oriented pass ([`redact_log_text`]) that scrubs the
//! same key set from config-style log syntax. [`redact_log_artefact`] routes
//! each artefact to the right pass based on XML well-formedness (#89).

#![deny(clippy::indexing_slicing, clippy::string_slice)]

/// Element names whose text content is replaced with `<REDACTED>`.
/// Matching is exact on the local element name (namespace-stripped).
pub const REDACT_ELEMENT_NAMES: &[&str] = &[
    "pre-shared-key",
    "secret",
    "simple-password",
    "encrypted-password",
    "community",
    "hmac-key",
    "authentication-key",
    "authentication-password",
    "privacy-password",
    "key",
    "value",
];

/// Replacement string used in redacted element text.
pub const REDACTED_MARKER: &str = "<REDACTED>";

/// Outcome of [`try_redact_xml`]: either the input was confirmed
/// well-formed XML and redacted (whether or not anything actually changed),
/// or the input could not be confirmed well-formed and redaction was not
/// attempted at all.
///
/// This distinction matters: `Redacted(s)` with `s == input` legitimately
/// means "parsed fine, nothing sensitive found." `Unparseable` means the
/// redactor cannot vouch for the content at all — callers that need the
/// house fail-closed rule (device operations, and any support-bundle
/// artefact expected to be well-formed XML) must treat `Unparseable` as a
/// refusal to ship, not as "probably fine."
#[derive(Debug, PartialEq, Eq)]
pub enum XmlRedaction {
    /// Input was confirmed well-formed XML; this is the redacted output.
    Redacted(String),
    /// Input could not be confirmed well-formed XML; no redaction was
    /// attempted and nothing was verified safe.
    Unparseable,
}

/// Redact known-sensitive element text content from an XML payload, and
/// independently redact any text node that looks like a Junos crypt hash
/// (`$N$...`) regardless of its element name, as a catch-all for secrets
/// under names not on [`REDACT_ELEMENT_NAMES`].
///
/// Returns [`XmlRedaction::Unparseable`] rather than falling back to the
/// unredacted input when the input cannot be confirmed well-formed XML, or
/// when the redacted form cannot be reconstructed as valid UTF-8 XML — a
/// caller that received `Unparseable` and shipped the raw payload anyway
/// would defeat the whole point of `redact=true`.
pub fn try_redact_xml(input: &str) -> XmlRedaction {
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
    // attribute name. On a genuine parse failure, refuse rather than
    // returning the input unchanged — see [`XmlRedaction::Unparseable`].
    if roxmltree::Document::parse(input).is_err()
        && roxmltree::Document::parse(&crate::xml::sanitize_rustez_xml(input)).is_err()
    {
        return XmlRedaction::Unparseable;
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
                    .any(|name| e.local_name().as_ref() == *name);
                if writer.write_event(Event::Start(e)).is_err() {
                    return XmlRedaction::Unparseable;
                }
                if matched {
                    redact_depth += 1;
                }
                matched_stack.push(matched);
                redacted_run = false;
            }
            Ok(Event::End(e)) => {
                if writer.write_event(Event::End(e)).is_err() {
                    return XmlRedaction::Unparseable;
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
                        return XmlRedaction::Unparseable;
                    }
                    redacted_run = true;
                }
            }
            // Catch-all: outside any named-matched element, a text or CDATA
            // node that is itself a bare Junos crypt hash (`$N$...`) is
            // still a secret — it just landed under an element name not on
            // the locked list. Redact it too.
            Ok(Event::Text(t)) if text_is_junos_hash(t.as_ref()) => {
                if writer
                    .write_event(Event::Text(BytesText::new(REDACTED_MARKER)))
                    .is_err()
                {
                    return XmlRedaction::Unparseable;
                }
            }
            Ok(Event::CData(t)) if text_is_junos_hash(t.as_ref()) => {
                if writer
                    .write_event(Event::Text(BytesText::new(REDACTED_MARKER)))
                    .is_err()
                {
                    return XmlRedaction::Unparseable;
                }
            }
            Ok(event) => {
                if writer.write_event(event).is_err() {
                    return XmlRedaction::Unparseable;
                }
            }
            Err(_) => return XmlRedaction::Unparseable,
        }
    }

    match String::from_utf8(writer.into_inner()) {
        Ok(s) => XmlRedaction::Redacted(s),
        Err(_) => XmlRedaction::Unparseable,
    }
}

/// Redact known-sensitive element text content from an XML payload.
/// Returns the redacted XML string. If the input cannot be parsed,
/// returns the input unchanged.
///
/// This is the permissive convenience wrapper around [`try_redact_xml`] for
/// callers that have no fail-closed obligation of their own. Callers on a
/// path that must never ship an unverified payload — like
/// `collect_jtac_support_bundle`'s per-RPC XML capture — must call
/// [`try_redact_xml`] directly and refuse the artefact on
/// [`XmlRedaction::Unparseable`] instead of using this wrapper. There is no
/// legitimate non-test caller for the permissive unchanged-on-failure
/// behaviour, so this is test-only (F7).
#[cfg(test)]
fn redact_xml(input: &str) -> String {
    match try_redact_xml(input) {
        XmlRedaction::Redacted(s) => s,
        XmlRedaction::Unparseable => input.to_string(),
    }
}

/// True when `text`, trimmed of surrounding whitespace, looks like a bare
/// Junos crypt hash (`$1$`, `$5$`, `$6$`, `$8$`, `$9$`, ... or `$sha1$`): a
/// `$`, one or more digits (or the literal `sha1`), then a closing `$`. Used
/// by [`try_redact_xml`]'s catch-all so a secret is still caught when it
/// lands under an element name not on the locked list.
fn text_is_junos_hash(text: &str) -> bool {
    is_junos_hash(text.trim())
}

/// Format qualifiers that may sit between a sensitive key and its value in
/// Junos config/log syntax (e.g. `pre-shared-key ascii-text "$9$..."`). When
/// present they are preserved and the *following* token is redacted.
const VALUE_QUALIFIERS: &[&str] = &["ascii-text", "hexadecimal", "plain-text", "encrypted"];

/// Route a captured artefact through the appropriate redactor. Well-formed XML
/// payloads are first run through the element-name redactor ([`try_redact_xml`])
/// and then *always* through the line-oriented redactor ([`redact_log_text`])
/// as well: rustez's `parse_cli_output` returns the whole RPC reply verbatim
/// when the expected `<output>` child element is absent, so a CLI-syntax
/// secret can end up sitting in plain text under an element name that is not
/// on the locked list (e.g. directly under `<rpc-reply>`) — the element-name
/// pass has nothing to match there. Content that merely looks like XML but
/// that the redactor could not actually walk, and log files archived since
/// #82, are treated as plain text and routed through the line-oriented
/// redactor only. Previously non-XML artefacts failed the XML well-formedness
/// gate and were emitted verbatim, leaking secrets embedded in log lines
/// (#89); the well-formedness gate can never fall through to shipping the
/// artefact unredacted — the line-oriented pass is always the floor.
pub fn redact_log_artefact(input: &str) -> String {
    let is_xml = roxmltree::Document::parse(input).is_ok()
        || roxmltree::Document::parse(&crate::xml::sanitize_rustez_xml(input)).is_ok();
    if is_xml {
        match try_redact_xml(input) {
            XmlRedaction::Redacted(s) => redact_log_text(&s),
            XmlRedaction::Unparseable => redact_log_text(input),
        }
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
#[allow(clippy::indexing_slicing)] // called with bounds-checked byte offsets
fn is_word_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'
}

/// A bare value is treated as a secret with no further context when it is a
/// Junos crypt hash: a `$`, one or more digits (crypt id `$1$`, `$5$`, `$6$`,
/// `$8$`, `$9$`, ...) or the literal `sha1`, then a closing `$`. Such tokens
/// never occur in ordinary prose. Requiring the closing `$` (rather than just
/// `$` + one digit) avoids false positives like `$5 off` and covers the
/// `$sha1$...` form, which has no leading digit.
fn is_junos_hash(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.first() != Some(&b'$') {
        return false;
    }
    if token.starts_with("$sha1$") {
        return true;
    }
    let mut i = 1;
    let mut digits = 0usize;
    while let Some(&b) = bytes.get(i) {
        if !b.is_ascii_digit() {
            break;
        }
        digits += 1;
        i += 1;
    }
    digits > 0 && bytes.get(i) == Some(&b'$')
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
        // SOUND: `idx > 0` guard ensures `idx - 1` is valid.
        #[allow(clippy::indexing_slicing)]
        let at_boundary = idx == 0 || !is_word_char(bytes[idx - 1]);
        let mut matched = false;
        if at_boundary {
            for key in REDACT_ELEMENT_NAMES {
                let klen = key.len();
                let end = idx + klen;
                // SOUND: `idx` is always a char boundary (advances by ch.len_utf8()),
                // `klen` is the byte length of an ASCII key, so `end` is also a char
                // boundary. The `end <= bytes.len()` guard prevents out-of-bounds.
                #[allow(clippy::indexing_slicing)]
                if end <= bytes.len()
                    && &bytes[idx..end] == key.as_bytes()
                    && (end == bytes.len() || !is_word_char(bytes[end]))
                {
                    let set_context = audit_context || set_statement_precedes(line, idx);
                    if let Some((value_start, value_end)) = redactable_value(line, end, set_context)
                    {
                        // SOUND: `idx` is a char boundary, `value_start` comes from
                        // `value_token` which guarantees char boundaries (scans for
                        // ASCII delimiters or line.len()).
                        #[allow(clippy::string_slice)]
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
            // SOUND: `idx` is always a char boundary (loop invariant).
            #[allow(clippy::string_slice)]
            let ch = line[idx..]
                .chars()
                .next()
                .expect("chars().next() cannot fail: loop invariant idx < line.len()");
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
    // SOUND: `key_start` is `idx` from the caller, which is always a char boundary.
    #[allow(clippy::string_slice)]
    let prefix = &line[..key_start];
    let tokens: Vec<&str> = prefix.split_whitespace().collect();
    let Some(set_idx) = tokens.iter().rposition(|&token| token == "set") else {
        return false;
    };
    // SOUND: `set_idx` comes from `rposition`, so it is a valid index.
    #[allow(clippy::indexing_slicing)]
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
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    let mut scan = pos;
    #[allow(clippy::indexing_slicing)]
    while scan < bytes.len() && (bytes[scan] == b' ' || bytes[scan] == b'\t') {
        scan += 1;
    }
    #[allow(clippy::indexing_slicing)]
    if scan < bytes.len() && bytes[scan] == b'=' {
        scan += 1;
        #[allow(clippy::indexing_slicing)]
        while scan < bytes.len() && (bytes[scan] == b' ' || bytes[scan] == b'\t') {
            scan += 1;
        }
        return value_token(line, scan);
    }

    // Space form: require at least one space after the key.
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    if pos >= bytes.len() || (bytes[pos] != b' ' && bytes[pos] != b'\t') {
        return None;
    }
    #[allow(clippy::indexing_slicing)]
    while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
        pos += 1;
    }
    if pos >= bytes.len() {
        return None;
    }

    // Optional format qualifier (e.g. `ascii-text`): preserved, value follows.
    let mut qualifier_present = false;
    let (tok_start, tok_end) = token_bounds(line, pos);
    // SOUND: `token_bounds` guarantees char boundaries (scans for ASCII
    // delimiters or line.len()).
    #[allow(clippy::string_slice)]
    if VALUE_QUALIFIERS.contains(&&line[tok_start..tok_end]) {
        qualifier_present = true;
        pos = tok_end;
        // SOUND: bounds-checked against bytes.len().
        #[allow(clippy::indexing_slicing)]
        while pos < bytes.len() && (bytes[pos] == b' ' || bytes[pos] == b'\t') {
            pos += 1;
        }
        if pos >= bytes.len() {
            return None;
        }
    }

    let (value_start, value_end) = value_token(line, pos)?;
    // SOUND: bounds checks prevent out-of-bounds indexing.
    #[allow(clippy::indexing_slicing)]
    let quoted = bytes[value_start] == b'"'
        || bytes[value_start] == b'\''
        || bytes_start_with(bytes, value_start, QUOT_ENTITY);
    #[allow(clippy::indexing_slicing)]
    let terminated = value_end < bytes.len() && bytes[value_end] == b';';
    // A `{` (optionally preceded by whitespace) opens a config block — treat
    // it as a terminator like `;` (F1: legacy curly-brace SNMP syntax, e.g.
    // `community NAME {`).
    let mut block_scan = value_end;
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while block_scan < bytes.len() && (bytes[block_scan] == b' ' || bytes[block_scan] == b'\t') {
        block_scan += 1;
    }
    // SOUND: bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    let opens_block = block_scan < bytes.len() && bytes[block_scan] == b'{';
    // SOUND: `value_token` guarantees char boundaries (scans for ASCII
    // delimiters or line.len()).
    #[allow(clippy::string_slice)]
    let hash = is_junos_hash(&line[value_start..value_end]);

    if quoted || qualifier_present || terminated || opens_block || hash || set_context {
        Some((value_start, value_end))
    } else {
        None
    }
}

/// XML entity form of a double quote (`&quot;`). CLI text redacted after
/// [`try_redact_xml`]'s element pass (see [`redact_log_artefact`]) may still
/// have its literal `"` characters XML-escaped; [`value_token`] and
/// [`redactable_value`] must recognise this form too, or a quoted value with
/// an internal space is only partially matched up to the first space —
/// leaking the remainder (F5).
const QUOT_ENTITY: &[u8] = b"&quot;";

/// True when `bytes[pos..]` starts with `needle`, without slicing (this
/// module denies `clippy::indexing_slicing`/`clippy::string_slice`).
fn bytes_start_with(bytes: &[u8], pos: usize, needle: &[u8]) -> bool {
    needle
        .iter()
        .enumerate()
        .all(|(i, &b)| bytes.get(pos + i) == Some(&b))
}

/// Locate the value token starting at `pos`, returning its `[start, end)` byte
/// range. A quoted token — delimited by `"`, `'`, or the XML entity `&quot;`
/// (F5) — spans to its matching closing quote; a bare token runs until
/// whitespace or a `;` terminator. Returns `None` at end-of-line.
fn value_token(line: &str, pos: usize) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    if pos >= bytes.len() {
        return None;
    }
    // SOUND: bounds-checked above.
    #[allow(clippy::indexing_slicing)]
    let first = bytes[pos];
    if first == b'"' || first == b'\'' {
        let mut end = pos + 1;
        // SOUND: bounds-checked against bytes.len().
        #[allow(clippy::indexing_slicing)]
        while end < bytes.len() && bytes[end] != first {
            end += 1;
        }
        // SOUND: bounds-checked.
        #[allow(clippy::indexing_slicing)]
        if end < bytes.len() {
            end += 1; // include the closing quote
        }
        // `end` is always a char boundary: either `bytes.len()` or one byte
        // past an ASCII quote (`"` or `'`), both of which are char boundaries.
        return Some((pos, end));
    }
    if bytes_start_with(bytes, pos, QUOT_ENTITY) {
        let mut end = pos + QUOT_ENTITY.len();
        while end < bytes.len() && !bytes_start_with(bytes, end, QUOT_ENTITY) {
            end += 1;
        }
        if end < bytes.len() {
            end += QUOT_ENTITY.len(); // include the closing entity
        }
        // `end` only ever lands where the ASCII byte sequence `&quot;` starts
        // or matches `bytes.len()`, both of which are char boundaries — the
        // scan advances one byte at a time but a partial match can never
        // stop mid-multi-byte-char, since `&` (0x26) never occurs as a UTF-8
        // continuation byte (0x80-0xBF).
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
    // SOUND: all byte indexing is bounds-checked against bytes.len().
    #[allow(clippy::indexing_slicing)]
    while end < bytes.len()
        && bytes[end] != b' '
        && bytes[end] != b'\t'
        && bytes[end] != b'\n'
        && bytes[end] != b'\r'
        && bytes[end] != b';'
    {
        end += 1;
    }
    // `end` is always a char boundary: either `bytes.len()` or pointing to an
    // ASCII delimiter (space, tab, newline, carriage return, or semicolon).
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

    // ── #273: non-ASCII adjacent to a near-miss key must not panic ────────────

    // Each key in REDACT_ELEMENT_NAMES gets a regression test with a multi-byte
    // char straddling the byte after a `klen - 1` prefix match. The function
    // must return (not panic) and leave the input unchanged (a near-miss is not
    // a match).

    #[test]
    fn log_near_miss_pre_shared_key_with_multibyte_char() {
        // "pre-shared-ke" is 13 bytes, one short of "pre-shared-key" (14 bytes).
        // The multi-byte char 'é' (2 bytes) starts at byte 14, so idx + klen = 15
        // lands inside it. The old code sliced `line[idx..15]` and panicked.
        let line = " pre-shared-keé";
        let out = redact_log_line(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn log_near_miss_secret_with_multibyte_char() {
        // "secre" is 5 bytes, one short of "secret" (6 bytes).
        // The multi-byte char 'é' (2 bytes) starts at byte 6, so idx + klen = 7
        // lands inside it. The old code sliced `line[idx..7]` and panicked.
        let line = " secreé";
        let out = redact_log_line(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn log_near_miss_simple_password_with_multibyte_char() {
        // "simple-passwor" is 14 bytes, one short of "simple-password" (15 bytes).
        // The multi-byte char 'é' (2 bytes) starts at byte 15, so idx + klen = 16
        // lands inside it. The old code sliced `line[idx..16]` and panicked.
        let line = " simple-passworé";
        let out = redact_log_line(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn log_near_miss_encrypted_password_with_multibyte_char() {
        // "encrypted-passwor" is 17 bytes, one short of "encrypted-password" (18).
        // The multi-byte char 'é' (2 bytes) starts at byte 18, so idx + klen = 19
        // lands inside it. The old code sliced `line[idx..19]` and panicked.
        let line = " encrypted-passworé";
        let out = redact_log_line(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn log_near_miss_community_with_multibyte_char() {
        // "communit" is 8 bytes, one short of "community" (9 bytes).
        // The multi-byte char 'é' (2 bytes) starts at byte 9, so idx + klen = 10
        // lands inside it. The old code sliced `line[idx..10]` and panicked.
        let line = " communité";
        let out = redact_log_line(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    #[test]
    fn log_near_miss_hmac_key_with_multibyte_char() {
        // "hmac-ke" is 7 bytes, one short of "hmac-key" (8 bytes).
        // The multi-byte char 'é' (2 bytes) starts at byte 8, so idx + klen = 9
        // lands inside it. The old code sliced `line[idx..9]` and panicked.
        let line = " hmac-keé";
        let out = redact_log_line(line);
        assert_eq!(out, line, "near-miss must not be redacted: {out}");
    }

    // A real key followed by non-ASCII in the value must still redact.
    #[test]
    fn log_redacts_real_key_with_non_ascii_value() {
        let line = "set snmp community \"välue123\"";
        let out = redact_log_text(line);
        assert!(!out.contains("välue123"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        assert!(out.contains("community"), "key dropped: {out}");
    }

    // ── fail-closed: `try_redact_xml` must distinguish "parsed, nothing to
    // redact" from "could not parse", and never silently drop into shipping
    // unverified content ──────────────────────────────────────────────────

    #[test]
    fn try_redact_xml_reports_unparseable_on_genuine_parse_failure() {
        let bad = "<unclosed><secret>oops";
        assert_eq!(try_redact_xml(bad), XmlRedaction::Unparseable);
    }

    #[test]
    fn try_redact_xml_redacts_well_formed_input() {
        let xml = "<ike-policy><pre-shared-key>s3cr3t</pre-shared-key></ike-policy>";
        match try_redact_xml(xml) {
            XmlRedaction::Redacted(out) => {
                assert!(!out.contains("s3cr3t"), "secret leaked: {out}");
                assert!(out.contains("REDACTED"), "marker missing: {out}");
            }
            XmlRedaction::Unparseable => panic!("well-formed input must not be Unparseable"),
        }
    }

    // `redact_xml` is the permissive convenience wrapper: its
    // unchanged-on-failure contract must still hold for callers that accept
    // it explicitly (tests, `redact_log_artefact`'s best-effort dispatch).
    #[test]
    fn redact_xml_still_returns_input_unchanged_on_parse_failure() {
        let bad = "<unclosed><secret>oops";
        assert_eq!(redact_xml(bad), bad);
    }

    // A payload that is plain text (e.g. `request support information`
    // output, which is never XML) must never round-trip through the
    // support-bundle artefact path unredacted just because it fails the XML
    // well-formedness gate: `redact_log_artefact` dispatches it to the
    // line-oriented scrubber instead of passing it through.
    #[test]
    fn text_tech_support_output_is_redacted_not_shipped_raw() {
        let tech_support = "Hostname: srx1\n\
             set security ike policy p1 pre-shared-key ascii-text \"$9$leakedPSK\";\n\
             set snmp community privateRO;\n";
        // Demonstrates the underlying bug: `redact_xml` alone is a no-op on
        // non-XML text because its well-formedness gate always fails.
        assert_eq!(
            redact_xml(tech_support),
            tech_support,
            "redact_xml is expected to no-op on non-XML text — that was the bug"
        );
        // `redact_log_artefact` (the fix) actually scrubs it.
        let out = redact_log_artefact(tech_support);
        assert!(!out.contains("leakedPSK"), "PSK leaked: {out}");
        assert!(!out.contains("privateRO"), "SNMP community leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    // Content that fails the XML well-formedness gate (e.g. a log file that
    // happens to start with a stray `<`) must still fall through to the
    // line-oriented floor rather than being shipped verbatim.
    #[test]
    fn unparseable_content_with_embedded_secret_is_still_scrubbed_by_the_log_dispatcher() {
        let bad = "<unclosed>\nset security ike policy p1 pre-shared-key ascii-text \"$9$leak\"\n";
        assert!(
            roxmltree::Document::parse(bad).is_err(),
            "fixture must actually be a parse failure"
        );
        let out = redact_log_artefact(bad);
        assert!(!out.contains("$9$leak"), "secret leaked: {out}");
    }

    // ── newly listed redact keys: authentication-key, SNMPv3
    // authentication-password/privacy-password, MD5 key, NTP value ────────

    #[test]
    fn redacts_snmpv3_usm_auth_and_priv_passwords() {
        let xml = concat!(
            "<snmp><v3><usm><local-engine><user>",
            "<name>oncall</name>",
            "<authentication-md5><authentication-password>$9$authLEAK</authentication-password></authentication-md5>",
            "<privacy-des><privacy-password>$9$privLEAK</privacy-password></privacy-des>",
            "</user></local-engine></usm></v3></snmp>",
        );
        let out = redact_xml(xml);
        assert!(!out.contains("authLEAK"), "auth password leaked: {out}");
        assert!(!out.contains("privLEAK"), "priv password leaked: {out}");
        assert!(out.contains("oncall"), "non-sensitive text lost: {out}");
    }

    #[test]
    fn redacts_routing_protocol_authentication_key() {
        // e.g. `set protocols bgp group ext authentication-key "$9$..."`
        let xml = "<protocols><bgp><group><name>ext</name>\
                   <authentication-key>$9$bgpKeyLEAK</authentication-key>\
                   </group></bgp></protocols>";
        let out = redact_xml(xml);
        assert!(
            !out.contains("bgpKeyLEAK"),
            "authentication-key leaked: {out}"
        );
    }

    #[test]
    fn redacts_md5_authentication_key_element() {
        // e.g. `set protocols ospf area 0 interface ge-0/0/0 authentication
        // md5 1 key "$9$..."`
        let xml = "<protocols><ospf><area><interface>\
                   <authentication><md5><name>1</name><key>$9$ospfMd5LEAK</key></md5></authentication>\
                   </interface></area></ospf></protocols>";
        let out = redact_xml(xml);
        assert!(!out.contains("ospfMd5LEAK"), "MD5 key leaked: {out}");
    }

    #[test]
    fn redacts_ntp_authentication_key_value() {
        // e.g. `set system ntp authentication-key 1 type md5 value "$9$..."`
        let xml = "<system><ntp><authentication-key>\
                   <key>1</key><type>md5</type><value>$9$ntpValueLEAK</value>\
                   </authentication-key></ntp></system>";
        let out = redact_xml(xml);
        assert!(!out.contains("ntpValueLEAK"), "NTP value leaked: {out}");
    }

    // ── `$N$` catch-all applies to arbitrary XML text, not just named
    // elements ─────────────────────────────────────────────────────────────

    #[test]
    fn catch_all_redacts_junos_hash_under_an_unlisted_element_name() {
        let xml = "<config><password-hash>$6$saltXYZ$hashLEAKvalue</password-hash></config>";
        let out = redact_xml(xml);
        assert!(
            !out.contains("$6$saltXYZ$hashLEAKvalue"),
            "hash leaked: {out}"
        );
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    #[test]
    fn catch_all_leaves_non_hash_text_under_unlisted_elements_untouched() {
        let xml = "<config><description>not a secret</description></config>";
        let out = redact_xml(xml);
        assert!(
            out.contains("not a secret"),
            "non-secret text mangled: {out}"
        );
        assert!(!out.contains("REDACTED"), "unexpected redaction: {out}");
    }

    #[test]
    fn catch_all_does_not_duplicate_marker_inside_a_named_matched_element() {
        let xml = "<ike-policy><pre-shared-key>$9$abc</pre-shared-key></ike-policy>";
        let out = redact_xml(xml);
        assert_eq!(
            out.matches("REDACTED").count(),
            1,
            "marker duplicated by both the element-name pass and the catch-all: {out}"
        );
    }

    // ── F1: legacy curly-brace SNMP config syntax ──────────────────────────

    #[test]
    fn log_redacts_community_in_curly_brace_block() {
        // Legacy SNMP config style: `community NAME { ... }` instead of
        // `community NAME;`. The old `redactable_value` only treated `;` as a
        // terminator, so a bare value followed by `{` fell through with no
        // config signal and was left unredacted.
        let line = "    community s3cr3tCommunity {\n";
        let out = redact_log_text(line);
        assert!(!out.contains("s3cr3tCommunity"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        assert!(out.trim_end().ends_with('{'), "brace dropped: {out}");
    }

    // ── F2: element-redacted XML must still get the line-oriented pass ────

    #[test]
    fn artefact_dispatcher_scrubs_cli_text_embedded_in_xml_without_output_wrapper() {
        // rustez's `parse_cli_output` returns the whole RPC reply text when
        // there is no `<output>` child element. The element-name XML
        // redactor has nothing to match here (no element in this reply is
        // named after a locked key), so the embedded CLI-syntax secret must
        // be caught by a second, line-oriented pass over the (already
        // element-redacted) XML text — not left to the element pass alone.
        let xml = "<rpc-reply>set snmp community leakedXML;\n</rpc-reply>";
        let out = redact_log_artefact(xml);
        assert!(!out.contains("leakedXML"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    #[test]
    fn artefact_dispatcher_still_redacts_named_elements_after_line_pass() {
        // The added line-oriented pass (F2) must not undo or interfere with
        // the existing element-name redaction.
        let xml = "<ike><pre-shared-key>xmlsecret</pre-shared-key></ike>";
        let out = redact_log_artefact(xml);
        assert!(!out.contains("xmlsecret"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    // ── F4: `is_junos_hash` must require a closing `$`, and must cover
    // `$sha1$` ──────────────────────────────────────────────────────────────

    #[test]
    fn is_junos_hash_matches_sha1_prefix() {
        assert!(is_junos_hash(
            "$sha1$abcdef0123456789abcdef0123456789abcdef01"
        ));
    }

    #[test]
    fn is_junos_hash_rejects_dollar_digit_without_closing_dollar() {
        assert!(!is_junos_hash("$5 off"));
    }

    #[test]
    fn is_junos_hash_still_matches_crypt_hash() {
        assert!(is_junos_hash("$6$saltsalt$hashhashhash"));
    }

    #[test]
    fn catch_all_redacts_sha1_prefixed_hash() {
        let xml = "<config><password-hash>$sha1$leakedSHA1hash</password-hash></config>";
        let out = redact_xml(xml);
        assert!(!out.contains("leakedSHA1hash"), "hash leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
    }

    #[test]
    fn catch_all_does_not_redact_dollar_digit_prose() {
        let xml = "<config><promo>$5 off your order</promo></config>";
        let out = redact_xml(xml);
        assert!(
            out.contains("$5 off your order"),
            "false-positive redaction: {out}"
        );
    }

    // ── F5: `&quot;`-quoted values (XML-escaped literal quotes) must not
    // partially leak past the first internal space ────────────────────────

    #[test]
    fn log_redacts_value_quoted_with_xml_entity_quot_containing_internal_space() {
        // A CLI-syntax secret embedded inside XML-escaped text (e.g. after
        // the F2 dispatcher runs `redact_log_text` over the element-redacted
        // XML string) may have its quotes as the `&quot;` entity rather than
        // a literal `"`. The old bare-token scan stopped at the first
        // internal space, leaking everything after it up to the closing
        // entity.
        let line =
            "set security ike policy p1 pre-shared-key ascii-text &quot;correct horse&quot;;";
        let out = redact_log_text(line);
        assert!(!out.contains("correct horse"), "secret leaked: {out}");
        assert!(out.contains("REDACTED"), "marker missing: {out}");
        assert!(out.contains("pre-shared-key"), "key dropped: {out}");
    }
}
