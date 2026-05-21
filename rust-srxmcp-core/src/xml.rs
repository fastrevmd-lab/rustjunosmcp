//! XML helpers shared across SRX workflows. Uses roxmltree for a clean DOM
//! API that keeps every tool out of the multi-RE envelope business.

use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::Writer;
use std::io::Cursor;

/// One node's payload after stripping the multi-RE envelope.
///
/// `re_name` is `""` for standalone devices, `"node0"` / `"node1"` for
/// clustered devices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReNode {
    pub re_name: String,
    /// Raw XML for everything inside this node's `<multi-routing-engine-item>`
    /// (or the full document body for standalone devices).
    pub inner_xml: String,
}

/// Serialize a roxmltree node and all its children back to an XML string,
/// correctly escaping text content and attribute values via quick_xml.
fn node_to_xml(node: roxmltree::Node<'_, '_>) -> String {
    let mut writer = Writer::new(Cursor::new(Vec::new()));
    write_node(&mut writer, node);
    String::from_utf8(writer.into_inner().into_inner()).unwrap_or_default()
}

fn write_node<W: std::io::Write>(writer: &mut Writer<W>, node: roxmltree::Node<'_, '_>) {
    if node.is_element() {
        let name = node.tag_name().name();
        let mut start = BytesStart::new(name);
        for attr in node.attributes() {
            // push_attribute escapes attribute values automatically.
            start.push_attribute((attr.name(), attr.value()));
        }
        if node.has_children() {
            let _ = writer.write_event(Event::Start(start));
            for child in node.children() {
                write_node(writer, child);
            }
            let _ = writer.write_event(Event::End(BytesEnd::new(name)));
        } else {
            let _ = writer.write_event(Event::Empty(start));
        }
    } else if node.is_text() {
        if let Some(text) = node.text() {
            // BytesText::new escapes text content automatically.
            let _ = writer.write_event(Event::Text(BytesText::new(text)));
        }
    }
}

/// Split an `<rpc-reply>` body into per-RE chunks. Returns a single-element
/// vec with `re_name == ""` for standalone devices.
///
/// Contract: if the `<multi-routing-engine-results>` envelope is present but
/// contains zero `<multi-routing-engine-item>` children, this function returns
/// an empty `Vec` (not an error). Callers must treat an empty result as
/// "no nodes responded."
///
/// Input is run through [`sanitize_rustez_xml`] first so that orphan
/// `junos:` namespace attributes and unescaped `&lt;`/`&gt;` in text content
/// (both produced by rustnetconf when it strips the `<nc:rpc-reply>`
/// wrapper) do not abort the parse.
pub fn multi_re_split(reply_xml: &str) -> Result<Vec<ReNode>, crate::SrxError> {
    let cleaned = sanitize_rustez_xml(reply_xml);
    let reply_xml = cleaned.as_ref();
    let doc =
        roxmltree::Document::parse(reply_xml).map_err(|e| crate::SrxError::Parse(e.to_string()))?;

    // Look for a <multi-routing-engine-results> element anywhere in the doc.
    let envelope = doc
        .descendants()
        .find(|n| n.is_element() && n.tag_name().name() == "multi-routing-engine-results");

    let Some(envelope) = envelope else {
        // Standalone device — return the whole reply as a single ReNode.
        return Ok(vec![ReNode {
            re_name: String::new(),
            inner_xml: reply_xml.to_string(),
        }]);
    };

    let mut nodes = Vec::new();
    for item in envelope
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "multi-routing-engine-item")
    {
        let re_name = item
            .children()
            .find(|n| n.is_element() && n.tag_name().name() == "re-name")
            .and_then(|n| n.text())
            .unwrap_or("")
            .trim()
            .to_string();

        // Collect inner XML: all children except the <re-name> element.
        let inner_xml: String = item
            .children()
            .filter(|n| !(n.is_element() && n.tag_name().name() == "re-name"))
            .map(node_to_xml)
            .collect();

        nodes.push(ReNode { re_name, inner_xml });
    }

    Ok(nodes)
}

/// Find the first child element matching `name` and return its inner text,
/// trimmed. Returns `None` if absent.
///
/// Accepts both well-formed XML documents and XML fragments (multiple sibling
/// top-level elements, as produced by `multi_re_split`). Fragments are wrapped
/// in a synthetic root before parsing.
///
/// TODO(post-1B): Only the first text node of a leaf element is returned.
/// Most Junos leaf elements are entity-free single-text-node leaves, so this
/// is sufficient for now. Revisit if a workflow needs concatenated mixed
/// content.
pub fn text_of(xml: &str, name: &str) -> Option<String> {
    // Try parsing as-is first (valid XML doc or single-root fragment).
    // If that fails, wrap in a synthetic root to handle multi-sibling fragments
    // such as those produced by multi_re_split.
    let owned;
    let input = if roxmltree::Document::parse(xml).is_ok() {
        xml
    } else {
        owned = format!("<_>{xml}</_>");
        owned.as_str()
    };
    let doc = roxmltree::Document::parse(input).ok()?;
    doc.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
}

/// Sanitize a raw XML string returned by `rustez`/`rustnetconf` so that
/// `roxmltree` can parse it. Two problems are fixed:
///
/// 1. **Undeclared namespace attributes** (`junos:style="brief"`):
///    rustnetconf strips the `<nc:rpc-reply>` wrapper where `xmlns:junos`
///    was declared, leaving orphan `junos:*` attributes that roxmltree
///    rejects with an unknown-prefix error. These are removed.
/// 2. **Unescaped `<` / `>` in text content**:
///    `rustnetconf::extract_rpc_reply_inner_content` decodes `&lt;`/`&gt;`
///    entity references, so element text like `<sa-direction>&lt;</sa-direction>`
///    becomes `<sa-direction><</sa-direction>` in the returned string.
///    They are re-escaped via a two-pass substitution that preserves XML markup.
///
/// Pure text manipulation — no XML parser is invoked. Returns a `Cow::Borrowed`
/// fast path when neither problem is present.
pub fn sanitize_rustez_xml(xml: &str) -> std::borrow::Cow<'_, str> {
    let needs_ns_strip = xml.contains("junos:");
    let needs_text_escape =
        xml.bytes().any(|b| b == b'<' || b == b'>') && has_bare_angle_brackets_in_text(xml);
    if !needs_ns_strip && !needs_text_escape {
        return std::borrow::Cow::Borrowed(xml);
    }

    let after_ns = if needs_ns_strip {
        simple_strip_junos(xml)
    } else {
        xml.to_string()
    };

    let result = if needs_text_escape {
        escape_text_angle_brackets(&after_ns)
    } else {
        after_ns
    };

    std::borrow::Cow::Owned(result)
}

/// Heuristic: does this string contain `<` or `>` bytes that are not part of
/// legitimate XML markup? Scoped to Junos/rustnetconf output only (does not
/// handle CDATA sections — those do not appear in Junos replies).
fn has_bare_angle_brackets_in_text(xml: &str) -> bool {
    let bytes = xml.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut in_tag = false;

    while i < len {
        let b = bytes[i];
        if in_tag {
            if b == b'>' {
                in_tag = false;
            }
            i += 1;
            continue;
        }
        match b {
            b'<' => {
                let next = if i + 1 < len { bytes[i + 1] } else { 0 };
                let is_tag = next == b'/'
                    || next == b'?'
                    || next == b'!'
                    || next.is_ascii_alphanumeric()
                    || next == b'_';
                if is_tag {
                    in_tag = true;
                } else {
                    return true;
                }
            }
            b'>' => return true,
            _ => {}
        }
        i += 1;
    }
    false
}

/// Re-escape bare `<` / `>` characters that appear in text content of an XML
/// string. Text segments (between `>` and `<`) get `<`/`>` escaped; markup
/// (everything inside `<...>`) is passed through verbatim.
fn escape_text_angle_brackets(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len() + 32);
    let mut rest = xml;

    let mut in_text = !xml.starts_with('<');

    while !rest.is_empty() {
        if in_text {
            if let Some(tag_start) = find_next_tag_start(rest) {
                let text_segment = &rest[..tag_start];
                for ch in text_segment.chars() {
                    match ch {
                        '<' => out.push_str("&lt;"),
                        '>' => out.push_str("&gt;"),
                        other => out.push(other),
                    }
                }
                rest = &rest[tag_start..];
                in_text = false;
            } else {
                for ch in rest.chars() {
                    match ch {
                        '<' => out.push_str("&lt;"),
                        '>' => out.push_str("&gt;"),
                        other => out.push(other),
                    }
                }
                break;
            }
        } else if let Some(tag_end) = rest.find('>') {
            out.push_str(&rest[..=tag_end]);
            rest = &rest[tag_end + 1..];
            in_text = true;
        } else {
            out.push_str(rest);
            break;
        }
    }
    out
}

/// Find the byte offset of the next `<` that opens a legitimate XML tag.
fn find_next_tag_start(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        if bytes[i] == b'<' {
            let next = if i + 1 < len { bytes[i + 1] } else { 0 };
            if next == b'/'
                || next == b'?'
                || next == b'!'
                || next.is_ascii_alphanumeric()
                || next == b'_'
            {
                return Some(i);
            }
        }
        i += 1;
    }
    None
}

/// Strip every `junos:attr="value"` occurrence with leading whitespace.
fn simple_strip_junos(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(pos) = rest.find("junos:") {
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];
        let attr_end = find_attr_end(rest);
        rest = &rest[attr_end..];
        rest = rest.trim_start_matches(' ');
    }
    out.push_str(rest);
    out
}

/// Find the end position of an XML attribute starting at `s`.
fn find_attr_end(s: &str) -> usize {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len && bytes[i] != b'=' {
        i += 1;
    }
    if i >= len {
        return len;
    }
    i += 1;
    if i >= len {
        return len;
    }
    let quote = bytes[i];
    if quote != b'"' && quote != b'\'' {
        while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
            i += 1;
        }
        return i;
    }
    i += 1;
    while i < len && bytes[i] != quote {
        i += 1;
    }
    if i < len {
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_reply_returns_one_node_empty_name() {
        let xml = "<rpc-reply><a><b>x</b></a></rpc-reply>";
        let v = multi_re_split(xml).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].re_name, "");
        assert!(
            v[0].inner_xml.contains("<b>x</b>"),
            "inner_xml={}",
            v[0].inner_xml
        );
    }

    #[test]
    fn multi_re_envelope_yields_per_node() {
        let xml = r#"
<rpc-reply>
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <chassis-cluster-status><cluster-id>1</cluster-id></chassis-cluster-status>
    </multi-routing-engine-item>
    <multi-routing-engine-item>
      <re-name>node1</re-name>
      <chassis-cluster-status><cluster-id>1</cluster-id></chassis-cluster-status>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        let v = multi_re_split(xml).unwrap();
        let names: Vec<_> = v.iter().map(|n| n.re_name.as_str()).collect();
        assert!(names.contains(&"node0"), "names={names:?}");
        assert!(names.contains(&"node1"), "names={names:?}");
    }

    #[test]
    fn text_of_returns_first_match() {
        let xml = "<a><b>hello</b><b>world</b></a>";
        assert_eq!(text_of(xml, "b").as_deref(), Some("hello"));
        assert!(text_of(xml, "missing").is_none());
    }

    #[test]
    fn multi_re_split_preserves_special_chars_in_text_and_attrs() {
        // Junos descriptions and URLs commonly contain & < > " — round-trip
        // through multi_re_split + text_of must not corrupt them.
        let xml = r#"
<rpc-reply>
  <multi-routing-engine-results>
    <multi-routing-engine-item>
      <re-name>node0</re-name>
      <description>a &amp; b &lt; c</description>
      <url attr="x &amp; y">http://example.com?a=1&amp;b=2</url>
    </multi-routing-engine-item>
  </multi-routing-engine-results>
</rpc-reply>"#;
        let v = multi_re_split(xml).unwrap();
        assert_eq!(v.len(), 1);
        let inner = &v[0].inner_xml;
        // text_of must still decode correctly on the round-tripped inner_xml
        assert_eq!(text_of(inner, "description").as_deref(), Some("a & b < c"));
        assert_eq!(
            text_of(inner, "url").as_deref(),
            Some("http://example.com?a=1&b=2")
        );
    }

    #[test]
    fn multi_re_envelope_with_no_items_yields_empty_vec() {
        // Document the contract: envelope present but with zero items
        // is intentionally an empty result vec, not an error. Callers must
        // treat empty as "no nodes responded."
        let xml = r#"<rpc-reply><multi-routing-engine-results></multi-routing-engine-results></rpc-reply>"#;
        let v = multi_re_split(xml).unwrap();
        assert!(v.is_empty());
    }
}
