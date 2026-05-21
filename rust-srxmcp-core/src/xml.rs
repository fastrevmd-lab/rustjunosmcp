//! XML helpers shared across SRX workflows. Uses roxmltree for a clean DOM
//! API that keeps every tool out of the multi-RE envelope business.

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

/// Serialize a roxmltree node and all its children back to an XML string.
fn node_to_xml(node: roxmltree::Node<'_, '_>) -> String {
    if node.is_text() {
        return node.text().unwrap_or("").to_string();
    }
    if !node.is_element() {
        return String::new();
    }
    let tag = node.tag_name().name();
    let mut out = format!("<{tag}");
    for attr in node.attributes() {
        out.push_str(&format!(" {}=\"{}\"", attr.name(), attr.value()));
    }
    let children: String = node.children().map(node_to_xml).collect();
    if children.is_empty() {
        out.push_str("/>");
    } else {
        out.push('>');
        out.push_str(&children);
        out.push_str(&format!("</{tag}>"));
    }
    out
}

/// Split an `<rpc-reply>` body into per-RE chunks. Returns a single-element
/// vec with `re_name == ""` for standalone devices.
pub fn multi_re_split(reply_xml: &str) -> Result<Vec<ReNode>, crate::SrxError> {
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
pub fn text_of(xml: &str, name: &str) -> Option<String> {
    let doc = roxmltree::Document::parse(xml).ok()?;
    doc.descendants()
        .find(|n| n.is_element() && n.tag_name().name() == name)
        .and_then(|n| n.text())
        .map(|s| s.trim().to_string())
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
}
