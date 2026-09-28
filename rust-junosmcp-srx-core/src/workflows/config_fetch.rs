//! Shared subtree-filtered `get-configuration` helper.
//!
//! `rustez::rpc::RpcExecutor::call()` only supports flat key/value child
//! elements — no nested XML — so a subtree filter needs the RPC envelope
//! built by hand, the same technique `support_bundle::collect_per_type`
//! already uses for its per-problem-type RPCs that take inner args.

use crate::SrxError;

/// Build the `<get-configuration inherit="inherit"><configuration>{filter_inner}</configuration></get-configuration>`
/// envelope. Pure, unit-testable.
///
/// `inherit="inherit"` is required — without it Junos returns the config
/// exactly as written, so any NAT rule-set, address-book entry, or
/// application that is inherited from an `apply-groups` reference is
/// invisible to every tool built on `get_configuration_subtree`, and the
/// tool reports the object as absent when it is really just inherited
/// (Percy H1, MEC-83).
pub(crate) fn get_configuration_envelope(filter_inner: &str) -> String {
    format!(
        "<get-configuration inherit=\"inherit\"><configuration>{filter_inner}</configuration></get-configuration>"
    )
}

/// Send `<get-configuration inherit="inherit"><configuration>{filter_inner}</configuration></get-configuration>`
/// and return the raw reply body.
///
/// `filter_inner` is the subtree filter content, e.g.
/// `"<security><address-book/></security>"`. `call_xml` does not mark the
/// candidate datastore dirty, which is correct here — `get-configuration`
/// with no explicit target reads `<running/>`.
pub(crate) async fn get_configuration_subtree(
    exec: &mut rustez::rpc::RpcExecutor<'_>,
    filter_inner: &str,
) -> Result<String, SrxError> {
    let envelope = get_configuration_envelope(filter_inner);
    exec.call_xml(&envelope)
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_carries_inherit_attribute() {
        let xml = get_configuration_envelope("<security><nat/></security>");
        assert!(
            xml.starts_with("<get-configuration inherit=\"inherit\">"),
            "envelope must request inherited (apply-groups) config, got: {xml}"
        );
        assert!(xml.contains("<security><nat/></security>"));
    }
}
