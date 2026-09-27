//! Shared subtree-filtered `get-configuration` helper.
//!
//! `rustez::rpc::RpcExecutor::call()` only supports flat key/value child
//! elements — no nested XML — so a subtree filter needs the RPC envelope
//! built by hand, the same technique `support_bundle::collect_per_type`
//! already uses for its per-problem-type RPCs that take inner args.

use crate::SrxError;

/// Send `<get-configuration><configuration>{filter_inner}</configuration></get-configuration>`
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
    let envelope = format!(
        "<get-configuration><configuration>{filter_inner}</configuration></get-configuration>"
    );
    exec.call_xml(&envelope)
        .await
        .map_err(|e| SrxError::Transport(rust_junosmcp_core::JmcpError::from(e)))
}
