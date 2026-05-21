//! Error taxonomy for SRX workflows.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SrxError {
    #[error("transport: {0}")]
    Transport(#[from] rust_junosmcp_core::JmcpError),

    #[error("rpc error: {tag} ({severity}) — {message}")]
    Rpc {
        tag: String,
        severity: String,
        message: String,
    },

    #[error("xml parse: {0}")]
    Parse(String),

    #[error("schema mismatch in {rpc}: missing required element <{element}>")]
    SchemaMismatch {
        rpc: &'static str,
        element: &'static str,
    },

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

impl SrxError {
    /// Convenience builder used by per-tool parsers.
    pub fn schema_mismatch(rpc: &'static str, element: &'static str) -> Self {
        Self::SchemaMismatch { rpc, element }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_mismatch_displays_rpc_and_element() {
        let e = SrxError::schema_mismatch("get-chassis-cluster-status-information", "cluster-id");
        let s = e.to_string();
        assert!(s.contains("get-chassis-cluster-status-information"), "{s}");
        assert!(s.contains("cluster-id"), "{s}");
    }

    #[test]
    fn rpc_variant_includes_tag_and_message() {
        let e = SrxError::Rpc {
            tag: "data-missing".into(),
            severity: "error".into(),
            message: "configuration database empty".into(),
        };
        let s = e.to_string();
        assert!(s.contains("data-missing"));
        assert!(s.contains("configuration database empty"));
    }
}
