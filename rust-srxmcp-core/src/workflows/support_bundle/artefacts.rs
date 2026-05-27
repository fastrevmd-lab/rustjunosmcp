//! Per-artefact capture types for `collect_jtac_support_bundle`. An
//! "artefact" is a single piece of evidence in the bundle: either an RPC
//! reply XML or a log file fetched via scp.
//!
//! Each [`CapturedArtefact`] carries enough metadata that the orchestrator
//! can build the on-device tarball manifest and the LXC-side sidecar JSON
//! without re-parsing the payloads.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Origin of a captured artefact. RPC replies carry the RPC name; log
/// files carry the device path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtefactSource {
    /// NETCONF RPC reply (e.g. `get-configuration`). The inner string is
    /// the RPC element name. When the RPC carried inner XML args, the
    /// args are recorded in `args` for replay.
    Rpc { name: String, args: Option<String> },
    /// Log file pulled via scp from the device. Inner string is the
    /// device-side absolute path (e.g. `/var/log/messages`).
    LogFile { device_path: String },
}

/// A single artefact captured during bundle assembly. `bytes_in_tarball`
/// is the post-redact byte count of what actually lands in the tarball
/// (so `redact=true` runs are accurately accounted for).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct CapturedArtefact {
    pub source: ArtefactSource,
    /// File name inside the tarball (relative path, no leading `/`).
    /// Example: `rpc/get-configuration.xml`, `logs/messages`.
    pub tarball_path: String,
    /// SHA-256 hex of the post-redact payload (lower-case, no prefix).
    pub sha256: String,
    pub bytes_in_tarball: u64,
    /// `true` if redact rules matched and at least one element was
    /// replaced. `false` for log files (redaction is RPC-XML-only in v0.3.0).
    pub redacted: bool,
    /// Per-artefact error capture so a single missing log doesn't abort
    /// the whole bundle. `None` on success.
    pub error: Option<String>,
}
