//! Command-line arguments for the SRX HTTP endpoint.

use clap::Parser;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "rust-srxmcp",
    version,
    about = "Juniper SRX-specific MCP server."
)]
pub struct Cli {
    /// HTTP bind host.
    #[arg(long, default_value = "127.0.0.1", env = "JMCP_SRX_HTTP_HOST")]
    pub host: String,

    /// HTTP bind port.
    #[arg(long, default_value_t = 30032, env = "JMCP_SRX_HTTP_PORT")]
    pub port: u16,

    /// Bearer-token file (shared with rust-junosmcp).
    #[arg(long, env = "JMCP_TOKENS_PATH")]
    pub tokens_file: Option<PathBuf>,

    /// Devices file required for NETCONF tools and token-scope validation.
    #[arg(long, env = "JMCP_DEVICES_PATH")]
    pub device_mapping: Option<PathBuf>,

    /// PEM-encoded TLS certificate. Must be paired with --tls-key.
    #[arg(long, env = "JMCP_SRX_TLS_CERT")]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS private key. Must be paired with --tls-cert.
    #[arg(long, env = "JMCP_SRX_TLS_KEY")]
    pub tls_key: Option<PathBuf>,

    /// Allow unauthenticated requests on a loopback bind only (lab use).
    #[arg(long)]
    pub allow_no_auth: bool,

    /// Permit a non-loopback bind over plaintext HTTP. Use only behind a
    /// trusted TLS-terminating proxy or equivalent transport protection.
    #[arg(long)]
    pub allow_insecure_bind: bool,

    /// Accept unknown SSH host keys on first contact (TOFU; lab only).
    #[arg(long)]
    pub ssh_accept_new_host_keys: bool,

    /// Path to the SSH known_hosts file for NETCONF strict host-key checking.
    #[arg(long, default_value = "/etc/jmcp/known_hosts")]
    pub known_hosts_file: PathBuf,

    /// Shared directory for cross-process destructive-operation leases.
    #[arg(
        long,
        default_value = "/var/lib/jmcp/device-leases",
        env = "JMCP_DEVICE_LEASE_DIR"
    )]
    pub device_lease_dir: PathBuf,

    /// Additional Host authorities accepted by streamable HTTP, beyond the
    /// loopback defaults. Repeat for each expected host or authority.
    #[arg(long)]
    pub allowed_host: Vec<String>,

    /// Disable the Host allowlist. Reintroduces RUSTSEC-2026-0189 exposure;
    /// bearer authentication and TLS policy remain independent.
    #[arg(long)]
    pub disable_host_check: bool,

    /// Max request body bytes before HTTP 413 (streamable-http). 0 = unlimited.
    #[arg(long, env = "JMCP_SRX_MAX_REQUEST_BODY_BYTES", default_value_t = 10 * 1024 * 1024)]
    pub max_request_body_bytes: usize,

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, env = "JMCP_SRX_MAX_INFLIGHT_REQUESTS", default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(
        long,
        env = "JMCP_SRX_MAX_INFLIGHT_REQUESTS_PER_TOKEN",
        default_value_t = 16
    )]
    pub max_inflight_requests_per_token: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, env = "JMCP_SRX_MAX_SESSIONS", default_value_t = 128)]
    pub max_sessions: usize,

    /// Session idle timeout in seconds. 0 = disabled.
    #[arg(
        long,
        env = "JMCP_SRX_SESSION_IDLE_TIMEOUT_SECS",
        default_value_t = 300
    )]
    pub session_idle_timeout_secs: u64,

    /// Session max lifetime in seconds. 0 = disabled.
    #[arg(
        long,
        env = "JMCP_SRX_SESSION_MAX_LIFETIME_SECS",
        default_value_t = 3600
    )]
    pub session_max_lifetime_secs: u64,

    /// Audit/log output format for stderr: text or json.
    #[arg(long, env = "JMCP_SRX_AUDIT_FORMAT", default_value = "text")]
    pub audit_format: String,

    /// Optional file to append JSON audit lines to (in addition to stderr).
    #[arg(long, env = "JMCP_SRX_AUDIT_LOG_FILE")]
    pub audit_log_file: Option<std::path::PathBuf>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_defaults() {
        let cli = Cli::parse_from(["rust-srxmcp"]);
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 30032);
        assert!(cli.tokens_file.is_none());
        assert!(cli.tls_cert.is_none());
        assert!(cli.tls_key.is_none());
        assert!(!cli.allow_no_auth);
        assert!(!cli.allow_insecure_bind);
        assert_eq!(
            cli.device_lease_dir,
            std::path::PathBuf::from("/var/lib/jmcp/device-leases")
        );
    }
}
