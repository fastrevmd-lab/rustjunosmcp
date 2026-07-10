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
