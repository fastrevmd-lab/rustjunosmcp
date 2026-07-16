//! Command-line arguments. Two top-level modes: serve (default) and token
//! management subcommand.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Transport {
    Stdio,
    StreamableHttp,
}

#[derive(Debug, Parser)]
#[command(name = "rust-junosmcp", version, about = "Junos MCP server (Rust)")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// JSON file with device mapping (Juniper junos-mcp-server compatible).
    #[arg(short = 'f', long, default_value = "devices.json", global = true)]
    pub device_mapping: PathBuf,

    /// Transport.
    #[arg(short = 't', long, default_value = "stdio", value_enum)]
    pub transport: Transport,

    /// Bind host (streamable-http only).
    #[arg(short = 'H', long, default_value = "127.0.0.1")]
    pub host: String,

    /// Bind port (streamable-http only).
    #[arg(short = 'p', long, default_value_t = 30030)]
    pub port: u16,

    /// Bearer-token file. Required for streamable-http unless --allow-no-auth.
    #[arg(long)]
    pub tokens_file: Option<PathBuf>,

    /// PEM-encoded TLS cert (streamable-http only). Pair with --tls-key.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// PEM-encoded TLS key (streamable-http only). Pair with --tls-cert.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Disable bearer-token auth. Refuses to bind off-loopback.
    #[arg(long)]
    pub allow_no_auth: bool,

    /// Bind off-loopback over plain HTTP. Required for non-127.0.0.1 hosts when TLS is not configured.
    #[arg(long)]
    pub allow_insecure_bind: bool,

    /// Reject add_device and reload_devices unconditionally.
    /// Independent of token scopes.
    #[arg(long)]
    pub inventory_readonly: bool,

    /// Permit add_device to accept auth.type="password".
    /// Off by default. Mutually exclusive with --inventory-readonly.
    #[arg(long)]
    pub allow_password_auth_add: bool,

    /// Directory used to stage files before scp push (transfer_file).
    #[arg(long, default_value = "/var/lib/jmcp/staging")]
    pub staging_dir: PathBuf,

    /// SSH known_hosts file used for scp pushes (transfer_file).
    #[arg(long, default_value = "/etc/jmcp/known_hosts")]
    pub known_hosts_file: PathBuf,

    /// Shared directory for cross-process destructive-operation leases.
    #[arg(long, default_value = "/var/lib/jmcp/device-leases")]
    pub device_lease_dir: PathBuf,

    /// Accept and pin new device host keys on first contact (TOFU,
    /// `StrictHostKeyChecking=accept-new`). Off by default — the server
    /// uses `StrictHostKeyChecking=yes` and requires a pre-populated
    /// `known_hosts` (see scripts/scan-known-hosts.sh). Lab-only.
    #[arg(long)]
    pub ssh_accept_new_host_keys: bool,

    /// Additional Host authorities to accept on the streamable-http endpoint,
    /// beyond the loopback defaults (localhost, 127.0.0.1, ::1). Repeatable.
    /// Set this to the host/authority clients actually send (e.g. the LAN IP)
    /// or off-loopback clients are rejected with HTTP 403 (DNS-rebinding guard).
    #[arg(long)]
    pub allowed_host: Vec<String>,

    /// Disable the streamable-http Host allowlist entirely (accept any Host).
    /// Reintroduces the RUSTSEC-2026-0189 exposure; bearer auth still applies.
    /// Off by default.
    #[arg(long)]
    pub disable_host_check: bool,

    /// Expose unauthenticated Prometheus metrics at /metrics (streamable-http only).
    #[arg(long, env = "JMCP_ENABLE_METRICS")]
    pub enable_metrics: bool,

    /// Max request body bytes before HTTP 413 (streamable-http). 0 = unlimited.
    #[arg(long, env = "JMCP_MAX_REQUEST_BODY_BYTES", default_value_t = 10 * 1024 * 1024)]
    pub max_request_body_bytes: usize,

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, env = "JMCP_MAX_INFLIGHT_REQUESTS", default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(
        long,
        env = "JMCP_MAX_INFLIGHT_REQUESTS_PER_TOKEN",
        default_value_t = 16
    )]
    pub max_inflight_requests_per_token: usize,

    /// Max requests per second per bearer token. Set with burst; 0/0 = disabled.
    #[arg(
        long,
        env = "JMCP_MAX_REQUESTS_PER_SECOND_PER_TOKEN",
        default_value_t = 0
    )]
    pub max_requests_per_second_per_token: u64,

    /// Max immediate request burst per bearer token. Set with rate; 0/0 = disabled.
    #[arg(long, env = "JMCP_MAX_REQUEST_BURST_PER_TOKEN", default_value_t = 0)]
    pub max_request_burst_per_token: u64,

    /// Max concurrent in-flight requests per target router. 0 = unlimited.
    #[arg(
        long,
        env = "JMCP_MAX_INFLIGHT_REQUESTS_PER_ROUTER",
        default_value_t = 4
    )]
    pub max_inflight_requests_per_router: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, env = "JMCP_MAX_SESSIONS", default_value_t = 128)]
    pub max_sessions: usize,

    /// Max concurrent MCP sessions per bearer token. 0 = unlimited.
    #[arg(long, env = "JMCP_MAX_SESSIONS_PER_TOKEN", default_value_t = 16)]
    pub max_sessions_per_token: usize,

    /// Session idle timeout in seconds. 0 = disabled.
    #[arg(long, env = "JMCP_SESSION_IDLE_TIMEOUT_SECS", default_value_t = 300)]
    pub session_idle_timeout_secs: u64,

    /// Session max lifetime in seconds. 0 = disabled.
    #[arg(long, env = "JMCP_SESSION_MAX_LIFETIME_SECS", default_value_t = 3600)]
    pub session_max_lifetime_secs: u64,

    /// Audit/log output format for stderr: text or json.
    #[arg(long, env = "JMCP_AUDIT_FORMAT", default_value = "text")]
    pub audit_format: String,

    /// Optional file to append JSON audit lines to (in addition to stderr).
    #[arg(long, env = "JMCP_AUDIT_LOG_FILE")]
    pub audit_log_file: Option<std::path::PathBuf>,

    /// Also send structured audit events directly to journald.
    #[arg(long, env = "JMCP_AUDIT_JOURNALD")]
    pub audit_journald: bool,

    /// Per-field audit redaction, e.g. `routers=hmac,host=drop`.
    /// Fields: routers, host, name, basename, command, pfe_command.
    /// Transforms: keep, drop, hmac. Empty = disabled.
    #[arg(long, env = "JMCP_AUDIT_REDACT", default_value = "")]
    pub audit_redact: String,

    /// File containing the HMAC key used by any `=hmac` redaction. Required
    /// when audit-redact requests hmac. Path only; the key is never a flag/env value.
    #[arg(long, env = "JMCP_AUDIT_HMAC_KEY_FILE")]
    pub audit_hmac_key_file: Option<std::path::PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Manage the bearer-token store.
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenAction {
    /// Mint a new token and append to the file.
    Add {
        #[arg(long)]
        tokens_file: PathBuf,
        #[arg(long)]
        name: String,
        /// Comma-separated router names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        routers: Vec<String>,
        /// Comma-separated tool names, or '*' for all.
        #[arg(long, value_delimiter = ',')]
        tools: Vec<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// List token names + scopes (never the hash or secret).
    List {
        #[arg(long)]
        tokens_file: PathBuf,
    },
    /// Remove a token by name.
    Revoke {
        #[arg(long)]
        tokens_file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        server_pid: Option<i32>,
    },
    /// Revoke + re-add under the same scopes; prints a new secret.
    Rotate {
        #[arg(long)]
        tokens_file: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn defaults() {
        let cli = Cli::parse_from(["rust-junosmcp"]);
        assert_eq!(cli.device_mapping, PathBuf::from("devices.json"));
        assert_eq!(cli.transport, Transport::Stdio);
        assert_eq!(cli.host, "127.0.0.1");
        assert_eq!(cli.port, 30030);
        assert!(cli.command.is_none());
        assert!(cli.tokens_file.is_none());
        assert!(!cli.allow_no_auth);
        assert!(!cli.allow_insecure_bind);
        assert!(!cli.enable_metrics);
        assert_eq!(cli.max_sessions_per_token, 16);

        let metrics = Cli::parse_from(["rust-junosmcp", "--enable-metrics"]);
        assert!(metrics.enable_metrics);

        let disabled = Cli::parse_from(["rust-junosmcp", "--max-sessions-per-token", "0"]);
        assert_eq!(disabled.max_sessions_per_token, 0);

        let custom = Cli::parse_from(["rust-junosmcp", "--max-sessions-per-token", "9"]);
        assert_eq!(custom.max_sessions_per_token, 9);
    }

    #[test]
    fn per_router_limit_defaults_and_parses() {
        let default_cli = Cli::parse_from(["rust-junosmcp"]);
        assert_eq!(default_cli.max_inflight_requests_per_router, 4);

        let disabled =
            Cli::parse_from(["rust-junosmcp", "--max-inflight-requests-per-router", "0"]);
        assert_eq!(disabled.max_inflight_requests_per_router, 0);

        let custom = Cli::parse_from(["rust-junosmcp", "--max-inflight-requests-per-router", "7"]);
        assert_eq!(custom.max_inflight_requests_per_router, 7);
    }

    #[test]
    fn per_token_rate_limit_defaults_and_parses() {
        let default_cli = Cli::parse_from(["rust-junosmcp"]);
        assert_eq!(default_cli.max_requests_per_second_per_token, 0);
        assert_eq!(default_cli.max_request_burst_per_token, 0);

        let custom = Cli::parse_from([
            "rust-junosmcp",
            "--max-requests-per-second-per-token",
            "7",
            "--max-request-burst-per-token",
            "11",
        ]);
        assert_eq!(custom.max_requests_per_second_per_token, 7);
        assert_eq!(custom.max_request_burst_per_token, 11);
    }

    #[test]
    fn parses_short_flags() {
        let cli = Cli::parse_from(["rust-junosmcp", "-f", "/etc/jmcp/d.json"]);
        assert_eq!(cli.device_mapping, PathBuf::from("/etc/jmcp/d.json"));
    }

    #[test]
    fn parses_streamable_http_value() {
        let cli = Cli::parse_from(["rust-junosmcp", "-t", "streamable-http"]);
        assert_eq!(cli.transport, Transport::StreamableHttp);
    }

    #[test]
    fn inventory_flags_off_by_default() {
        let cli = Cli::parse_from(["rust-junosmcp"]);
        assert!(!cli.inventory_readonly);
        assert!(!cli.allow_password_auth_add);
    }

    #[test]
    fn ssh_accept_new_host_keys_off_by_default() {
        let cli = Cli::parse_from(["rust-junosmcp"]);
        assert!(!cli.ssh_accept_new_host_keys);
    }

    #[test]
    fn ssh_accept_new_host_keys_parses_when_set() {
        let cli = Cli::parse_from(["rust-junosmcp", "--ssh-accept-new-host-keys"]);
        assert!(cli.ssh_accept_new_host_keys);
    }

    #[test]
    fn defaults_for_transfer_paths() {
        let cli = Cli::parse_from(["rust-junosmcp"]);
        assert_eq!(
            cli.staging_dir,
            std::path::PathBuf::from("/var/lib/jmcp/staging")
        );
        assert_eq!(
            cli.known_hosts_file,
            std::path::PathBuf::from("/etc/jmcp/known_hosts")
        );
        assert_eq!(
            cli.device_lease_dir,
            std::path::PathBuf::from("/var/lib/jmcp/device-leases")
        );
    }

    #[test]
    fn parses_custom_transfer_paths() {
        let cli = Cli::parse_from([
            "rust-junosmcp",
            "--staging-dir",
            "/tmp/staging",
            "--known-hosts-file",
            "/tmp/khosts",
        ]);
        assert_eq!(cli.staging_dir, std::path::PathBuf::from("/tmp/staging"));
        assert_eq!(
            cli.known_hosts_file,
            std::path::PathBuf::from("/tmp/khosts")
        );
    }

    #[test]
    fn parses_token_add_subcommand() {
        let cli = Cli::parse_from([
            "rust-junosmcp",
            "token",
            "add",
            "--tokens-file",
            "/tmp/t.json",
            "--name",
            "alice",
            "--routers",
            "*",
            "--tools",
            "*",
        ]);
        assert!(matches!(cli.command, Some(Command::Token { .. })));
    }

    #[test]
    fn audit_journald_defaults_off_and_parses() {
        let default_cli = Cli::parse_from(["rust-junosmcp"]);
        assert!(!default_cli.audit_journald);

        let enabled = Cli::parse_from(["rust-junosmcp", "--audit-journald"]);
        assert!(enabled.audit_journald);
    }
}
