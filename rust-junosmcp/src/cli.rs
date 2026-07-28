//! Command-line arguments. Two top-level modes: serve (default) and token
//! management subcommand.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

// Re-export from mecmcp-runtime for compatibility
pub use mecmcp_runtime::cli::Transport;

#[derive(Debug, Parser)]
#[cfg_attr(
    feature = "srx",
    command(
        name = "rust-junosmcp",
        version,
        about = "Junos and SRX MCP server (Rust)"
    )
)]
#[cfg_attr(
    not(feature = "srx"),
    command(name = "rust-junosmcp", version, about = "Junos MCP server (Rust)")
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    /// JSON file with device mapping (Juniper junos-mcp-server compatible).
    #[arg(
        short = 'f',
        long,
        default_value = "devices.json",
        global = true,
        alias = "device-mapping"
    )]
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

    /// Additional Host authorities to accept on the streamable-http endpoint,
    /// beyond the loopback defaults (localhost, 127.0.0.1, ::1). Repeatable.
    /// Set this to the host/authority clients actually send (e.g. the LAN IP)
    /// or off-loopback clients are rejected with HTTP 403 (DNS-rebinding guard).
    #[arg(long)]
    pub allowed_host: Vec<String>,

    /// Accepted browser Origin URL. Repeat for multiple values.
    #[arg(long)]
    pub allowed_origin: Vec<String>,

    /// Audit/log output format for stderr: text or json.
    #[arg(long, default_value = "text")]
    pub audit_format: String,

    /// Optional file to append JSON audit lines to (in addition to stderr).
    #[arg(long)]
    pub audit_log_file: Option<PathBuf>,

    /// Also send structured audit events directly to journald.
    #[arg(long)]
    pub audit_journald: bool,

    /// Per-field audit redaction, e.g. `devices=hmac,host=drop`.
    /// Fields: devices, host, name, basename, command, pfe_command.
    /// Transforms: keep, drop, hmac. Empty = disabled.
    #[arg(long, default_value = "")]
    pub audit_redact: String,

    /// File containing the HMAC key used by any `=hmac` redaction. Required
    /// when audit-redact requests hmac. Path only; the key is never a flag/env value.
    #[arg(long)]
    pub audit_hmac_key_file: Option<PathBuf>,

    // Junos-specific flags below
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

    /// Change-set lifecycle state file for two-person approval workflow.
    #[arg(long, default_value = "/var/lib/jmcp/changeset-state.json")]
    pub changeset_state_file: PathBuf,

    /// Change-set approval timeout in seconds. After this window, unapproved
    /// change sets expire and cannot be applied.
    #[arg(long, default_value_t = 3600)]
    pub changeset_approval_timeout_secs: u64,

    /// Enable lab mode for change-set workflow: allows single-operator
    /// waiver instead of requiring a second principal to approve.
    #[arg(long)]
    pub changeset_lab_mode: bool,

    /// Directory used to stage collected SRX support bundles.
    #[cfg(feature = "srx")]
    #[arg(
        long,
        default_value =
            rust_junosmcp_srx_core::workflows::support_bundle::DEFAULT_STAGING_DIR
    )]
    pub support_bundle_staging_dir: PathBuf,

    /// Maximum bytes retained in the SRX support-bundle staging area.
    #[cfg(feature = "srx")]
    #[arg(
        long,
        default_value_t =
            rust_junosmcp_srx_core::workflows::support_bundle::DEFAULT_STAGING_MAX_BYTES
    )]
    pub support_bundle_staging_max_bytes: u64,

    /// Accept and pin new device host keys on first contact (TOFU,
    /// `StrictHostKeyChecking=accept-new`). Off by default — the server
    /// uses `StrictHostKeyChecking=yes` and requires a pre-populated
    /// `known_hosts` (see scripts/scan-known-hosts.sh). Lab-only.
    #[arg(long)]
    pub ssh_accept_new_host_keys: bool,

    /// Disable the streamable-http Host allowlist entirely (accept any Host).
    /// Reintroduces the RUSTSEC-2026-0189 exposure; bearer auth still applies.
    /// Off by default.
    #[arg(long)]
    pub disable_host_check: bool,

    /// Expose unauthenticated Prometheus metrics at /metrics (streamable-http only).
    #[arg(long)]
    pub enable_metrics: bool,

    /// Max request body bytes before HTTP 413 (streamable-http). 0 = unlimited.
    #[arg(long, default_value_t = 10 * 1024 * 1024)]
    pub max_request_body_bytes: usize,

    /// Max concurrent in-flight requests across all callers. 0 = unlimited.
    #[arg(long, default_value_t = 64)]
    pub max_inflight_requests: usize,

    /// Max concurrent in-flight requests per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_inflight_requests_per_token: usize,

    /// Max requests per second per source IP address. Set with burst; 0/0 = disabled.
    #[arg(long, default_value_t = 0)]
    pub max_requests_per_second_per_ip: u64,

    /// Max immediate request burst per source IP address. Set with rate; 0/0 = disabled.
    #[arg(long, default_value_t = 0)]
    pub max_request_burst_per_ip: u64,

    /// Max requests per second per bearer token. Set with burst; 0/0 = disabled.
    #[arg(long, default_value_t = 0)]
    pub max_requests_per_second_per_token: u64,

    /// Max immediate request burst per bearer token. Set with rate; 0/0 = disabled.
    #[arg(long, default_value_t = 0)]
    pub max_request_burst_per_token: u64,

    /// Max concurrent in-flight requests per target router. 0 = unlimited.
    #[arg(long, default_value_t = 4)]
    pub max_inflight_requests_per_router: usize,

    /// Max concurrent MCP sessions. 0 = unlimited.
    #[arg(long, default_value_t = 128)]
    pub max_sessions: usize,

    /// Max concurrent MCP sessions per bearer token. 0 = unlimited.
    #[arg(long, default_value_t = 16)]
    pub max_sessions_per_token: usize,

    /// Session idle timeout in seconds. 0 = disabled.
    #[arg(long, default_value_t = 300)]
    pub session_idle_timeout_secs: u64,

    /// Session max lifetime in seconds. 0 = disabled.
    #[arg(long, default_value_t = 3600)]
    pub session_max_lifetime_secs: u64,
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
        /// Comma-separated device names, or '*' for all.
        #[arg(long, alias = "routers", value_delimiter = ',')]
        devices: Vec<String>,
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
    /// Change an existing token's scopes without reissuing its secret.
    SetScope {
        #[arg(long)]
        tokens_file: PathBuf,
        #[arg(long)]
        name: String,
        /// Comma-separated device names, or '*' for all. Omit to leave unchanged.
        #[arg(long, alias = "routers", value_delimiter = ',')]
        devices: Option<Vec<String>>,
        /// Comma-separated tool names, or '*' for all. Omit to leave unchanged.
        #[arg(long, value_delimiter = ',')]
        tools: Option<Vec<String>>,
        #[arg(long)]
        server_pid: Option<i32>,
    },
}

#[cfg(test)]
mod tests {

    /// The two junos-only CLI rules that cannot live in `mecmcp-runtime`,
    /// because the shared `Cli` struct has no fields for these flags.
    ///
    /// The Phase 3b migration moved `cli_validate.rs` upstream and dropped the
    /// inventory rule on the way: the binary accepted `--inventory-readonly`
    /// together with `--allow-password-auth-add` while the doc comment on the
    /// latter still promised they were mutually exclusive. Asserting on the
    /// parsed flags here keeps the pair coupled to something that fails.
    #[test]
    fn junos_only_cli_rules_are_still_reachable() {
        // Both flags parse, so the refusal has to come from main's vendor block
        // rather than from clap — which is exactly why it was droppable.
        let both = Cli::parse_from([
            "rust-junosmcp",
            "--inventory-readonly",
            "--allow-password-auth-add",
        ]);
        assert!(
            both.inventory_readonly && both.allow_password_auth_add,
            "both flags must remain parseable; the mutual exclusion is enforced \
             in main.rs, not by clap"
        );

        let metrics_stdio = Cli::parse_from(["rust-junosmcp", "-t", "stdio", "--enable-metrics"]);
        assert!(
            metrics_stdio.enable_metrics && metrics_stdio.transport == Transport::Stdio,
            "the metrics/stdio combination must remain parseable for the same reason"
        );
    }

    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn help_describes_the_compiled_feature_surface() {
        let about = Cli::command().get_about().unwrap().to_string();
        #[cfg(feature = "srx")]
        assert!(about.contains("Junos and SRX"), "about: {about}");
        #[cfg(not(feature = "srx"))]
        assert!(
            about.contains("Junos") && !about.contains("SRX"),
            "about: {about}"
        );
    }

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
    fn parses_token_add_subcommand_with_devices() {
        let cli = Cli::parse_from([
            "rust-junosmcp",
            "token",
            "add",
            "--tokens-file",
            "/tmp/t.json",
            "--name",
            "alice",
            "--devices",
            "*",
            "--tools",
            "*",
        ]);
        assert!(matches!(cli.command, Some(Command::Token { .. })));
    }

    #[test]
    fn parses_token_add_subcommand_with_routers_alias() {
        // --routers is a hidden alias for --devices (mecmcp #29, plan D2)
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

    /// Test that the examples embedded in help text are valid. Prevents
    /// drift between documentation and validation, which caused #217.
    #[test]
    fn help_text_examples_are_valid() {
        // Extract help text.
        let help = Cli::command().render_help().to_string();

        // --audit-redact: extract the example from its doc comment.
        // Format: "Per-field audit redaction, e.g. `devices=hmac,host=drop`."
        let audit_redact_example = help
            .lines()
            .find_map(|line| {
                if line.contains("Per-field audit redaction") {
                    // Extract content between backticks.
                    line.split('`').nth(1)
                } else {
                    None
                }
            })
            .expect("--audit-redact help text should contain an example in backticks");

        // Feed the documented example to the REAL validator.
        //
        // An earlier version of this test called `Cli::parse_from` and asserted
        // the string round-tripped, then compared it to a hardcoded copy of the
        // expected example. That could not catch the bug it was written for:
        // clap does no validation of `--audit-redact`, so the test passed just
        // as happily with the invalid `routers=hmac` that shipped in v0.11.0.
        // And a hardcoded copy of the example is a second source of truth,
        // free to drift exactly the way the first one did.
        //
        // `mecmcp-audit` is already a dependency of this crate — main.rs calls
        // this same function — so the real validator is directly reachable.
        let key_dir = tempfile::tempdir().expect("tempdir");
        let key_path = key_dir.path().join("hmac.key");
        std::fs::write(&key_path, b"0123456789abcdef0123456789abcdef").expect("write key");

        mecmcp_audit::AuditRedaction::parse(audit_redact_example, Some(&key_path)).unwrap_or_else(
            |error| {
                panic!(
                    "the --audit-redact example in --help does not validate: \
                     {audit_redact_example:?} rejected by the real parser: {error}. \
                     Fix the doc comment on the flag, not this test."
                )
            },
        );
    }
}
