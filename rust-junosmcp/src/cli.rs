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
        #[arg(long)] tokens_file: PathBuf,
        #[arg(long)] name: String,
        /// Comma-separated router names, or '*' for all.
        #[arg(long, value_delimiter = ',')] routers: Vec<String>,
        /// Comma-separated tool names, or '*' for all.
        #[arg(long, value_delimiter = ',')] tools: Vec<String>,
        /// Send SIGHUP to this pid after writing.
        #[arg(long)] server_pid: Option<i32>,
    },
    /// List token names + scopes (never the hash or secret).
    List {
        #[arg(long)] tokens_file: PathBuf,
    },
    /// Remove a token by name.
    Revoke {
        #[arg(long)] tokens_file: PathBuf,
        #[arg(long)] name: String,
        #[arg(long)] server_pid: Option<i32>,
    },
    /// Revoke + re-add under the same scopes; prints a new secret.
    Rotate {
        #[arg(long)] tokens_file: PathBuf,
        #[arg(long)] name: String,
        #[arg(long)] server_pid: Option<i32>,
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
    fn parses_token_add_subcommand() {
        let cli = Cli::parse_from([
            "rust-junosmcp", "token", "add",
            "--tokens-file", "/tmp/t.json",
            "--name", "alice",
            "--routers", "*",
            "--tools", "*",
        ]);
        assert!(matches!(cli.command, Some(Command::Token { .. })));
    }
}
