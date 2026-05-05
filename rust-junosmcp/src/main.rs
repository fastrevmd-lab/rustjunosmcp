mod auth_layer;
mod caller;
mod cli;
mod cli_validate;
mod http_transport;
mod server;
mod token_cmd;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command, Transport};
use rmcp::ServiceExt;
use rust_junosmcp_auth::file::TokenStoreFile;
use rust_junosmcp_core::{DeviceManager, Inventory, Policy};
use server::JmcpHandler;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args = Cli::parse();

    if let Some(Command::Token { action }) = args.command {
        return token_cmd::run(action);
    }

    cli_validate::validate(&args).map_err(|e| anyhow::anyhow!("{}", e))?;

    let inventory = Arc::new(
        Inventory::load(&args.device_mapping)
            .with_context(|| format!("loading {}", args.device_mapping.display()))?,
    );
    tracing::info!(
        devices = inventory.names().len(),
        path = %args.device_mapping.display(),
        "loaded inventory"
    );

    let policy = Arc::new(Policy::build(&inventory).context("compiling blocklist policy")?);
    let counts = policy.rule_counts();
    tracing::info!(
        default_command_rules = counts.default_commands,
        default_config_rules = counts.default_config,
        devices_with_rules = counts.devices_with_rules,
        total_devices = inventory.names().len(),
        "blocklist policy loaded"
    );

    let dev_manager = Arc::new(DeviceManager::new(inventory.clone()));

    // Build the token store (or None for --allow-no-auth / stdio).
    let token_store = match (&args.tokens_file, args.allow_no_auth) {
        (Some(path), _) => {
            let names = inventory.names();
            let known: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
            let store = TokenStoreFile::load(path, &known)
                .with_context(|| format!("loading {}", path.display()))?;
            tracing::info!(tokens = store.len(), "token store loaded");
            Some(Arc::new(arc_swap::ArcSwap::from_pointee(store)))
        }
        (None, true) => {
            tracing::warn!("--allow-no-auth: streamable-http will accept unauthenticated requests");
            None
        }
        (None, false) if matches!(args.transport, Transport::StreamableHttp) => {
            unreachable!("cli_validate::validate should have refused this combination");
        }
        _ => None,
    };

    let handler = JmcpHandler::new(inventory.clone(), dev_manager, policy, token_store.clone());

    match args.transport {
        Transport::Stdio => {
            let service = handler
                .serve((tokio::io::stdin(), tokio::io::stdout()))
                .await
                .context("starting MCP stdio service")?;
            service
                .waiting()
                .await
                .context("MCP service exited with error")?;
        }
        Transport::StreamableHttp => {
            let addr: std::net::SocketAddr = format!("{}:{}", args.host, args.port)
                .parse()
                .with_context(|| format!("parsing {}:{}", args.host, args.port))?;
            http_transport::serve(handler, addr, token_store).await?;
        }
    }
    Ok(())
}
