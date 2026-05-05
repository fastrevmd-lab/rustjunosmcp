mod cli;
mod server;

use anyhow::{bail, Context, Result};
use clap::Parser;
use cli::{Cli, Transport};
use rmcp::ServiceExt;
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

    if matches!(args.transport, Transport::StreamableHttp) {
        bail!(
            "streamable-http transport is not supported in v0.1. \
             Use --transport stdio. HTTP support is planned for v0.2."
        );
    }

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
    let handler = JmcpHandler::new(inventory, dev_manager, policy);

    let service = handler
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .context("starting MCP stdio service")?;
    service
        .waiting()
        .await
        .context("MCP service exited with error")?;
    Ok(())
}
