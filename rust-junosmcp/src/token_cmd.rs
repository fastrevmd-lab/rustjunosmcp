//! `rust-junosmcp token …` subcommand. Implementations land in Task 7.

use crate::cli::TokenAction;
use anyhow::Result;

pub fn run(action: TokenAction) -> Result<()> {
    match action {
        TokenAction::Add { .. } => anyhow::bail!("token add: not implemented yet"),
        TokenAction::List { .. } => anyhow::bail!("token list: not implemented yet"),
        TokenAction::Revoke { .. } => anyhow::bail!("token revoke: not implemented yet"),
        TokenAction::Rotate { .. } => anyhow::bail!("token rotate: not implemented yet"),
    }
}
