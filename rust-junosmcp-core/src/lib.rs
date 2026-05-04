//! Core logic for rust-junosmcp: inventory, device manager, and MCP tool handlers
//! built on top of [`rustez`].
//!
//! The binary crate `rust-junosmcp` wires this into the rmcp transport.

pub mod error;
pub mod inventory;
pub use error::JmcpError;
pub use inventory::AuthConfig;
