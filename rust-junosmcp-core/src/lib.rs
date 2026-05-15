//! Core logic for rust-junosmcp: inventory, device manager, and MCP tool handlers
//! built on top of [`rustez`].
//!
//! The binary crate `rust-junosmcp` wires this into the rmcp transport.

pub mod device_manager;
pub mod error;
pub mod helpers;
pub mod inventory;
pub mod policy;
pub mod tools;
pub use device_manager::DeviceManager;
pub use error::JmcpError;
pub use inventory::{AuthConfig, DeviceEntry, Inventory};
pub use policy::Policy;
pub use tools::transfer_file::{OpenSshScpRunner, ScpJob, ScpOutcome, ScpRunner, TransferConfig};
pub use tools::upgrade_junos::UpgradeConfig;
