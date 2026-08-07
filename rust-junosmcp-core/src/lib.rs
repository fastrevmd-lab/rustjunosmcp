//! Core logic for rust-junosmcp: inventory, device manager, and MCP tool handlers
//! built on top of [`rustez`].
//!
//! The binary crate `rust-junosmcp` wires this into the rmcp transport.

#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod bootstrap;
pub mod device_manager;
pub mod error;
pub mod helpers;
pub mod inventory;
pub mod junos_transaction;
pub mod output;
pub mod policy;
pub mod progress;
pub mod schema_alias;
pub mod tools;

// Re-export mecmcp-device primitives
pub use mecmcp_device::cancel;
pub use mecmcp_device::{DeviceLock, DeviceLockGuard, FlockDeviceLock};

// Backward compatibility alias for existing consumers
pub type DeviceLeaseManager = FlockDeviceLock;
pub type DeviceLeaseGuard = DeviceLockGuard;
pub const DEFAULT_DEVICE_LEASE_DIR: &str = "/var/lib/jmcp/device-leases";

pub use device_manager::DeviceManager;
pub use error::JmcpError;
pub use inventory::{AuthConfig, DeviceEntry, Inventory};
pub use policy::Policy;
pub use rustez::HostKeyVerification;
pub use tools::transfer_file::{
    MecmcpScpRunner, MockScpRunner, ScpJob, ScpOutcome, ScpRunner, TransferConfig,
};
pub use tools::upgrade_junos::UpgradeConfig;
