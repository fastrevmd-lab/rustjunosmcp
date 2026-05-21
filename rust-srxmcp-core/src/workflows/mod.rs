//! One module per Phase 1B tool. Each exposes a single public
//! `async fn run(&PooledDevice, args) -> Result<SrxToolResponse<T>, SrxError>`.

pub mod cluster_status;
pub mod license;
pub mod services_status;

// Wired in subsequent tasks:
// pub mod vpn_report;
