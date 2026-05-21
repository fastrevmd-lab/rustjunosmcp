//! One module per Phase 1B tool. Each exposes a single public
//! `async fn run(&PooledDevice, args) -> Result<SrxToolResponse<T>, SrxError>`.

pub mod cluster_status;
pub mod license;

// Wired in subsequent tasks:
// pub mod services_status;
// pub mod vpn_report;
