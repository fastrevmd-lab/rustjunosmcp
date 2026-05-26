//! One module per Phase 1B tool. Each exposes a single public
//! `async fn run(&PooledDevice, args) -> Result<SrxToolResponse<T>, SrxError>`.

pub mod appid_package;
pub mod cluster_status;
pub mod idp_package;
pub mod license;
pub mod services_status;
pub mod signature_package;
pub mod vpn_lifecycle;
