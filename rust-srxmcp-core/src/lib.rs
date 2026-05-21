//! Core workflows + shared types for `rust-srxmcp`.
//!
//! This crate is consumed by the `rust-srxmcp` binary. It owns the typed
//! tool response envelope (`SrxToolResponse<T>`), absence semantics
//! (`SrxState`), the multi-RE XML helper, the `SrxError` taxonomy, and
//! one `workflows::<tool>` module per Phase 1B tool.

pub mod absence;
pub mod error;
pub mod workflows;
pub mod xml;

pub use absence::{SrxState, SrxToolResponse};
pub use error::SrxError;
pub use workflows::cluster_status::{
    ClusterNode, ClusterStatusArgs, ClusterStatusData, RedundancyGroup, RgMember,
};
pub use workflows::license::{
    LicenseArgs, LicenseCounts, LicenseData, LicenseRecord, SrxLicensedFeature,
};
