//! Caller-attributed audit events for rust-junosmcp / rust-srxmcp.

mod init;
mod schema;
mod scope;
pub mod testutil;

pub use init::{init_tracing, AuditConfig, AuditFormat};
pub use schema::{AuditOutcome, AuditValue};
pub use scope::AuditScope;
