//! Caller-attributed audit events for rust-junosmcp / rust-srxmcp.

mod schema;
mod scope;
pub mod testutil;
mod init;

pub use schema::{AuditOutcome, AuditValue};
pub use scope::AuditScope;
pub use init::{AuditConfig, AuditFormat, init_tracing};
