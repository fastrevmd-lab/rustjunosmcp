//! Caller-attributed audit events for rust-junosmcp / rust-srxmcp.

mod init;
mod redact;
mod schema;
mod scope;
pub mod testutil;

pub use init::{init_tracing, AuditConfig, AuditFormat};
pub use redact::{active, render, AuditRedaction, FieldTransform, RedactError, REDACTABLE_FIELDS};
pub use schema::{AuditOutcome, AuditValue};
pub use scope::AuditScope;
