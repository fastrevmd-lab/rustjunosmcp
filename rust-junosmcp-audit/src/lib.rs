//! Caller-attributed audit events for the unified rust-junosmcp server.

mod init;
mod redact;
mod schema;
mod scope;
pub mod testutil;

pub use init::{init_tracing, AuditConfig, AuditFormat};
pub use redact::{
    active, install, render, AuditRedaction, FieldTransform, RedactError, REDACTABLE_FIELDS,
};
pub use schema::{AuditOutcome, AuditValue};
pub use scope::AuditScope;
