//! Caller-attributed audit events for the unified rust-junosmcp server.

mod init;
mod redact;
mod schema;
mod scope;
pub mod testutil;

pub use init::{AuditConfig, AuditFormat, init_tracing};
pub use redact::{
    AuditRedaction, FieldTransform, REDACTABLE_FIELDS, RedactError, active, install, render,
};
pub use schema::{AuditOutcome, AuditValue};
pub use scope::AuditScope;
