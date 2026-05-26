//! Shared primitives for IDP + AppID signature-package workflows
//! (`manage_idp_security_package`, `manage_appid_signature_package`).
//!
//! Submodules:
//! * [`plan`] — the `confirmation_required` JSON envelope returned by call 1
//!   of the two-call confirmation protocol, plus the `already_at_target`
//!   short-circuit response.
//! * [`poll`] — generic async poll-with-deadline used by the download and
//!   install status RPCs.
//! * [`preflight`] — pure XML helpers shared by both workflow modules
//!   (commit-confirmed window detection today; cluster / license / reachability
//!   wrappers land alongside their first consumer).

pub mod plan;
pub mod poll;
pub mod preflight;

pub use plan::{
    AlreadyAtTargetResponse, ConfirmationPlan, DownloadAndInstallPlan, NodeVersionInfo,
    RollbackPlan, Service, TargetSource, Topology, UninstallPlan,
};
pub use poll::{poll_until_done, PollError, PollOutcome};
pub use preflight::detect_commit_confirmed;
