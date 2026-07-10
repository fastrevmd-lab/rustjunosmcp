//! Shared primitives for IDP + AppID signature-package workflows
//! (`manage_idp_security_package`, `manage_appid_signature_package`).
//!
//! Submodules:
//! * [`confirmation`] — short-lived, caller-bound, one-time artifacts that
//!   authorize execution of an unchanged destructive plan.
//! * [`plan`] — the `confirmation_required` JSON envelope returned by call 1
//!   of the two-call confirmation protocol, plus the `already_at_target`
//!   short-circuit response.
//! * [`poll`] — generic async poll-with-deadline used by the download and
//!   install status RPCs.
//! * [`preflight`] — pure XML helpers shared by both workflow modules
//!   (commit-confirmed window detection today; cluster / license / reachability
//!   wrappers land alongside their first consumer).

pub mod confirmation;
pub mod plan;
pub mod poll;
pub mod preflight;

pub use confirmation::{
    confirmation_token_for_request, ConfirmationBinding, ConfirmationError, ConfirmationStore,
    ConfirmedPlan,
};
pub use plan::{
    AlreadyAtTargetResponse, ConfirmationPlan, ConfirmationRequiredTag, DownloadAndInstallAction,
    DownloadAndInstallPlan, NodeVersionInfo, RollbackAction, RollbackPlan, Service, TargetSource,
    Topology, UninstallAction, UninstallPlan,
};
pub use poll::{poll_until_done, PollError, PollOutcome};
pub use preflight::detect_commit_confirmed;
