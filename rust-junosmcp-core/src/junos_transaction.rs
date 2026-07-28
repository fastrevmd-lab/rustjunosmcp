//! Junos implementation of `mecmcp_changeset::DeviceTransaction`.
//!
//! This module wraps the existing device manager and rustez primitives to
//! provide the change-set lifecycle (fingerprint → stage → diff → validate →
//! commit) for Junos devices.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::helpers::build_config_payload;
use crate::tools::candidate_transaction::CheckOutcome;
use async_trait::async_trait;
use mecmcp_audit::Attribution;
use mecmcp_changeset::{
    CommitOptions, CommitOutcome, DeviceTransaction, RollbackOutcome, RollbackRef,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Junos-specific action: a config payload or a rollback archive reference.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JunosAction {
    /// Configuration payload to load. Exactly one of `payload` or
    /// `rollback_source` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<ConfigPayloadSpec>,
    /// Rollback archive version (0..=49). Junos loads rollback N and diffs it.
    /// Exactly one of `payload` or `rollback_source` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_source: Option<u32>,
}

/// Serializable config payload specification.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConfigPayloadSpec {
    pub text: String,
    /// Format: "set", "text", or "xml". Defaults to "set" if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Opaque staged-transaction handle.
///
/// On a chassis cluster, `cfg.load()` auto-opens a *private* configuration
/// database that is destroyed when the session unlocks. To preserve the staged
/// candidate across validate and commit, we must retain the session and its
/// lock until commit or discard.
pub struct JunosStagedTransaction {
    /// Device name for the pool.
    #[allow(dead_code)] // Kept for potential future use; session carries the connection.
    router: String,
    /// Diff captured during load.
    diff: String,
    /// Private database session. Retained until commit/discard so validate and
    /// commit see the same candidate. The session is marked non-reusable; it
    /// will be closed (not pooled) on drop.
    ///
    /// Uses tokio::sync::Mutex for interior mutability because the trait signature
    /// passes `&Staged` (immutable), but we need mutable access to call `.config()`.
    /// tokio::sync::Mutex is used (not std::sync::Mutex) because the guard must
    /// be held across `.await` points.
    session: tokio::sync::Mutex<Option<crate::device_manager::PooledDevice>>,
}

/// Diff output: just the text diff from Junos.
#[derive(Debug, Clone, Serialize)]
pub struct JunosDiff {
    pub diff: String,
}

/// Validation result.
#[derive(Debug, Clone, Serialize)]
pub struct JunosValidation {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Junos transaction context.
///
/// This struct implements `DeviceTransaction` by delegating to rustez primitives.
/// It holds a reference to the device manager for opening sessions.
pub struct JunosTransaction {
    device_manager: Arc<DeviceManager>,
    router: String,
}

impl JunosTransaction {
    pub fn new(device_manager: Arc<DeviceManager>, router: String) -> Self {
        Self {
            device_manager,
            router,
        }
    }
}

#[async_trait]
impl DeviceTransaction for JunosTransaction {
    type Action = JunosAction;
    type Staged = JunosStagedTransaction;
    type Diff = JunosDiff;
    type Validation = JunosValidation;
    type Error = JmcpError;

    async fn fingerprint(&self) -> Result<String, Self::Error> {
        // Fetch the candidate database via <get-configuration database="candidate"/>.
        // Uses the rustez RPC executor to issue a raw NETCONF RPC with the
        // database attribute. The returned XML is normalised before hashing to
        // ensure determinism: Junos includes a changing `junos:changed-seconds`
        // timestamp attribute and can vary in whitespace.
        let mut dev = self.device_manager.open(&self.router).await?;
        let mut exec = dev.rpc()?;

        // Issue the RPC with database="candidate" attribute using call_xml.
        // The envelope must include the attribute on the element.
        let candidate_xml = exec
            .call_xml(r#"<get-configuration database="candidate"/>"#)
            .await?;

        // Normalise: strip junos: namespace attributes (including the timestamp),
        // then apply line-based normalisation for deterministic hashing.
        let normalised = normalise_candidate_for_fingerprint(&candidate_xml);

        // SHA-256 hash the normalised text.
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(normalised.as_bytes());
        let hash = hasher.finalize();

        // Return in the mecmcp_changeset digest format: "sha256:{lowercase-hex}".
        Ok(format!("sha256:{:x}", hash))
    }

    async fn stage(&self, actions: &[Self::Action]) -> Result<Self::Staged, Self::Error> {
        // Defect #8: Validate exactly-one invariant (payload XOR rollback_source).
        for (i, action) in actions.iter().enumerate() {
            match (&action.payload, action.rollback_source) {
                (Some(_), Some(_)) => {
                    return Err(JmcpError::Validation(format!(
                        "action {} has both payload and rollback_source; exactly one is required",
                        i
                    )));
                }
                (None, None) => {
                    return Err(JmcpError::Validation(format!(
                        "action {} has neither payload nor rollback_source",
                        i
                    )));
                }
                _ => {} // exactly one is set; proceed
            }
        }

        // Open a session and lock the candidate. Load each action's payload or
        // rollback source. Capture the diff. The session is retained (not pooled)
        // until commit or discard so validate and commit see the same candidate.
        let mut dev = self.device_manager.open(&self.router).await?;

        // Defect #2: Mark session non-reusable before locking. It will be restored
        // to reusable only after all cleanup (rollback + unlock) succeeds.
        dev.prevent_reuse();

        let mut cfg = dev.config()?;

        // Lock the candidate.
        if let Err(error) = cfg.lock().await {
            // Lock failed before any load. Session is clean; allow pooling.
            dev.allow_reuse();
            return Err(error.into());
        }

        // Load actions. Track success count for partial-failure revert.
        for (loaded, action) in actions.iter().enumerate() {
            let load_result = if let Some(rollback) = action.rollback_source {
                cfg.rollback(rollback).await
            } else if let Some(ref spec) = action.payload {
                let payload = build_config_payload(spec.text.clone(), spec.format.as_deref())?;
                cfg.load(payload).await.map(|_| ())
            } else {
                unreachable!("exactly-one validation already checked this");
            };

            if let Err(error) = load_result {
                // Partial failure. Revert the candidate (rollback 0) and unlock.
                // Both must succeed before we allow the session back into the pool.
                // Finding 2 (P1): Cleanup failures must be visible in the returned
                // error, not just logged. A failed revert on a standalone device can
                // leave earlier actions sitting in the shared candidate, breaking the
                // all-or-none staging contract, and the caller sees nothing telling it
                // recovery is needed.
                let mut revert_err_opt = None;
                let mut unlock_err_opt = None;

                if loaded > 0
                    && let Err(revert_error) = cfg.rollback(0).await
                {
                    tracing::error!(
                        router = %self.router,
                        loaded,
                        primary_error = %error,
                        revert_error = %revert_error,
                        "failed to revert partial stage; session tainted"
                    );
                    revert_err_opt = Some(revert_error.to_string());
                }

                if let Err(unlock_error) = cfg.unlock().await {
                    tracing::error!(
                        router = %self.router,
                        primary_error = %error,
                        unlock_error = %unlock_error,
                        "failed to unlock after load failure; session tainted"
                    );
                    unlock_err_opt = Some(unlock_error.to_string());
                }

                if revert_err_opt.is_none() && unlock_err_opt.is_none() {
                    dev.allow_reuse();
                }

                // Return the cleanup-aware error if cleanup failed, otherwise the primary.
                return match (&revert_err_opt, &unlock_err_opt) {
                    (Some(revert_err), Some(unlock_err)) => {
                        Err(JmcpError::CandidateCleanupFailed {
                            primary: error.to_string(),
                            rollback: revert_err.clone(),
                            unlock: unlock_err.clone(),
                        })
                    }
                    (Some(revert_err), None) => Err(JmcpError::CandidateCleanupFailed {
                        primary: error.to_string(),
                        rollback: revert_err.clone(),
                        unlock: "ok".into(),
                    }),
                    (None, Some(unlock_err)) => Err(JmcpError::CandidateCleanupFailed {
                        primary: error.to_string(),
                        rollback: if loaded > 0 { "ok" } else { "skipped" }.into(),
                        unlock: unlock_err.clone(),
                    }),
                    (None, None) => Err(error.into()),
                };
            }
        }

        // Capture the diff.
        let diff = cfg.diff().await?.unwrap_or_default();

        // Defect #1: DO NOT unlock. Retain the session and lock so validate and
        // commit operate on the same private candidate database. On a chassis
        // cluster, unlocking closes the private database, and later operations
        // would open fresh sessions that can't see the staged candidate.
        //
        // The session will be dropped (and thus unlocked and closed) when the
        // caller drops the Staged handle, or when commit/rollback explicitly
        // unlocks and allows pooling.

        Ok(JunosStagedTransaction {
            router: self.router.clone(),
            diff,
            session: tokio::sync::Mutex::new(Some(dev)),
        })
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        // The diff was captured during stage. Return it.
        Ok(JunosDiff {
            diff: staged.diff.clone(),
        })
    }

    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        // Defect #1 fix: Use the retained session from stage, not a fresh one.
        // The staged session holds the lock and the private candidate database
        // (on chassis clusters). A fresh session cannot see the staged candidate.
        let mut session_guard = staged.session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            JmcpError::Validation("staged transaction has no session; already consumed?".into())
        })?;

        let mut cfg = session.config()?;

        match cfg.commit_check().await {
            Ok(()) => Ok(JunosValidation {
                valid: true,
                details: None,
            }),
            Err(error) => {
                // Classify the error. Only a device content rejection is "invalid".
                // Anything else (parse failure, multi-RE cluster reply, timeout) is
                // "check failed" — the check could not reach a verdict.
                let outcome =
                    crate::tools::candidate_transaction::classify_check_error(error.into());
                match outcome {
                    CheckOutcome::Valid => Ok(JunosValidation {
                        valid: true,
                        details: None,
                    }),
                    CheckOutcome::Invalid(details) => Ok(JunosValidation {
                        valid: false,
                        details: Some(details),
                    }),
                    CheckOutcome::CheckFailed(details) => Err(JmcpError::Validation(format!(
                        "commit-check could not reach a verdict: {}",
                        details
                    ))),
                }
            }
        }
    }

    async fn commit(
        &self,
        staged: &Self::Staged,
        attribution: &Attribution,
        options: &CommitOptions,
    ) -> Result<CommitOutcome, Self::Error> {
        // Finding 1 (P1): Reject confirm_timeout BEFORE staging to avoid leaving
        // the candidate dirty on refusal. The previous code refused after stage(),
        // which locked and loaded the shared candidate, then returned an error
        // without cleanup — leaving the staged changes for whatever commits next.
        // Reject an unusable confirm window before staging is touched, so a refusal
        // never leaves the candidate dirty for whatever commits next.
        let confirm_minutes = match options.confirm_timeout {
            Some(timeout) => Some(junos_confirm_minutes(timeout)?),
            None => None,
        };

        // Defect #1 fix: Use the staged session's lock and private candidate database.
        let mut session_guard = staged.session.lock().await;
        let session = session_guard.as_mut().ok_or_else(|| {
            JmcpError::Validation("staged transaction has no session; already consumed?".into())
        })?;

        // Build the commit comment from the attribution.
        let comment = format_attribution(attribution);

        // Confirmed commit takes a different path: the Junos-native RPC rather
        // than the RFC form, because only the native one survives this session.
        if let Some(minutes) = confirm_minutes {
            return confirmed_commit_on_session(session, minutes, &comment).await;
        }

        let mut cfg = session.config()?;

        // Normal synchronous commit with comment.
        // Defect #3: Distinguish timeout/transport uncertainty from known rejection.
        match cfg.commit_with_comment(&comment).await {
            Ok(()) => {
                // Commit succeeded. Unlock and allow the session to be pooled.
                // If unlock fails, the commit already succeeded, but the lock state
                // is unknown — that's Indeterminate.
                match cfg.unlock().await {
                    Ok(()) => {
                        // Finding 4 (P2): After commit and unlock both succeed, allow
                        // the session to be pooled. The previous code left prevent_reuse
                        // set, forcing a fresh SSH connection for every successful change
                        // set. ConfigManager doesn't implement Drop, so we can just allow
                        // reuse on the session directly (the borrow ends at the match arm).
                        session.allow_reuse();

                        Ok(CommitOutcome::Reconciled {
                            succeeded: true,
                            job_id: None,
                            details: Some("commit succeeded".into()),
                        })
                    }
                    Err(unlock_error) => {
                        // Commit succeeded but unlock failed or timed out. The lock
                        // state is unknown. Return Indeterminate.
                        Ok(CommitOutcome::Indeterminate {
                            reason: format!(
                                "commit succeeded but unlock failed: {}; lock state unknown",
                                unlock_error
                            ),
                        })
                    }
                }
            }
            Err(error) => {
                // Defect #3: Classify the error. A timeout or transport drop after
                // the commit RPC was sent means the outcome is unknown (device may
                // have committed). Only an explicit device rejection is Reconciled.
                if is_transport_uncertainty(&error) {
                    Ok(CommitOutcome::Indeterminate {
                        reason: format!("commit RPC timed out or transport dropped: {}", error),
                    })
                } else {
                    // Known rejection (syntax error, config invalid, etc.).
                    Ok(CommitOutcome::Reconciled {
                        succeeded: false,
                        job_id: None,
                        details: Some(error.to_string()),
                    })
                }
            }
        }
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::Archive(n) => {
                // Defect #6: Archive rollback leaks the lock. After acquiring the lock,
                // an invalid or unavailable archive makes rollback(n) return without
                // unlocking, and a successful load followed by a known commit rejection
                // unlocks without reverting the rollback-loaded candidate.
                //
                // FIX: Route every post-lock exit through cleanup (revert + unlock).
                let mut dev = self.device_manager.open(&self.router).await?;
                dev.prevent_reuse(); // Taint until cleanup succeeds.
                let mut cfg = dev.config()?;

                if let Err(lock_error) = cfg.lock().await {
                    dev.allow_reuse(); // Lock never acquired; session is clean.
                    return Err(lock_error.into());
                }

                // Load rollback N. If this fails, the candidate may be dirty (partial
                // load) or the archive may be invalid. Either way, revert (rollback 0)
                // before unlocking.
                let load_result = cfg.rollback(n).await;
                if let Err(load_error) = load_result {
                    let mut cleanup_failed = false;
                    if let Err(revert_error) = cfg.rollback(0).await {
                        tracing::error!(
                            router = %self.router,
                            archive = n,
                            load_error = %load_error,
                            revert_error = %revert_error,
                            "failed to revert after archive load failure; session tainted"
                        );
                        cleanup_failed = true;
                    }
                    if let Err(unlock_error) = cfg.unlock().await {
                        tracing::error!(
                            router = %self.router,
                            unlock_error = %unlock_error,
                            "failed to unlock after archive load failure; session tainted"
                        );
                        cleanup_failed = true;
                    }
                    if !cleanup_failed {
                        dev.allow_reuse();
                    }
                    return Err(load_error.into());
                }

                // Attempt to commit the rollback-loaded candidate.
                let commit_comment = format!("rollback to archive {}", n);
                let commit_result = cfg.commit_with_comment(&commit_comment).await;

                match commit_result {
                    Ok(()) => {
                        // Commit succeeded. Unlock and allow pooling.
                        if let Err(unlock_error) = cfg.unlock().await {
                            tracing::error!(
                                router = %self.router,
                                unlock_error = %unlock_error,
                                "unlock failed after successful archive rollback commit; session tainted"
                            );
                            // Session stays tainted (prevent_reuse).
                        } else {
                            dev.allow_reuse();
                        }
                        Ok(RollbackOutcome {
                            succeeded: true,
                            details: Some(format!("rollback to archive {} committed", n)),
                        })
                    }
                    Err(commit_error) => {
                        // Commit failed. The candidate is dirty (has rollback N loaded).
                        // Revert (rollback 0) and unlock before returning.
                        let mut cleanup_failed = false;
                        if let Err(revert_error) = cfg.rollback(0).await {
                            tracing::error!(
                                router = %self.router,
                                commit_error = %commit_error,
                                revert_error = %revert_error,
                                "failed to revert after archive commit failure; session tainted"
                            );
                            cleanup_failed = true;
                        }
                        if let Err(unlock_error) = cfg.unlock().await {
                            tracing::error!(
                                router = %self.router,
                                unlock_error = %unlock_error,
                                "failed to unlock after archive commit failure; session tainted"
                            );
                            cleanup_failed = true;
                        }
                        if !cleanup_failed {
                            dev.allow_reuse();
                        }
                        Ok(RollbackOutcome {
                            succeeded: false,
                            details: Some(commit_error.to_string()),
                        })
                    }
                }
            }
            RollbackRef::CandidateRevert => {
                // Defect #7: An uncertain candidate revert is reported as a known failure.
                // When rollback(0) times out or loses its response, the revert may have
                // succeeded, but this returns Ok with succeeded=false. The caller cannot
                // enter indeterminate recovery and may retry against a candidate that has
                // already changed.
                //
                // FIX: Propagate transport and RPC uncertainty as Err, and reserve
                // RollbackOutcome for outcomes actually known.
                let mut dev = self.device_manager.open(&self.router).await?;
                let mut cfg = dev.config()?;

                match cfg.rollback(0).await {
                    Ok(()) => Ok(RollbackOutcome {
                        succeeded: true,
                        details: Some("candidate reverted (rollback 0)".into()),
                    }),
                    Err(error) => {
                        // Defect #7 fix: Classify the error. Timeout or transport drop
                        // means the outcome is unknown. Return Err so the caller knows
                        // reconciliation is required. Only a known rejection (e.g., the
                        // rollback RPC explicitly failed with a config error, which is
                        // rare for rollback 0) is a RollbackOutcome.
                        if is_transport_uncertainty(&error) {
                            Err(JmcpError::Validation(format!(
                                "candidate revert (rollback 0) outcome unknown: {}",
                                error
                            )))
                        } else {
                            Ok(RollbackOutcome {
                                succeeded: false,
                                details: Some(error.to_string()),
                            })
                        }
                    }
                }
            }
            RollbackRef::Custom(ref target) => Err(JmcpError::Validation(format!(
                "custom rollback target '{}' is not supported on Junos",
                target
            ))),
        }
    }

    async fn confirm_commit(
        &self,
        _operation_id: &str,
        attribution: &Attribution,
    ) -> Result<CommitOutcome, Self::Error> {
        // Issue a second <commit/> with a comment that references the confirmed
        // commit and applies the attribution. This is the NEW primitive that does
        // not currently exist: a plain commit (no candidate changes). We'll use
        // the existing commit_with_comment for now, which is safe because a
        // confirming commit against an empty candidate is a no-op with a logged
        // comment.
        let mut dev = self.device_manager.open(&self.router).await?;
        let mut cfg = dev.config()?;

        let comment = format!("Confirming commit: {}", format_attribution(attribution));

        match cfg.commit_with_comment(&comment).await {
            Ok(()) => Ok(CommitOutcome::Reconciled {
                succeeded: true,
                job_id: None,
                details: Some("confirming commit succeeded".into()),
            }),
            Err(error) => Ok(CommitOutcome::Reconciled {
                succeeded: false,
                job_id: None,
                details: Some(error.to_string()),
            }),
        }
    }
}

/// Normalise candidate configuration XML for deterministic fingerprinting.
///
/// Normalisation contract:
/// 1. Strip `junos:` namespace attributes (including `junos:changed-seconds`,
///    the timestamp that changes on every read, and `junos:style`).
/// 2. Trim each line, remove empty lines, sort lines.
///
/// The timestamp attribute `junos:changed-seconds` is Junos' way of marking
/// configuration recency. It changes on every `<get-configuration>` call, even
/// when the configuration itself is unchanged. Stripping it is essential for
/// fingerprint stability.
///
/// This does not parse the XML structure as a tree but is stable enough to
/// detect meaningful configuration changes while ignoring incidental whitespace
/// and the timestamp. A production implementation might use a proper XML
/// canonicalisation algorithm (e.g., C14N), but that requires an XML parser
/// and is overkill for this use case.
fn normalise_candidate_for_fingerprint(xml: &str) -> String {
    // Step 1: Strip junos: namespace attributes using the same primitive that
    // the SRX support-bundle redaction uses. This removes junos:changed-seconds,
    // junos:style, and any other junos: attributes that vary between reads.
    let stripped = simple_strip_junos_attrs(xml);

    // Step 2: Whitespace only. Indentation and blank lines carry no meaning in
    // this output, so trimming them is safe.
    //
    // Order is NOT normalised, deliberately. Junos evaluates security policies
    // and firewall filter terms in the order they appear, so a reordered policy
    // list is a genuinely different configuration that behaves differently.
    // Sorting the lines here would make such a change hash identically to the
    // original and report no drift — defeating the one thing this fingerprint
    // exists to detect.
    let lines: Vec<&str> = stripped
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect();
    lines.join("\n")
}

/// Strip every `junos:attr="value"` occurrence in opening tags only.
///
/// Defect #5: The previous implementation used an unanchored substring search,
/// so configuration text containing a literal `junos:` (e.g.,
/// `<description>junos:foo</description>`) was treated as an attribute, causing
/// fingerprint collisions.
///
/// FIX: Only strip `junos:` when it appears in an opening tag context (after `<`
/// and before `>`). This is still a simplified parser (not a full XML tree), but
/// it correctly distinguishes attributes from element text.
fn simple_strip_junos_attrs(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;

    while let Some(open_tag_start) = rest.find('<') {
        // Copy everything before the opening `<`.
        out.push_str(&rest[..open_tag_start]);
        rest = &rest[open_tag_start..];

        // Find the closing `>` of this tag.
        let tag_end = match rest.find('>') {
            Some(pos) => pos,
            None => {
                // Malformed XML: no closing `>`. Copy the rest and bail.
                out.push_str(rest);
                return out;
            }
        };

        // Extract the tag content (everything between `<` and `>`).
        let tag_with_brackets = &rest[..=tag_end];
        let tag_content = &tag_with_brackets[1..tag_end]; // strip `<` and `>`

        // If this is a closing tag, comment, or CDATA, copy it as-is and continue.
        if tag_content.starts_with('/')
            || tag_content.starts_with('!')
            || tag_content.starts_with('?')
        {
            out.push_str(tag_with_brackets);
            rest = &rest[tag_end + 1..];
            continue;
        }

        // This is an opening tag. Strip `junos:` attributes from it.
        out.push('<');
        let stripped_tag_content = strip_junos_from_tag_content(tag_content);
        out.push_str(&stripped_tag_content);
        out.push('>');
        rest = &rest[tag_end + 1..];
    }

    // Copy any remaining content after the last tag.
    out.push_str(rest);
    out
}

/// Strip `junos:attr="value"` patterns from tag content (the text between `<` and `>`).
fn strip_junos_from_tag_content(tag: &str) -> String {
    let mut out = String::with_capacity(tag.len());
    let mut rest = tag;

    while let Some(pos) = rest.find("junos:") {
        // Copy everything before `junos:`.
        out.push_str(&rest[..pos]);
        rest = &rest[pos..];

        // Find the end of the attribute (past the closing quote).
        let attr_end = find_attr_end(rest);
        rest = &rest[attr_end..];

        // Strip leading whitespace after the attribute.
        rest = rest.trim_start_matches(' ');
    }

    out.push_str(rest);
    out
}

/// Find the end position of an XML attribute starting at `s`.
///
/// Duplicated from `rust-junosmcp-srx-core/src/xml.rs` to avoid a cross-crate
/// dependency. Handles both quoted and unquoted attribute values.
fn find_attr_end(s: &str) -> usize {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    // Find the '=' sign.
    while i < len && bytes[i] != b'=' {
        i += 1;
    }
    if i >= len {
        return len;
    }
    i += 1; // past '='
    if i >= len {
        return len;
    }
    let quote = bytes[i];
    // Unquoted attribute value.
    if quote != b'"' && quote != b'\'' {
        while i < len && !bytes[i].is_ascii_whitespace() && bytes[i] != b'>' {
            i += 1;
        }
        return i;
    }
    // Quoted attribute value: find the closing quote.
    i += 1; // past opening quote
    while i < len && bytes[i] != quote {
        i += 1;
    }
    if i < len {
        i += 1; // past closing quote
    }
    i
}

/// Classify whether a rustez error indicates transport/timeout uncertainty.
///
/// Finding 3 (P2): Match on error VARIANTS, not substrings. A device returning
/// `<rpc-error>` with a message that happens to contain "timeout" (e.g., rejecting
/// a configuration statement *named* `timeout`) is a terminal ServerError — a
/// known rejection (Reconciled { succeeded: false }), not Indeterminate.
///
/// Returns `true` for errors that indicate the outcome is unknown (timeout,
/// connection drop, channel closed). Returns `false` for errors that indicate
/// a known rejection (explicit ServerError from the device).
///
/// **Evidence on error variant discrimination**: rustnetconf 0.13.x and rustez 0.13.x
/// provide the following enum structure:
///
/// - `RustEzError::Netconf(NetconfError)` wraps all NETCONF-layer errors.
/// - `NetconfError::Rpc(RpcError::ServerError { .. })` is an explicit `<rpc-error>`
///   from the device — a known verdict, even if the message text contains "timeout".
/// - `NetconfError::Transport(_)` and `NetconfError::Framing(_)` are transport/framing
///   failures — the RPC outcome is unknown.
/// - `RpcError::ParseError(_)` can be a multi-RE cluster reply or a framing failure —
///   treat as uncertainty (safer default).
///
/// This distinction is PRESENT in the error variants and is RELIABLE: ServerError
/// means the device replied with an `<rpc-error>` element, which is a terminal
/// rejection. Transport/Framing mean the connection dropped or the message was
/// corrupt, which leaves the outcome unknown.
fn is_transport_uncertainty(error: &rustez::RustEzError) -> bool {
    use rustez::RustEzError;
    use rustnetconf::error::{NetconfError, RpcError};

    match error {
        // ServerError is an explicit <rpc-error> from the device. The device
        // rendered a verdict. This is a known rejection, NOT uncertainty.
        RustEzError::Netconf(NetconfError::Rpc(RpcError::ServerError { .. })) => false,

        // ParseError can be a framing failure, a multi-RE cluster reply that
        // won't parse, or a device rejection wrapped in unparseable XML. Without
        // more context, treat it as uncertainty (the safer default).
        RustEzError::Netconf(NetconfError::Rpc(RpcError::ParseError(_))) => true,

        // Transport and framing errors (session closed, EOF, channel dropped).
        RustEzError::Netconf(NetconfError::Transport(_) | NetconfError::Framing(_)) => true,

        // Protocol errors (capability mismatch, session state) also indicate
        // uncertainty when they occur mid-commit.
        RustEzError::Netconf(NetconfError::Protocol(_)) => true,

        // SSH config errors, facts errors, config errors, XML parse errors — these
        // are usually pre-RPC failures, but if they occur mid-commit the outcome is
        // unknown. Treat as uncertainty (safer default).
        RustEzError::SshConfig(_) | RustEzError::Facts(_) | RustEzError::Config(_) => true,

        // XML parse errors can occur when a device returns malformed XML mid-commit.
        RustEzError::XmlParse(_) => true,

        // Backstop for any future variants or nested errors not explicitly matched.
        _ => {
            // Substring matching as a last resort. This catches timeout messages that
            // don't fit the above variants. Still check variants first to avoid
            // false positives (e.g., ServerError with "timeout" in the message).
            let err_str = error.to_string().to_ascii_lowercase();
            [
                "timeout",
                "timed out",
                "connection closed",
                "connection reset",
                "broken pipe",
                "unexpected eof",
                "channel closed",
            ]
            .iter()
            .any(|needle| err_str.contains(needle))
        }
    }
}

/// Convert a confirm timeout into the whole minutes Junos expects.
///
/// The trait expresses the window as a `Duration`, but the Junos native RPC's
/// `<confirm-timeout>` is in **minutes** — verified on vSRX 24.4R1.9, where a
/// value of 1 rolled the change back at roughly sixty seconds. Passing seconds
/// straight through would have asked for a 300-minute window when the caller
/// meant five minutes.
///
/// Sub-minute windows are refused rather than rounded up to one minute: the
/// caller would be told a deadline the device will not honour, and a confirmed
/// commit whose window is wrong is worse than no confirmed commit.
fn junos_confirm_minutes(timeout: std::time::Duration) -> Result<u32, JmcpError> {
    let seconds = timeout.as_secs();
    if seconds < 60 {
        return Err(JmcpError::Validation(format!(
            "confirm timeout must be at least 60 seconds; Junos schedules the rollback in whole \
             minutes and cannot honour {seconds}s"
        )));
    }
    if !seconds.is_multiple_of(60) {
        return Err(JmcpError::Validation(format!(
            "confirm timeout must be a whole number of minutes; Junos cannot honour {seconds}s"
        )));
    }
    u32::try_from(seconds / 60)
        .map_err(|_| JmcpError::Validation("confirm timeout is implausibly large".into()))
}

/// Build the Junos-native confirmed-commit RPC.
///
/// Deliberately not `rustez`'s `commit_confirmed`, which sends the RFC form
/// `<commit><confirmed/><confirm-timeout/></commit>`. Under
/// `:confirmed-commit:1.0` — the only version vSRX 24.4R1.9 advertises — that
/// form is bound to the issuing session and rolls back the moment the session
/// closes. Since this server pools NETCONF sessions and returns them after the
/// commit, the pool reaper would revert the change well before the deadline the
/// caller was given (#227).
///
/// The Junos-native `<commit-configuration>` has the CLI's `commit confirmed`
/// semantics instead: the pending rollback belongs to the device, not the
/// session. Verified against vSRX 24.4R1.9 — the change survived closing the
/// issuing session, auto-reverted at the deadline when left alone, and was held
/// permanently by a confirming commit issued from a *different* session.
fn build_confirmed_commit_xml(minutes: u32, comment: &str) -> String {
    format!(
        "<commit-configuration><confirmed/><confirm-timeout>{minutes}</confirm-timeout>\
         <log>{}</log></commit-configuration>",
        escape_xml_text(comment)
    )
}

/// Minimal XML text escaping for values interpolated into an RPC body.
fn escape_xml_text(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Issue a confirmed commit on the staged session and report the deadline.
async fn confirmed_commit_on_session(
    session: &mut crate::device_manager::PooledDevice,
    minutes: u32,
    comment: &str,
) -> Result<CommitOutcome, JmcpError> {
    let xml = build_confirmed_commit_xml(minutes, comment);

    let response = {
        let mut exec = session.rpc()?;
        exec.call_xml(&xml).await
    };

    match response {
        Ok(_) => {
            // The rollback is the device's now, so the session is no longer
            // special and may return to the pool. This is the whole point of
            // using the native RPC: with the RFC form, pooling this session
            // would revert the change.
            session.allow_reuse();

            let deadline = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|since| since.as_secs())
                .unwrap_or(0)
                + u64::from(minutes) * 60;

            Ok(CommitOutcome::AwaitingConfirmation {
                job_id: None,
                rollback_deadline_unix: deadline,
                details: Some(format!(
                    "confirmed commit issued; the device reverts in {minutes} minute(s) unless a \
                     confirming commit is received"
                )),
            })
        }
        Err(error) if is_transport_uncertainty(&error) => Ok(CommitOutcome::Indeterminate {
            reason: format!(
                "confirmed commit sent but the outcome is unknown: {error}; the device may be \
                 holding a pending rollback"
            ),
        }),
        Err(error) => Err(error.into()),
    }
}

/// Format the attribution into a Junos commit comment.
fn format_attribution(attribution: &Attribution) -> String {
    let change_ref = attribution.change_ref.as_deref().unwrap_or("no-change-ref");
    let principal = &attribution.principal;
    let on_behalf_of = attribution.on_behalf_of.as_deref().unwrap_or("self");

    let actor_type_str = match attribution.actor_type {
        mecmcp_audit::ActorType::Human => "human",
        mecmcp_audit::ActorType::Agent => "agent",
        mecmcp_audit::ActorType::Unknown => "unknown",
    };

    // If it's an agent with identity, include provider and — only when the
    // caller actually asserted one — the model.
    //
    // `model_id` is always client-asserted: a token cannot vouch for which
    // model ran, so attribution built from a token entry leaves it empty by
    // design. Emitting `model=` unconditionally put a dangling, valueless key
    // on every commit this server made (mecmcp#75). Omit the segment rather
    // than record an empty claim.
    let agent_info = if let Some(ref agent) = attribution.agent {
        let model = if agent.model_id.is_empty() {
            String::new()
        } else {
            format!(" model={}", agent.model_id)
        };
        format!(" via {}-{}{}", agent.provider, agent.provider_tier, model)
    } else {
        String::new()
    };

    format!(
        "{} by {} ({}) on-behalf-of={}{}",
        change_ref, principal, actor_type_str, on_behalf_of, agent_info
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A transaction over an empty inventory. Every test using this asserts on
    /// behaviour that happens *before* a session is opened, so no device is
    /// contacted; `stage()` would fail at `device_manager.open()` if one of
    /// these ever got that far, which is itself the signal that the validation
    /// under test stopped working.
    fn offline_transaction() -> JunosTransaction {
        use crate::{device_manager::DeviceManager, inventory::Inventory};
        use std::sync::Arc;

        JunosTransaction::new(
            Arc::new(DeviceManager::new(Arc::new(Inventory::empty()))),
            "no-such-router".to_owned(),
        )
    }

    fn action(payload: Option<&str>, rollback_source: Option<u32>) -> JunosAction {
        JunosAction {
            payload: payload.map(|text| ConfigPayloadSpec {
                text: text.to_owned(),
                format: Some("set".to_owned()),
            }),
            rollback_source,
        }
    }

    /// `payload` and `rollback_source` are mutually exclusive. Staging both
    /// would load a payload *and* a rollback archive into one candidate, so the
    /// resulting configuration is neither of the things the caller asked for.
    #[tokio::test]
    async fn stage_rejects_an_action_carrying_both_payload_and_rollback() {
        let error = offline_transaction()
            .stage(&[action(Some("set system host-name a"), Some(0))])
            .await
            .err()
            .expect("both fields set must be refused");

        let message = error.to_string();
        assert!(
            message.contains("both payload and rollback_source"),
            "the error should name the conflict, got: {message}"
        );
    }

    /// Neither field set has no meaning either, and it must be caught before a
    /// session is opened rather than surfacing as an `unreachable!` later.
    #[tokio::test]
    async fn stage_rejects_an_action_carrying_neither_payload_nor_rollback() {
        let error = offline_transaction()
            .stage(&[action(None, None)])
            .await
            .err()
            .expect("neither field set must be refused");

        let message = error.to_string();
        assert!(
            message.contains("neither payload nor rollback_source"),
            "the error should name the omission, got: {message}"
        );
    }

    /// The invariant is per action, not just the first one: a valid action must
    /// not mask an invalid one behind it.
    #[tokio::test]
    async fn stage_validates_every_action_not_only_the_first() {
        let error = offline_transaction()
            .stage(&[
                action(Some("set system host-name a"), None),
                action(Some("set system host-name b"), Some(0)),
            ])
            .await
            .err()
            .expect("the second action is invalid and must be caught");

        let message = error.to_string();
        assert!(
            message.contains("action 1"),
            "the error should identify which action failed, got: {message}"
        );
    }

    /// Junos schedules the rollback in whole minutes. Passing the trait's
    /// seconds straight through would request a 300-minute window for a
    /// five-minute one — verified against vSRX 24.4R1.9, where
    /// `<confirm-timeout>1</confirm-timeout>` reverted at about sixty seconds.
    #[test]
    fn confirm_timeout_converts_seconds_to_whole_minutes() {
        use std::time::Duration;

        assert_eq!(junos_confirm_minutes(Duration::from_secs(60)).unwrap(), 1);
        assert_eq!(junos_confirm_minutes(Duration::from_secs(300)).unwrap(), 5);
    }

    /// A window Junos cannot honour is refused rather than rounded. Rounding up
    /// would hand the caller a deadline the device will not keep, and a
    /// confirmed commit with the wrong window is worse than none.
    #[test]
    fn confirm_timeout_refuses_windows_junos_cannot_honour() {
        use std::time::Duration;

        let err =
            junos_confirm_minutes(Duration::from_secs(30)).expect_err("sub-minute must be refused");
        assert!(err.to_string().contains("at least 60 seconds"), "{err}");

        let err = junos_confirm_minutes(Duration::from_secs(90))
            .expect_err("part-minute must be refused");
        assert!(err.to_string().contains("whole number of minutes"), "{err}");
    }

    /// The native `<commit-configuration>` RPC, not the RFC `<commit><confirmed/>`
    /// form. Only the native one survives the issuing session, which is what lets
    /// the session return to the pool (#227).
    #[test]
    fn confirmed_commit_uses_the_junos_native_rpc() {
        let xml = build_confirmed_commit_xml(5, "no-change-ref by tok (agent)");

        assert!(xml.starts_with("<commit-configuration>"), "{xml}");
        assert!(xml.contains("<confirmed/>"), "{xml}");
        assert!(
            xml.contains("<confirm-timeout>5</confirm-timeout>"),
            "{xml}"
        );
        assert!(
            !xml.contains("<commit>"),
            "must not emit the session-bound RFC form: {xml}"
        );
    }

    /// A comment reaches the device inside XML, so a stray angle bracket in the
    /// attribution must not be able to close the element early.
    #[test]
    fn confirmed_commit_escapes_the_comment() {
        let xml = build_confirmed_commit_xml(1, "evil </log><foo> & bar");

        assert!(!xml.contains("<foo>"), "unescaped markup leaked: {xml}");
        assert!(xml.contains("&lt;/log&gt;"), "{xml}");
        assert!(xml.contains("&amp; bar"), "{xml}");
    }

    fn agent_attribution(model_id: &str) -> Attribution {
        let mut attribution = Attribution::stdio();
        attribution.actor_type = mecmcp_audit::ActorType::Agent;
        attribution.on_behalf_of = Some("mharman".to_owned());
        attribution.agent = Some(mecmcp_audit::AgentIdentity {
            model_id: model_id.to_owned(),
            session_id: String::new(),
            client_name: None,
            provider: "anthropic".to_owned(),
            provider_tier: mecmcp_audit::Tier::Private,
            skills_used: Vec::new(),
        });
        attribution
    }

    /// A token cannot vouch for which model ran, so token-built attribution
    /// leaves `model_id` empty. The comment must then omit the segment rather
    /// than trail a valueless `model=` (mecmcp#75).
    #[test]
    fn commit_comment_omits_an_unasserted_model() {
        let comment = format_attribution(&agent_attribution(""));

        assert!(
            comment.contains("via anthropic-private"),
            "provider must still appear: {comment}"
        );
        assert!(
            !comment.contains("model="),
            "an empty model must not be recorded as a claim: {comment}"
        );
    }

    #[test]
    fn commit_comment_keeps_a_model_the_caller_asserted() {
        let comment = format_attribution(&agent_attribution("claude-opus-5"));

        assert!(
            comment.contains("via anthropic-private model=claude-opus-5"),
            "an asserted model must survive: {comment}"
        );
    }

    #[test]
    fn normalise_candidate_trims_whitespace() {
        let xml = r#"
            <configuration>
                <system>
                    <host-name>r1</host-name>
                </system>
            </configuration>
        "#;
        let normalised = normalise_candidate_for_fingerprint(xml);
        assert!(normalised.contains("<configuration>"));
        assert!(normalised.contains("<host-name>r1</host-name>"));
        // Document order is preserved: the opening element still precedes what
        // it contains.
        let open = normalised.find("<configuration>").expect("root present");
        let inner = normalised.find("<host-name>").expect("child present");
        assert!(open < inner, "normalisation must not reorder the document");
    }

    #[test]
    fn normalise_candidate_detects_reordering() {
        // Junos evaluates security policies in the order they appear, so moving
        // one is a real configuration change. An earlier version of this
        // normalisation sorted the lines, which made a reordered policy list
        // hash identically to the original — the fingerprint would have reported
        // no drift on a change that alters what the device does.
        let original = r#"<configuration>
            <policy><name>permit-dns</name></policy>
            <policy><name>deny-all</name></policy>
        </configuration>"#;
        let reordered = r#"<configuration>
            <policy><name>deny-all</name></policy>
            <policy><name>permit-dns</name></policy>
        </configuration>"#;

        assert_ne!(
            normalise_candidate_for_fingerprint(original),
            normalise_candidate_for_fingerprint(reordered),
            "reordering policies must change the fingerprint"
        );
    }

    #[test]
    fn normalise_candidate_strips_junos_timestamp() {
        // Junos includes junos:changed-seconds on the root element, which changes
        // on every read. Fingerprinting must strip it for determinism.
        let xml1 = r#"<configuration junos:changed-seconds="1700000000">
            <system><host-name>r1</host-name></system>
        </configuration>"#;
        let xml2 = r#"<configuration junos:changed-seconds="1700000999">
            <system><host-name>r1</host-name></system>
        </configuration>"#;

        let norm1 = normalise_candidate_for_fingerprint(xml1);
        let norm2 = normalise_candidate_for_fingerprint(xml2);

        // The normalised forms must be identical because only the timestamp differs.
        assert_eq!(norm1, norm2, "timestamp-only change must hash identically");

        // Verify the timestamp was actually removed.
        assert!(
            !norm1.contains("junos:"),
            "junos: attributes must be stripped"
        );
    }

    #[test]
    fn normalise_candidate_detects_real_config_change() {
        let xml1 = r#"<configuration junos:changed-seconds="1700000000">
            <system><host-name>r1</host-name></system>
        </configuration>"#;
        let xml2 = r#"<configuration junos:changed-seconds="1700000000">
            <system><host-name>r2</host-name></system>
        </configuration>"#;

        let norm1 = normalise_candidate_for_fingerprint(xml1);
        let norm2 = normalise_candidate_for_fingerprint(xml2);

        // A real configuration change (r1 → r2) must produce different fingerprints.
        assert_ne!(
            norm1, norm2,
            "real config change must produce different fingerprints"
        );
    }

    #[test]
    fn fingerprint_hash_format() {
        use sha2::{Digest, Sha256};

        // Fingerprint must return "sha256:{lowercase-hex}" format.
        let xml = r#"<configuration><system><host-name>test</host-name></system></configuration>"#;
        let normalised = normalise_candidate_for_fingerprint(xml);
        let mut hasher = Sha256::new();
        hasher.update(normalised.as_bytes());
        let hash = hasher.finalize();
        let fingerprint = format!("sha256:{:x}", hash);

        // Verify the format.
        assert!(fingerprint.starts_with("sha256:"));
        assert_eq!(fingerprint.len(), 7 + 64); // "sha256:" + 64 hex chars
        assert!(fingerprint[7..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn format_attribution_includes_all_fields() {
        use mecmcp_audit::{ActorType, AgentIdentity, Principal, Tier};
        use uuid::Uuid;

        let attribution = Attribution {
            principal: Principal::Token("alice".into()),
            actor_type: ActorType::Agent,
            agent: Some(AgentIdentity {
                model_id: "claude-sonnet-4-5".into(),
                session_id: "sess123".into(),
                client_name: None,
                provider: "anthropic".into(),
                provider_tier: Tier::Public,
                skills_used: vec![],
            }),
            on_behalf_of: Some("bob".into()),
            change_ref: Some("CHG0012345".into()),
            request_id: Uuid::new_v4(),
            token_verified_fields: mecmcp_audit::TokenVerifiedFields::none(),
        };
        let formatted = format_attribution(&attribution);
        assert!(formatted.contains("CHG0012345"));
        assert!(formatted.contains("alice"));
        assert!(formatted.contains("anthropic"));
        assert!(formatted.contains("public"));
        assert!(formatted.contains("bob"));
        assert!(formatted.contains("agent"));
    }

    #[test]
    fn normalise_candidate_does_not_strip_junos_from_element_text() {
        // Defect #5 regression guard: A literal "junos:" in element text
        // (e.g., <description>junos:foo</description>) must NOT be treated as
        // an attribute. The previous unanchored substring search would strip
        // it, causing two genuinely different configs to hash identically.
        let xml1 = r#"<configuration>
            <system><host-name>r1</host-name></system>
        </configuration>"#;
        let xml2 = r#"<configuration>
            <system>
                <host-name>r1</host-name>
                <description>junos:style configuration</description>
            </system>
        </configuration>"#;

        let norm1 = normalise_candidate_for_fingerprint(xml1);
        let norm2 = normalise_candidate_for_fingerprint(xml2);

        // The second config has a description with literal "junos:" text.
        // This is a real difference and must produce different fingerprints.
        assert_ne!(
            norm1, norm2,
            "literal 'junos:' in element text must not cause fingerprint collision"
        );

        // Verify the description text was preserved (not stripped).
        assert!(
            norm2.contains("junos:style configuration"),
            "element text containing 'junos:' must be preserved"
        );
    }

    #[test]
    fn normalise_candidate_strips_junos_attrs_from_opening_tags() {
        // Defect #5 fix verification: junos: attributes in opening tags ARE
        // stripped, but element text containing "junos:" is preserved.
        let xml = r#"<configuration junos:changed-seconds="1700000000">
            <system junos:style="curly">
                <host-name>r1</host-name>
                <description>junos:style configuration</description>
            </system>
        </configuration>"#;

        let norm = normalise_candidate_for_fingerprint(xml);

        // Attributes junos:changed-seconds and junos:style must be stripped.
        assert!(
            !norm.contains("junos:changed-seconds"),
            "junos:changed-seconds attribute must be stripped"
        );
        assert!(
            !norm.contains("junos:style=\"curly\""),
            "junos:style attribute must be stripped"
        );

        // Element text "junos:style configuration" must be preserved.
        assert!(
            norm.contains("junos:style configuration"),
            "element text 'junos:style configuration' must be preserved"
        );
    }

    #[test]
    fn is_transport_uncertainty_detects_timeout() {
        // The error string is what matters for classification, not the exact type.
        // Create a mock error with "timeout" in the message.
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};

        // Use a parse error with "timeout" in the message to test the classifier.
        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::ParseError(
            "operation timed out waiting for response".into(),
        )));
        assert!(
            is_transport_uncertainty(&error),
            "timeout must be classified as transport uncertainty"
        );

        // Test other uncertainty patterns.
        let error2 = RustEzError::Netconf(NetconfError::Rpc(RpcError::ParseError(
            "connection closed unexpectedly".into(),
        )));
        assert!(
            is_transport_uncertainty(&error2),
            "connection closed must be classified as transport uncertainty"
        );
    }

    #[test]
    fn is_transport_uncertainty_does_not_match_rpc_errors() {
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};
        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::ServerError {
            error_type: None,
            tag: rustnetconf::types::ErrorTag::OperationFailed,
            severity: None,
            app_tag: None,
            path: None,
            message: "syntax error".into(),
            info: None,
        }));
        assert!(
            !is_transport_uncertainty(&error),
            "RPC server error must NOT be classified as transport uncertainty"
        );
    }

    #[test]
    fn finding3_server_error_with_timeout_in_message_is_not_uncertain() {
        // Finding 3 (P2) regression guard: A ServerError (explicit <rpc-error>
        // from the device) whose message happens to contain "timeout" is still
        // a known rejection, not Indeterminate. The previous string-matching
        // classifier would treat this as uncertain.
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};

        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::ServerError {
            error_type: None,
            tag: rustnetconf::types::ErrorTag::InvalidValue,
            severity: None,
            app_tag: None,
            path: None,
            message: "invalid value for 'timeout' parameter: must be 1..3600".into(),
            info: None,
        }));

        assert!(
            !is_transport_uncertainty(&error),
            "ServerError with 'timeout' in message must be classified as a known rejection"
        );
    }

    #[test]
    fn finding3_parse_error_is_uncertain() {
        // ParseError can be a framing failure or unparseable device reply.
        // Treat it as uncertainty (the safer default).
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, RpcError};

        let error = RustEzError::Netconf(NetconfError::Rpc(RpcError::ParseError(
            "unexpected element".into(),
        )));

        assert!(
            is_transport_uncertainty(&error),
            "ParseError must be classified as uncertainty"
        );
    }

    #[test]
    fn finding3_transport_errors_are_uncertain() {
        use rustez::RustEzError;
        use rustnetconf::error::{NetconfError, TransportError};

        let transport = RustEzError::Netconf(NetconfError::Transport(TransportError::Connect(
            "connection refused".into(),
        )));
        assert!(
            is_transport_uncertainty(&transport),
            "Transport error must be classified as uncertainty"
        );
    }

    // Three fixes in this round have NO automated test, and that is a gap rather
    // than an oversight:
    //
    //   - the confirmed-commit refusal happening before anything is staged,
    //   - a partial-stage cleanup failure surfacing in the returned error,
    //   - pooling being re-enabled after a clean commit.
    //
    // `JunosTransaction` is constructed from a `DeviceManager` and reaches the
    // device through a real `PooledDevice`, so there is no seam to inject a
    // failing backend the way `candidate_transaction.rs` does with `FakeBackend`.
    // Testing these means either a live device or giving this type the same
    // backend abstraction, which is a larger change than the fixes themselves and
    // is tracked separately.
    //
    // Recording it here so the absence is visible in the file rather than only in
    // a review comment.
}
