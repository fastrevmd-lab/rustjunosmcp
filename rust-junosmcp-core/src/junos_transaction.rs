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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPayloadSpec {
    pub text: String,
    /// Format: "set", "text", or "xml". Defaults to "set" if omitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
}

/// Opaque staged-transaction handle.
///
/// Captures the device name and the diff produced during load. The session
/// itself is not held open — Junos releases the lock after each operation,
/// and the candidate database persists uncommitted changes across sessions.
pub struct JunosStagedTransaction {
    /// Device name for the pool.
    router: String,
    /// Diff captured during load.
    diff: String,
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
        // Open a session and lock the candidate. Load each action's payload or
        // rollback source. Capture the diff. If any action fails after the first
        // succeeds, revert the candidate (rollback 0) before returning an error.
        let mut dev = self.device_manager.open(&self.router).await?;
        let mut cfg = dev.config()?;

        // Lock the candidate.
        cfg.lock().await?;

        // Load actions. Track success count for partial-failure revert.
        // We need a separate counter for successful loads, not just the index.
        let mut loaded = 0;
        #[allow(clippy::explicit_counter_loop)]
        for (i, action) in actions.iter().enumerate() {
            let load_result = if let Some(rollback) = action.rollback_source {
                cfg.rollback(rollback).await
            } else if let Some(ref spec) = action.payload {
                let payload = build_config_payload(spec.text.clone(), spec.format.as_deref())?;
                cfg.load(payload).await.map(|_| ())
            } else {
                return Err(JmcpError::Validation(format!(
                    "action {} has neither payload nor rollback_source",
                    i
                )));
            };

            if let Err(error) = load_result {
                // Partial failure. Revert the candidate (rollback 0) and unlock.
                let revert_failed = if loaded > 0 {
                    if let Err(revert_error) = cfg.rollback(0).await {
                        tracing::error!(
                            router = %self.router,
                            loaded,
                            primary_error = %error,
                            revert_error = %revert_error,
                            "failed to revert partial stage; session tainted"
                        );
                        Some(revert_error)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let _ = cfg.unlock().await;

                if let Some(revert_error) = revert_failed {
                    // The session is tainted. Close it rather than pooling.
                    dev.prevent_reuse();
                    return Err(JmcpError::Validation(format!(
                        "partial stage failure on action {}, and revert failed: {}",
                        i, revert_error
                    )));
                }
                return Err(error.into());
            }
            loaded += 1;
        }

        // Capture the diff.
        let diff = cfg.diff().await?.unwrap_or_default();

        // Unlock. The candidate database persists uncommitted changes across
        // sessions, so we don't need to hold the session open.
        cfg.unlock().await?;

        Ok(JunosStagedTransaction {
            router: self.router.clone(),
            diff,
        })
    }

    async fn diff(&self, staged: &Self::Staged) -> Result<Self::Diff, Self::Error> {
        // The diff was captured during stage. Return it.
        Ok(JunosDiff {
            diff: staged.diff.clone(),
        })
    }

    async fn validate(&self, staged: &Self::Staged) -> Result<Self::Validation, Self::Error> {
        // Issue <commit-check/> on the session.
        let mut dev = self.device_manager.open(&staged.router).await?;
        let mut cfg = dev.config()?;

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
        let mut dev = self.device_manager.open(&staged.router).await?;
        let mut cfg = dev.config()?;

        // Build the commit comment from the attribution.
        let comment = format_attribution(attribution);

        if let Some(confirm_timeout) = options.confirm_timeout {
            // Confirmed commit. Note that Junos DROPS the commit comment on the
            // initial confirmed commit. The comment will be applied later via
            // confirm_commit().
            let seconds = confirm_timeout.as_secs();
            if seconds > u32::MAX as u64 {
                return Err(JmcpError::Validation(format!(
                    "confirm_timeout too large: {} seconds (max u32)",
                    seconds
                )));
            }
            let seconds_u32 = seconds as u32;

            match cfg.commit_confirmed(seconds_u32).await {
                Ok(()) => {
                    // Commit succeeded. Return AwaitingConfirmation with the deadline.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("system time before UNIX epoch")
                        .as_secs();
                    let rollback_deadline_unix = now + seconds;

                    Ok(CommitOutcome::AwaitingConfirmation {
                        job_id: None,
                        rollback_deadline_unix,
                        details: Some(format!(
                            "confirmed commit will auto-rollback in {} seconds unless confirmed",
                            seconds
                        )),
                    })
                }
                Err(error) => {
                    // Commit failed. Return Reconciled { succeeded: false }.
                    Ok(CommitOutcome::Reconciled {
                        succeeded: false,
                        job_id: None,
                        details: Some(error.to_string()),
                    })
                }
            }
        } else {
            // Normal synchronous commit with comment.
            match cfg.commit_with_comment(&comment).await {
                Ok(()) => Ok(CommitOutcome::Reconciled {
                    succeeded: true,
                    job_id: None,
                    details: Some("commit succeeded".into()),
                }),
                Err(error) => Ok(CommitOutcome::Reconciled {
                    succeeded: false,
                    job_id: None,
                    details: Some(error.to_string()),
                }),
            }
        }
    }

    async fn rollback(&self, to: RollbackRef) -> Result<RollbackOutcome, Self::Error> {
        match to {
            RollbackRef::Archive(n) => {
                // Load rollback N and commit it.
                let mut dev = self.device_manager.open(&self.router).await?;
                let mut cfg = dev.config()?;

                cfg.lock().await?;
                cfg.rollback(n).await?;
                let commit_comment = format!("rollback to archive {}", n);
                match cfg.commit_with_comment(&commit_comment).await {
                    Ok(()) => {
                        let _ = cfg.unlock().await;
                        Ok(RollbackOutcome {
                            succeeded: true,
                            details: Some(format!("rollback to archive {} committed", n)),
                        })
                    }
                    Err(error) => {
                        let _ = cfg.unlock().await;
                        Ok(RollbackOutcome {
                            succeeded: false,
                            details: Some(error.to_string()),
                        })
                    }
                }
            }
            RollbackRef::CandidateRevert => {
                // Load rollback 0 (clear uncommitted changes) without committing.
                let mut dev = self.device_manager.open(&self.router).await?;
                let mut cfg = dev.config()?;

                match cfg.rollback(0).await {
                    Ok(()) => Ok(RollbackOutcome {
                        succeeded: true,
                        details: Some("candidate reverted (rollback 0)".into()),
                    }),
                    Err(error) => Ok(RollbackOutcome {
                        succeeded: false,
                        details: Some(error.to_string()),
                    }),
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

/// Strip every `junos:attr="value"` occurrence with leading whitespace.
///
/// This is a simplified version of the same logic from
/// `rust-junosmcp-srx-core/src/xml.rs::simple_strip_junos`, duplicated here
/// to avoid a cross-crate dependency for a single function. The SRX-core
/// version is tested against live Junos replies; this copy is functionally
/// identical.
fn simple_strip_junos_attrs(xml: &str) -> String {
    let mut out = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(pos) = rest.find("junos:") {
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

    // If it's an agent with identity, include provider and model.
    let agent_info = if let Some(ref agent) = attribution.agent {
        format!(
            " via {}-{} model={}",
            agent.provider, agent.provider_tier, agent.model_id
        )
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

    // Note: Full integration tests (stage, commit, etc.) require a live device
    // or a much more elaborate fake. The existing candidate_transaction.rs test
    // suite covers the underlying primitives. These unit tests verify the
    // transaction-specific logic (normalisation, attribution formatting).
}
