//! Server-issued confirmation artifacts for destructive signature workflows.

use base64ct::{Base64UrlUnpadded, Encoding};
use rand::{rngs::OsRng, RngCore};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const DEFAULT_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_CAPACITY: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmationBinding {
    caller: String,
    router: String,
    device_identity: String,
}

impl ConfirmationBinding {
    pub fn new(caller: Option<&str>, router: &str, device_identity: &str) -> Self {
        Self {
            caller: caller.unwrap_or("unauthenticated").to_string(),
            router: router.to_string(),
            device_identity: device_identity.to_string(),
        }
    }

    pub fn caller(&self) -> &str {
        &self.caller
    }

    pub fn router(&self) -> &str {
        &self.router
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmedPlan {
    pub correlation_id: String,
}

pub fn confirmation_token_for_request<'a>(
    confirm: bool,
    token: Option<&'a str>,
    router: &str,
) -> Result<Option<&'a str>, crate::SrxError> {
    match (
        confirm,
        token.map(str::trim).filter(|value| !value.is_empty()),
    ) {
        (false, None) => Ok(None),
        (false, Some(_)) => Err(crate::SrxError::InvalidInput(
            "confirmation_token requires confirm=true".into(),
        )),
        (true, None) => Err(crate::SrxError::SignaturePackageConfirmationTokenRequired {
            router: router.to_string(),
        }),
        (true, Some(token)) => Ok(Some(token)),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationError {
    Capacity,
    Invalid,
    Expired,
    BindingMismatch,
    PlanDrift,
}

#[derive(Clone)]
pub struct ConfirmationStore {
    inner: Arc<Mutex<HashMap<[u8; 32], PendingConfirmation>>>,
    ttl: Duration,
    capacity: usize,
}

#[derive(Clone)]
struct PendingConfirmation {
    binding: ConfirmationBinding,
    plan_digest: [u8; 32],
    correlation_id: String,
    expires_at: Instant,
}

impl Default for ConfirmationStore {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_CAPACITY)
    }
}

impl ConfirmationStore {
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            ttl,
            capacity,
        }
    }

    /// Store only a SHA-256 digest of the opaque token, then add the raw token
    /// and expiry metadata to the plan returned to the caller.
    pub fn issue(
        &self,
        mut plan: Value,
        binding: ConfirmationBinding,
        correlation_id: &str,
    ) -> Result<Value, ConfirmationError> {
        let now = Instant::now();
        if !plan.is_object() {
            return Err(ConfirmationError::Invalid);
        }
        let expires_at = now
            .checked_add(self.ttl)
            .ok_or(ConfirmationError::Invalid)?;
        let wall_expiry = SystemTime::now()
            .checked_add(self.ttl)
            .ok_or(ConfirmationError::Invalid)?;
        let expiry = OffsetDateTime::from(wall_expiry)
            .format(&Rfc3339)
            .map_err(|_| ConfirmationError::Invalid)?;
        let plan_digest = digest_plan(&plan);

        let mut entries = self.entries();
        entries.retain(|_, pending| pending.expires_at > now);
        if entries.len() >= self.capacity {
            tracing::warn!(
                event = "signature_confirmation_rejected",
                reason = "capacity",
                caller = %binding.caller(),
                router = %binding.router(),
                correlation_id,
                "could not issue destructive signature-package confirmation"
            );
            return Err(ConfirmationError::Capacity);
        }

        let (token, token_digest) = loop {
            let mut token_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut token_bytes);
            let token = Base64UrlUnpadded::encode_string(&token_bytes);
            let digest = digest_bytes(token.as_bytes());
            if !entries.contains_key(&digest) {
                break (token, digest);
            }
        };

        entries.insert(
            token_digest,
            PendingConfirmation {
                binding: binding.clone(),
                plan_digest,
                correlation_id: correlation_id.to_string(),
                expires_at,
            },
        );
        drop(entries);

        let Value::Object(object) = &mut plan else {
            return Err(ConfirmationError::Invalid);
        };
        object.insert("confirmation_token".into(), Value::String(token));
        object.insert("confirmation_expires_at".into(), Value::String(expiry));
        object.insert(
            "correlation_id".into(),
            Value::String(correlation_id.to_string()),
        );

        tracing::info!(
            event = "signature_confirmation_issued",
            caller = %binding.caller(),
            router = %binding.router(),
            correlation_id,
            ttl_seconds = self.ttl.as_secs(),
            "issued destructive signature-package confirmation"
        );
        Ok(plan)
    }

    /// Reject unknown, expired, or mis-bound artifacts before opening a device
    /// session. The later [`Self::consume`] call repeats these checks and adds
    /// the freshly recomputed plan comparison atomically.
    pub fn validate_binding(
        &self,
        token: &str,
        binding: &ConfirmationBinding,
    ) -> Result<(), ConfirmationError> {
        let token_digest = digest_bytes(token.as_bytes());
        let now = Instant::now();
        let mut entries = self.entries();
        let Some(pending) = entries.get(&token_digest).cloned() else {
            tracing::warn!(
                event = "signature_confirmation_rejected",
                reason = "invalid_or_replayed",
                caller = %binding.caller(),
                router = %binding.router(),
                "rejected destructive signature-package confirmation"
            );
            return Err(ConfirmationError::Invalid);
        };
        if pending.expires_at <= now {
            entries.remove(&token_digest);
            tracing::warn!(
                event = "signature_confirmation_rejected",
                reason = "expired",
                caller = %binding.caller(),
                router = %binding.router(),
                correlation_id = %pending.correlation_id,
                "rejected destructive signature-package confirmation"
            );
            return Err(ConfirmationError::Expired);
        }
        if &pending.binding != binding {
            tracing::warn!(
                event = "signature_confirmation_rejected",
                reason = "binding_mismatch",
                caller = %binding.caller(),
                router = %binding.router(),
                correlation_id = %pending.correlation_id,
                "rejected destructive signature-package confirmation"
            );
            return Err(ConfirmationError::BindingMismatch);
        }
        Ok(())
    }

    /// Validate all bindings and the freshly recomputed plan, then consume the
    /// token atomically so a retry or concurrent replay cannot execute twice.
    pub fn consume(
        &self,
        token: &str,
        binding: &ConfirmationBinding,
        current_plan: &Value,
    ) -> Result<ConfirmedPlan, ConfirmationError> {
        let token_digest = digest_bytes(token.as_bytes());
        let now = Instant::now();
        let mut entries = self.entries();
        let Some(pending) = entries.get(&token_digest).cloned() else {
            tracing::warn!(
                event = "signature_confirmation_rejected",
                reason = "invalid_or_replayed",
                caller = %binding.caller(),
                router = %binding.router(),
                "rejected destructive signature-package confirmation"
            );
            return Err(ConfirmationError::Invalid);
        };

        if pending.expires_at <= now {
            entries.remove(&token_digest);
            tracing::warn!(
                event = "signature_confirmation_rejected",
                reason = "expired",
                caller = %binding.caller(),
                router = %binding.router(),
                correlation_id = %pending.correlation_id,
                "rejected destructive signature-package confirmation"
            );
            return Err(ConfirmationError::Expired);
        }
        if &pending.binding != binding {
            tracing::warn!(
                event = "signature_confirmation_rejected",
                reason = "binding_mismatch",
                caller = %binding.caller(),
                router = %binding.router(),
                correlation_id = %pending.correlation_id,
                "rejected destructive signature-package confirmation"
            );
            return Err(ConfirmationError::BindingMismatch);
        }
        if pending.plan_digest != digest_plan(current_plan) {
            entries.remove(&token_digest);
            tracing::warn!(
                event = "signature_confirmation_rejected",
                reason = "plan_drift",
                caller = %binding.caller(),
                router = %binding.router(),
                correlation_id = %pending.correlation_id,
                "rejected destructive signature-package confirmation"
            );
            return Err(ConfirmationError::PlanDrift);
        }

        entries.remove(&token_digest);
        tracing::info!(
            event = "signature_confirmation_consumed",
            caller = %binding.caller(),
            router = %binding.router(),
            correlation_id = %pending.correlation_id,
            "consumed destructive signature-package confirmation"
        );
        Ok(ConfirmedPlan {
            correlation_id: pending.correlation_id,
        })
    }

    fn entries(&self) -> MutexGuard<'_, HashMap<[u8; 32], PendingConfirmation>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl ConfirmationError {
    pub fn into_srx_error(self, router: &str) -> crate::SrxError {
        match self {
            Self::Capacity => crate::SrxError::SignaturePackageConfirmationCapacityExceeded {
                router: router.to_string(),
            },
            Self::PlanDrift => crate::SrxError::SignaturePackageConfirmationPlanDrift {
                router: router.to_string(),
            },
            Self::Expired => crate::SrxError::SignaturePackageConfirmationTokenInvalid {
                router: router.to_string(),
                reason: "confirmation token expired; request a new preview",
            },
            Self::BindingMismatch => crate::SrxError::SignaturePackageConfirmationTokenInvalid {
                router: router.to_string(),
                reason: "confirmation token does not belong to this caller, router, or device",
            },
            Self::Invalid => crate::SrxError::SignaturePackageConfirmationTokenInvalid {
                router: router.to_string(),
                reason: "confirmation token is invalid or has already been used",
            },
        }
    }
}

fn digest_plan(plan: &Value) -> [u8; 32] {
    let bytes = serde_json::to_vec(plan).expect("serde_json::Value serialization cannot fail");
    digest_bytes(&bytes)
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn binding(caller: &str) -> ConfirmationBinding {
        ConfirmationBinding::new(Some(caller), "srx-01", "srx-01|192.0.2.1|830|netconf")
    }

    fn issued(store: &ConfirmationStore, caller: &str) -> Value {
        store
            .issue(
                json!({
                    "code": "confirmation_required",
                    "router": "srx-01",
                    "service": "idp",
                    "action": "download_and_install",
                    "target_package_version": "3910"
                }),
                binding(caller),
                "req-123",
            )
            .unwrap()
    }

    fn token(plan: &Value) -> &str {
        plan["confirmation_token"].as_str().unwrap()
    }

    fn bare_plan() -> Value {
        json!({
            "code": "confirmation_required",
            "router": "srx-01",
            "service": "idp",
            "action": "download_and_install",
            "target_package_version": "3910"
        })
    }

    #[test]
    fn valid_token_is_one_time_and_preserves_correlation() {
        let store = ConfirmationStore::default();
        let plan = issued(&store, "alice");
        assert_eq!(plan["correlation_id"], "req-123");
        assert!(plan["confirmation_expires_at"].as_str().is_some());
        assert_eq!(token(&plan).len(), 43, "expected 256-bit base64url token");
        let confirmed = store
            .consume(token(&plan), &binding("alice"), &bare_plan())
            .unwrap();
        assert_eq!(confirmed.correlation_id, "req-123");
        assert_eq!(
            store.consume(token(&plan), &binding("alice"), &bare_plan()),
            Err(ConfirmationError::Invalid)
        );
    }

    #[test]
    fn token_is_bound_to_caller_without_letting_attacker_consume_it() {
        let store = ConfirmationStore::default();
        let plan = issued(&store, "alice");
        assert_eq!(
            store.consume(token(&plan), &binding("mallory"), &bare_plan()),
            Err(ConfirmationError::BindingMismatch)
        );
        assert!(store
            .consume(token(&plan), &binding("alice"), &bare_plan())
            .is_ok());
    }

    #[test]
    fn binding_can_be_checked_before_device_preflight_without_consuming_token() {
        let store = ConfirmationStore::default();
        let plan = issued(&store, "alice");
        store
            .validate_binding(token(&plan), &binding("alice"))
            .unwrap();
        assert!(store
            .consume(token(&plan), &binding("alice"), &bare_plan())
            .is_ok());
    }

    #[test]
    fn token_is_bound_to_router_and_device_identity() {
        let store = ConfirmationStore::default();
        let plan = issued(&store, "alice");
        let wrong_device =
            ConfirmationBinding::new(Some("alice"), "srx-01", "srx-01|192.0.2.99|830|netconf");
        assert_eq!(
            store.consume(token(&plan), &wrong_device, &bare_plan()),
            Err(ConfirmationError::BindingMismatch)
        );
    }

    #[test]
    fn material_plan_drift_invalidates_token() {
        let store = ConfirmationStore::default();
        let plan = issued(&store, "alice");
        let mut drifted = bare_plan();
        drifted["target_package_version"] = json!("3911");
        assert_eq!(
            store.consume(token(&plan), &binding("alice"), &drifted),
            Err(ConfirmationError::PlanDrift)
        );
        assert_eq!(
            store.consume(token(&plan), &binding("alice"), &bare_plan()),
            Err(ConfirmationError::Invalid)
        );
    }

    #[test]
    fn action_change_is_material_plan_drift() {
        let store = ConfirmationStore::default();
        let plan = issued(&store, "alice");
        let mut drifted = bare_plan();
        drifted["action"] = json!("rollback");
        assert_eq!(
            store.consume(token(&plan), &binding("alice"), &drifted),
            Err(ConfirmationError::PlanDrift)
        );
    }

    #[test]
    fn concurrent_replay_allows_exactly_one_consumer() {
        let store = ConfirmationStore::default();
        let plan = issued(&store, "alice");
        let token = token(&plan).to_string();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let token = token.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.consume(&token, &binding("alice"), &bare_plan())
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| { result.as_ref().err() == Some(&ConfirmationError::Invalid) })
                .count(),
            1
        );
    }

    #[test]
    fn tampered_token_is_rejected() {
        let store = ConfirmationStore::default();
        let plan = issued(&store, "alice");
        let tampered = format!("{}x", token(&plan));
        assert_eq!(
            store.consume(&tampered, &binding("alice"), &bare_plan()),
            Err(ConfirmationError::Invalid)
        );
    }

    #[test]
    fn expired_token_is_rejected_and_removed() {
        let store = ConfirmationStore::new(Duration::ZERO, 2);
        let plan = issued(&store, "alice");
        assert_eq!(
            store.consume(token(&plan), &binding("alice"), &bare_plan()),
            Err(ConfirmationError::Expired)
        );
        assert_eq!(
            store.consume(token(&plan), &binding("alice"), &bare_plan()),
            Err(ConfirmationError::Invalid)
        );
    }

    #[test]
    fn capacity_is_bounded() {
        let store = ConfirmationStore::new(Duration::from_secs(60), 1);
        let _ = issued(&store, "alice");
        assert_eq!(
            store.issue(bare_plan(), binding("bob"), "req-456"),
            Err(ConfirmationError::Capacity)
        );
    }

    #[test]
    fn bare_confirm_true_is_rejected() {
        let err = confirmation_token_for_request(true, None, "srx-01").unwrap_err();
        assert!(matches!(
            err,
            crate::SrxError::SignaturePackageConfirmationTokenRequired { .. }
        ));
    }

    #[test]
    fn preview_rejects_supplied_token_and_execution_accepts_nonempty_token() {
        assert!(matches!(
            confirmation_token_for_request(false, Some("token"), "srx-01"),
            Err(crate::SrxError::InvalidInput(_))
        ));
        assert_eq!(
            confirmation_token_for_request(true, Some("  token  "), "srx-01").unwrap(),
            Some("token")
        );
    }
}
