//! Tower middleware: extract `Authorization: Bearer ...`, look up the token in
//! the current `Arc<TokenStore>`, and stuff a `CallerCtx` into request
//! extensions. Reject otherwise with HTTP 401.

use crate::CallerCtx;
use axum::{
    body::{Body, to_bytes},
    http::{HeaderValue, Request, Response, StatusCode, header},
    middleware::Next,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthState {
    pub store: Arc<crate::TokenStoreFile>,
    pub preflight: mecmcp_transport::OptionalPreflight,
    pub body_limit: usize,
}

/// RFC 6750 §3 bearer challenge for the "no credentials presented" cases.
/// Bare scheme + realm is sufficient; `error=` is reserved for cases where
/// the client *did* present a token (RFC 6750 §3.1).
const CHALLENGE_NO_CREDENTIALS: &str = r#"Bearer realm="jmcp""#;

/// RFC 6750 §3.1 challenge for the case where the client presented a
/// syntactically-valid bearer token that did not match any known token.
const CHALLENGE_INVALID_TOKEN: &str = r#"Bearer realm="jmcp", error="invalid_token", error_description="The access token is invalid""#;

pub async fn auth_layer(
    axum::extract::State(state): axum::extract::State<AuthState>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let store_snapshot = state.store.store();

    let header_value = match req.headers().get(header::AUTHORIZATION) {
        Some(v) => v,
        None => {
            return reject(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "missing Authorization header",
                CHALLENGE_NO_CREDENTIALS,
            );
        }
    };
    let secret = match parse_bearer(header_value) {
        Some(s) => s,
        None => {
            return reject(
                StatusCode::UNAUTHORIZED,
                "invalid_request",
                "Authorization header must use Bearer scheme",
                CHALLENGE_NO_CREDENTIALS,
            );
        }
    };

    let ctx: CallerCtx = match store_snapshot.authenticate(secret) {
        Some(entry) => entry.into(),
        None => {
            tracing::warn!(
                remote = ?req.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>(),
                "auth_failed: no matching token"
            );
            return reject(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "invalid bearer token",
                CHALLENGE_INVALID_TOKEN,
            );
        }
    };

    // Buffer and limit body size, then run preflight if configured
    let (mut parts, body) = req.into_parts();
    let body_bytes = match to_bytes(body, state.body_limit).await {
        Ok(bytes) => bytes,
        Err(_) => {
            return payload_too_large();
        }
    };

    // Run preflight check if configured
    if let Err(reason) =
        mecmcp_transport::preflight::run_preflight(&state.preflight, &body_bytes, &ctx)
    {
        return forbidden(reason.as_str());
    }

    // Insert CallerCtx for downstream handlers
    parts.extensions.insert(ctx);
    let req = Request::from_parts(parts, Body::from(body_bytes));

    next.run(req).await
}

fn parse_bearer(v: &HeaderValue) -> Option<&str> {
    let s = v.to_str().ok()?;
    let header = s.trim();
    if header.len() < 7 {
        return None;
    }
    if !header[..7].eq_ignore_ascii_case("bearer ") {
        return None;
    }
    let token = header[7..].trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

/// Per RFC 6750 §3, every 401 from a bearer-protected resource MUST carry a
/// `WWW-Authenticate: Bearer ...` challenge. `challenge` is the full header
/// value (e.g. `Bearer realm="jmcp"` or `Bearer realm="jmcp", error="invalid_token"`).
///
/// The response body is the RFC 6749 §5.2 JSON error object
/// (`{"error": "...", "error_description": "..."}`) so MCP clients that parse
/// the body as OAuth-formatted JSON (e.g. the Claude Code SDK) do not choke on
/// a plain-text reason phrase.
fn reject(
    code: StatusCode,
    error_code: &'static str,
    msg: &str,
    challenge: &'static str,
) -> Response<Body> {
    let body = serde_json::json!({
        "error": error_code,
        "error_description": msg,
    })
    .to_string();
    Response::builder()
        .status(code)
        .header(header::WWW_AUTHENTICATE, challenge)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("response builder cannot fail: status, static challenge, and literal content-type are all valid")
}

fn forbidden(reason: &str) -> Response<Body> {
    let body = serde_json::json!({"error": reason}).to_string();
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(
            header::WWW_AUTHENTICATE,
            format!(r#"Bearer realm="jmcp", error="{reason}""#),
        )
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("response builder cannot fail")
}

fn payload_too_large() -> Response<Body> {
    let body = serde_json::json!({"error": "request_too_large"}).to_string();
    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .expect("response builder cannot fail")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_bearer_valid() {
        let h = HeaderValue::from_static("Bearer abc123");
        assert_eq!(parse_bearer(&h), Some("abc123"));
    }

    #[test]
    fn parse_bearer_missing_prefix() {
        let h = HeaderValue::from_static("Basic dXNlcjpwYXNz");
        assert_eq!(parse_bearer(&h), None);
    }

    #[test]
    fn parse_bearer_non_ascii_returns_none() {
        // bytes that are not valid header text (control chars below 0x20 are
        // rejected by HeaderValue::to_str).
        let h = HeaderValue::from_bytes(b"Bearer \xFF\xFE").unwrap();
        assert!(parse_bearer(&h).is_none());
    }

    #[test]
    fn parse_bearer_trims_whitespace() {
        let h = HeaderValue::from_static("Bearer    spaced-token   ");
        assert_eq!(parse_bearer(&h), Some("spaced-token"));
    }

    #[test]
    fn parse_bearer_scheme_case_insensitive_lowercase() {
        // RFC 6750: scheme is case-insensitive; "bearer" must work.
        let h = HeaderValue::from_static("bearer abc123");
        assert_eq!(parse_bearer(&h), Some("abc123"));
    }

    #[test]
    fn parse_bearer_scheme_case_insensitive_uppercase() {
        // RFC 6750: "BEARER" must work.
        let h = HeaderValue::from_static("BEARER abc123");
        assert_eq!(parse_bearer(&h), Some("abc123"));
    }

    #[test]
    fn parse_bearer_scheme_mixed_case() {
        // RFC 6750: "Bearer" (canonical) must continue to work.
        let h = HeaderValue::from_static("Bearer abc123");
        assert_eq!(parse_bearer(&h), Some("abc123"));
    }

    #[test]
    fn parse_bearer_rejects_empty_token() {
        let h = HeaderValue::from_static("Bearer ");
        assert_eq!(parse_bearer(&h), None);
    }
}
