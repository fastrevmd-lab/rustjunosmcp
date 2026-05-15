//! Tower middleware: extract `Authorization: Bearer ...`, look up the token in
//! the current `Arc<TokenStore>`, and stuff a `CallerCtx` into request
//! extensions. Reject otherwise with HTTP 401.

use crate::caller::CallerCtx;
use arc_swap::ArcSwap;
use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response, StatusCode},
    middleware::Next,
};
use rust_junosmcp_auth::TokenStore;
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthState {
    pub store: Arc<ArcSwap<TokenStore>>,
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
    mut req: Request<Body>,
    next: Next,
) -> Response<Body> {
    let store_snapshot = state.store.load_full();

    let header_value = match req.headers().get(header::AUTHORIZATION) {
        Some(v) => v,
        None => {
            return reject(
                StatusCode::UNAUTHORIZED,
                "missing Authorization header",
                CHALLENGE_NO_CREDENTIALS,
            )
        }
    };
    let secret = match parse_bearer(header_value) {
        Some(s) => s,
        None => {
            return reject(
                StatusCode::UNAUTHORIZED,
                "Authorization header must use Bearer scheme",
                CHALLENGE_NO_CREDENTIALS,
            )
        }
    };

    match store_snapshot.find(secret) {
        Some(entry) => {
            let ctx: CallerCtx = entry.into();
            req.extensions_mut().insert(ctx);
            next.run(req).await
        }
        None => {
            tracing::warn!(
                remote = ?req.extensions().get::<axum::extract::ConnectInfo<std::net::SocketAddr>>(),
                "auth_failed: no matching token"
            );
            reject(
                StatusCode::UNAUTHORIZED,
                "invalid bearer token",
                CHALLENGE_INVALID_TOKEN,
            )
        }
    }
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
fn reject(code: StatusCode, msg: &str, challenge: &'static str) -> Response<Body> {
    Response::builder()
        .status(code)
        .header(header::WWW_AUTHENTICATE, challenge)
        .body(Body::from(msg.to_string()))
        // OK: builder only fails on invalid header values; both `code` and the
        // static challenge constants are valid by construction.
        .unwrap()
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
