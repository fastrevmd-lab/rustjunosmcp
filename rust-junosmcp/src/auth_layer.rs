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
                true,
            )
        }
    };
    let secret = match parse_bearer(header_value) {
        Some(s) => s,
        None => {
            return reject(
                StatusCode::UNAUTHORIZED,
                "Authorization header must use Bearer scheme",
                true,
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
            reject(StatusCode::UNAUTHORIZED, "invalid bearer token", false)
        }
    }
}

fn parse_bearer(v: &HeaderValue) -> Option<&str> {
    let s = v.to_str().ok()?;
    let token = s.strip_prefix("Bearer ")?.trim();
    if token.is_empty() {
        return None;
    }
    Some(token)
}

fn reject(code: StatusCode, msg: &str, include_challenge: bool) -> Response<Body> {
    let mut resp = Response::builder().status(code);
    if include_challenge {
        resp = resp.header(header::WWW_AUTHENTICATE, "Bearer");
    }
    // OK: builder only fails on invalid header values; both `code` and the
    // static "Bearer" challenge are valid by construction.
    resp.body(Body::from(msg.to_string())).unwrap()
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
    fn parse_bearer_case_sensitive_scheme() {
        // RFC 6750 says Bearer is case-insensitive, but our parser is strict
        // on `Bearer ` exactly. Document that behavior here.
        let h = HeaderValue::from_static("bearer abc123");
        assert_eq!(parse_bearer(&h), None);
    }

    #[test]
    fn parse_bearer_rejects_empty_token() {
        let h = HeaderValue::from_static("Bearer ");
        assert_eq!(parse_bearer(&h), None);
    }
}
