//! Token mint, hash, and constant-time verify.

use base64ct::{Base64UrlUnpadded, Encoding};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// A freshly-minted token secret. The plaintext leaves the process exactly
/// once (printed by `token add`/`rotate`), so this type holds only the
/// base64url-unpadded ASCII string and is `Drop`-zeroed.
pub struct Secret(String);

impl Secret {
    /// Mint a fresh 32-byte random secret and return the (secret, hash) pair.
    pub fn mint() -> (Self, TokenHash) {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        let s = Base64UrlUnpadded::encode_string(&bytes);
        let hash = TokenHash::from_secret(&s);
        (Secret(s), hash)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // Best-effort zeroize. Not constant-time, but the process is on its way
        // out for token-management subcommands.
        unsafe {
            for b in self.0.as_bytes_mut() {
                std::ptr::write_volatile(b, 0u8);
            }
        }
    }
}

/// SHA-256 hash of a token secret, formatted as `sha256:<base64url-unpadded>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TokenHash(String);

impl TokenHash {
    pub fn from_secret(secret: &str) -> Self {
        let digest = Sha256::digest(secret.as_bytes());
        let s = format!("sha256:{}", Base64UrlUnpadded::encode_string(&digest));
        TokenHash(s)
    }

    pub fn parse(s: &str) -> Result<Self, ParseTokenHashError> {
        let rest = s.strip_prefix("sha256:").ok_or(ParseTokenHashError::MissingPrefix)?;
        if rest.len() != 43 {
            return Err(ParseTokenHashError::WrongLength { got: rest.len() });
        }
        // Validate base64url-unpadded char set by attempting a decode.
        Base64UrlUnpadded::decode_vec(rest)
            .map_err(|_| ParseTokenHashError::NotBase64Url)?;
        Ok(TokenHash(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Constant-time compare: hash this candidate secret and compare against self.
    pub fn verify(&self, candidate_secret: &str) -> bool {
        let candidate = TokenHash::from_secret(candidate_secret);
        self.0.as_bytes().ct_eq(candidate.0.as_bytes()).into()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseTokenHashError {
    #[error("missing 'sha256:' prefix")]
    MissingPrefix,
    #[error("wrong length: expected 43 chars after prefix, got {got}")]
    WrongLength { got: usize },
    #[error("not valid base64url-unpadded")]
    NotBase64Url,
}

impl TryFrom<String> for TokenHash {
    type Error = ParseTokenHashError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        TokenHash::parse(&s)
    }
}

impl From<TokenHash> for String {
    fn from(h: TokenHash) -> String {
        h.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_produces_43_char_base64url_secret() {
        let (secret, _hash) = Secret::mint();
        let s = secret.expose();
        assert_eq!(s.len(), 43, "expected 43-char unpadded base64url, got {}", s.len());
        assert!(s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "non-base64url char in secret: {s:?}");
    }

    #[test]
    fn hash_format_is_sha256_prefix_plus_43_chars() {
        let (_secret, hash) = Secret::mint();
        let s = hash.as_str();
        assert!(s.starts_with("sha256:"), "missing prefix: {s}");
        assert_eq!(s.len(), "sha256:".len() + 43);
    }

    #[test]
    fn verify_matches_correct_secret() {
        let (secret, hash) = Secret::mint();
        assert!(hash.verify(secret.expose()));
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let (_secret, hash) = Secret::mint();
        let (other, _) = Secret::mint();
        assert!(!hash.verify(other.expose()));
    }

    #[test]
    fn parse_hash_from_str_round_trip() {
        let (_secret, hash) = Secret::mint();
        let s = hash.as_str().to_string();
        let parsed = TokenHash::parse(&s).expect("parse");
        assert_eq!(parsed.as_str(), s);
    }

    #[test]
    fn parse_hash_rejects_missing_prefix() {
        assert!(TokenHash::parse("VYV9w8c").is_err());
    }

    #[test]
    fn parse_hash_rejects_wrong_length() {
        assert!(TokenHash::parse("sha256:short").is_err());
    }

    #[test]
    fn parse_hash_rejects_non_base64url() {
        let bad = format!("sha256:{}", "A".repeat(42) + "+");
        assert!(TokenHash::parse(&bad).is_err());
    }
}
