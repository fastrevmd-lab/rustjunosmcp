//! `transfer_file` MCP tool. SCP a pre-staged file from the host's staging
//! directory to a Junos device's /var/tmp/, with idempotent skip and
//! pre/post-transfer sha256 verification.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::cancel::{select_cancel, select_cancel_raw};
use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::tools::TransferFileArgs;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

/// Required free-space headroom on `/var` beyond the local file size, in bytes.
/// Junos needs working room for temp files and metadata; 32 MiB is generous
/// enough to absorb log churn during a multi-GB upload without false negatives.
pub(crate) const MIN_FREE_HEADROOM_BYTES: u64 = 32 * 1024 * 1024;

/// Format a 32-byte sha256 digest as 64 lowercase hex characters.
pub(crate) fn hex32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(&mut s, "{:02x}", b);
    }
    s
}

/// Scrub OpenSSH/scp stderr before it lands in a `JmcpError::ScpFailed`
/// surfaced to the MCP caller. Redacts:
/// - absolute filesystem paths (e.g. `/root/.ssh/id_ed25519`, `/var/tmp/x`)
///   → `<path>`
/// - IPv4 dotted-quad addresses (e.g. `192.168.1.10`) → `<host>`
///
/// Rationale (issue #26, L1): in a multi-tenant or less-trusted deployment,
/// raw `scp` stderr leaks the operator's filesystem layout (private-key
/// paths, staging dir locations) and the device's IP. Both are unnecessary
/// for diagnosing the underlying error reason, which we keep verbatim.
/// In single-operator labs this is cosmetic; in shared deployments it
/// matters.
pub(crate) fn scrub_scp_stderr(stderr: &str) -> String {
    let mut out = String::with_capacity(stderr.len());
    let bytes = stderr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];

        // Absolute path: starts with '/' and contains only path-safe ASCII.
        // We accept the run of `[A-Za-z0-9./_+-]` after the leading '/'.
        // Requires at least one non-'/' char after to avoid matching bare '/'.
        if b == b'/' {
            let mut j = i + 1;
            while j < bytes.len() && is_path_byte(bytes[j]) {
                j += 1;
            }
            if j > i + 1 {
                out.push_str("<path>");
                i = j;
                continue;
            }
        }

        // IPv4 dotted-quad: greedy match of d{1,3}(.d{1,3}){3}.
        if b.is_ascii_digit() {
            if let Some(end) = match_ipv4(&bytes[i..]) {
                out.push_str("<host>");
                i += end;
                continue;
            }
        }

        // Default: copy byte through. Safe because we only consume valid
        // UTF-8 boundaries above (the substituted matches are all ASCII).
        out.push(b as char);
        i += 1;
    }
    out
}

fn is_path_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+')
}

/// If `bytes` starts with an IPv4 dotted-quad (`d{1,3}.d{1,3}.d{1,3}.d{1,3}`)
/// not followed by another digit or '.', return the byte length consumed.
fn match_ipv4(bytes: &[u8]) -> Option<usize> {
    let mut idx = 0;
    for octet in 0..4 {
        // 1 to 3 digits
        let start = idx;
        while idx < bytes.len() && idx - start < 3 && bytes[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx == start {
            return None;
        }
        if octet < 3 {
            if idx >= bytes.len() || bytes[idx] != b'.' {
                return None;
            }
            idx += 1;
        }
    }
    // Must not be followed by another digit or '.' (would mean it's a longer
    // numeric token, not an address).
    if let Some(&next) = bytes.get(idx) {
        if next.is_ascii_digit() || next == b'.' {
            return None;
        }
    }
    Some(idx)
}

/// Build the JSON response returned when the destination already holds a file
/// with the same sha256 (idempotent skip). Kept as a pure helper so the shape
/// is unit-testable without standing up a DeviceManager.
pub(crate) fn skipped_response(basename: &str, sha: &[u8; 32], size: u64) -> Value {
    json!({
        "status": "skipped",
        "remote_path": format!("/var/tmp/{}", basename),
        "size_bytes": size,
        "sha256": hex32(sha),
        "verified": true,
        "message": "destination already present with matching sha256; no transfer performed",
    })
}

/// Validate that `source_path` is a safe basename. Rejects:
/// - empty
/// - longer than 255 bytes
/// - leading '.' (dotfiles)
/// - ".." anywhere (whole name or embedded, e.g. "a..b")
/// - any '/', '\\', or "..".
/// - any byte outside the ASCII allowlist `[A-Za-z0-9._-]`. This implicitly
///   rejects NUL bytes, ASCII control chars, and *all* non-ASCII Unicode —
///   including RTL overrides (U+202E), zero-width joiners, and homoglyph
///   scripts that could mask the true filename in operator logs or shell
///   expansions. Junos image / config artifacts are always plain ASCII so
///   this allowlist is non-restrictive in practice. (issue #26, L2)
pub fn validate_source_basename(source: &str) -> Result<(), JmcpError> {
    if source.is_empty() {
        return Err(JmcpError::BadSourcePath("source_path is empty".into()));
    }
    if source.len() > 255 {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path exceeds 255 bytes (got {})",
            source.len()
        )));
    }
    if source.starts_with('.') {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not start with '.'"
        )));
    }
    if source.contains('/') || source.contains('\\') {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not contain '/' or '\\\\' (basename only)"
        )));
    }
    if source.contains("..") {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' must not contain '..'"
        )));
    }
    // ASCII allowlist: [A-Za-z0-9._-] only. Scan bytes so non-ASCII (multi-
    // byte UTF-8) is rejected without needing to enumerate Unicode classes.
    if let Some(bad) = source
        .bytes()
        .find(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')))
    {
        return Err(JmcpError::BadSourcePath(format!(
            "source_path '{source}' contains disallowed byte 0x{bad:02x}; only [A-Za-z0-9._-] are permitted"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod scrub_tests {
    use super::*;

    #[test]
    fn redacts_absolute_path() {
        let s = scrub_scp_stderr("Load key \"/root/.ssh/id_ed25519\": invalid format");
        assert!(s.contains("<path>"), "{s}");
        assert!(!s.contains("/root"), "{s}");
        assert!(s.contains("invalid format"), "{s}");
    }

    #[test]
    fn redacts_ipv4_address() {
        let s = scrub_scp_stderr("ssh: connect to host 192.168.1.10 port 22: Connection timed out");
        assert!(s.contains("<host>"), "{s}");
        assert!(!s.contains("192.168"), "{s}");
        assert!(s.contains("Connection timed out"), "{s}");
        // "port 22" is left as-is — it's a service port number, not host info.
        assert!(s.contains("port 22"), "{s}");
    }

    #[test]
    fn redacts_multiple_paths_in_one_line() {
        let s =
            scrub_scp_stderr("scp: /var/tmp/foo.tgz: No such file or directory; checked /var/run");
        assert!(!s.contains("/var"), "{s}");
        assert_eq!(s.matches("<path>").count(), 2, "{s}");
        assert!(s.contains("No such file or directory"), "{s}");
    }

    #[test]
    fn keeps_diagnostic_text() {
        let s = scrub_scp_stderr("Permission denied (publickey).");
        // No paths or IPs to redact — message must pass through verbatim.
        assert_eq!(s, "Permission denied (publickey).");
    }

    #[test]
    fn preserves_newlines_and_structure() {
        let input = "line1: /a/b\nline2: 10.0.0.1\nline3: ok";
        let s = scrub_scp_stderr(input);
        assert_eq!(s.lines().count(), 3, "{s}");
        assert!(s.contains("<path>"));
        assert!(s.contains("<host>"));
        assert!(s.contains("ok"));
    }

    #[test]
    fn does_not_match_partial_ipv4() {
        // 1.2.3 is not a complete dotted-quad and must pass through.
        let s = scrub_scp_stderr("version 1.2.3 detected");
        assert_eq!(s, "version 1.2.3 detected");
    }

    #[test]
    fn does_not_match_bare_digits() {
        // Single number with no dots is not an IPv4 address.
        let s = scrub_scp_stderr("exit code 42");
        assert_eq!(s, "exit code 42");
    }

    #[test]
    fn leaves_bare_slash_alone() {
        // Single '/' with no following path chars should not become <path>.
        let s = scrub_scp_stderr("a / b");
        assert_eq!(s, "a / b");
    }
}

#[cfg(test)]
mod validate_tests {
    use super::*;

    #[test]
    fn accepts_plain_basename() {
        assert!(validate_source_basename("junos-25.4R1.12.tgz").is_ok());
    }

    #[test]
    fn accepts_ascii_with_dots_in_middle() {
        assert!(validate_source_basename("a.b.c.tgz").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(
            validate_source_basename(""),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_too_long() {
        let s = "a".repeat(256);
        assert!(matches!(
            validate_source_basename(&s),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_leading_dot() {
        assert!(matches!(
            validate_source_basename(".hidden"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_dotdot_anywhere() {
        assert!(matches!(
            validate_source_basename("a..b"),
            Err(JmcpError::BadSourcePath(_))
        ));
        assert!(matches!(
            validate_source_basename(".."),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_forward_slash() {
        assert!(matches!(
            validate_source_basename("dir/file.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_backslash() {
        assert!(matches!(
            validate_source_basename("dir\\file.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_absolute_path() {
        assert!(matches!(
            validate_source_basename("/etc/passwd"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn accepts_max_length_255() {
        assert!(validate_source_basename(&"a".repeat(255)).is_ok());
    }

    // ----- issue #26 L2: allowlist hardening -----

    #[test]
    fn rejects_nul_byte() {
        assert!(matches!(
            validate_source_basename("file\0.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_ascii_control_chars() {
        // newline, tab, BEL
        for c in ["a\nb", "a\tb", "a\x07b"] {
            assert!(
                matches!(
                    validate_source_basename(c),
                    Err(JmcpError::BadSourcePath(_))
                ),
                "should reject {c:?}"
            );
        }
    }

    #[test]
    fn rejects_space() {
        assert!(matches!(
            validate_source_basename("a b.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_unicode_rtl_override() {
        // U+202E RIGHT-TO-LEFT OVERRIDE — used in filename-spoofing attacks.
        assert!(matches!(
            validate_source_basename("file\u{202e}gpj.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_unicode_lookalike() {
        // Cyrillic 'а' (U+0430) instead of Latin 'a'.
        assert!(matches!(
            validate_source_basename("\u{0430}bc.tgz"),
            Err(JmcpError::BadSourcePath(_))
        ));
    }

    #[test]
    fn rejects_shell_metacharacters() {
        for c in ["a;b", "a|b", "a&b", "a$b", "a`b", "a*b", "a?b"] {
            assert!(
                matches!(
                    validate_source_basename(c),
                    Err(JmcpError::BadSourcePath(_))
                ),
                "should reject {c:?}"
            );
        }
    }
}

/// Stream a file from disk and return (sha256, size_bytes). Runs the actual
/// hashing on a blocking thread to keep the tokio runtime healthy on multi-GB
/// files (~3-5 s for 1.3 GB on the LXC).
pub async fn sha256_file(path: &Path) -> Result<([u8; 32], u64), JmcpError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<([u8; 32], u64), JmcpError> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut f = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut size: u64 = 0;
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        let out: [u8; 32] = hasher.finalize().into();
        Ok((out, size))
    })
    .await
    .map_err(|e| JmcpError::Io(std::io::Error::other(e)))?
}

/// Cancel-aware variant of [`sha256_file`]. Checks `ct.is_cancelled()`
/// between every 64 KiB read block (~5 ms cadence at SATA SSD speeds),
/// and additionally races the `JoinHandle` against `ct.cancelled()` so a
/// wedged blocking syscall doesn't keep us blocked past the cancel.
///
/// Used by `transfer_file::handle` and `upgrade_junos::run`. The
/// non-cancellable [`sha256_file`] is preserved for downstream callers
/// (and the `sha_tests` module).
pub(crate) async fn sha256_file_cancellable(
    path: &Path,
    ct: &CancellationToken,
) -> Result<([u8; 32], u64), JmcpError> {
    let path = path.to_path_buf();
    let inner_ct = ct.clone();
    let handle = tokio::task::spawn_blocking(move || -> Result<([u8; 32], u64), JmcpError> {
        use sha2::{Digest, Sha256};
        use std::io::Read;
        let mut f = std::fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut size: u64 = 0;
        loop {
            // Cancel check between blocks. For a 1.3 GB image at ~250 MB/s
            // this is ~5 ms per check — fast cancel without measurable
            // hashing overhead.
            if inner_ct.is_cancelled() {
                return Err(JmcpError::Cancelled);
            }
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            size += n as u64;
        }
        let out: [u8; 32] = hasher.finalize().into();
        Ok((out, size))
    });
    tokio::select! {
        biased;
        _ = ct.cancelled() => {
            // The spawn_blocking thread will notice on its next iteration
            // and return Cancelled; we don't await it (leak-acceptable for
            // a finite-duration hash).
            Err(JmcpError::Cancelled)
        }
        r = handle => r.map_err(|e| JmcpError::Io(std::io::Error::other(e)))?,
    }
}

#[cfg(test)]
mod sha_tests {
    use super::*;
    use std::io::Write;

    fn hex_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write as _;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    #[tokio::test]
    async fn hashes_empty_file() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let (h, n) = sha256_file(f.path()).await.unwrap();
        assert_eq!(n, 0);
        assert_eq!(
            hex_lower(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[tokio::test]
    async fn hashes_known_vector_abc() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        f.flush().unwrap();
        let (h, n) = sha256_file(f.path()).await.unwrap();
        assert_eq!(n, 3);
        assert_eq!(
            hex_lower(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn nonexistent_file_returns_io_error() {
        let r = sha256_file(Path::new("/nonexistent/jmcp/file")).await;
        assert!(matches!(r, Err(JmcpError::Io(_))));
    }

    /// T2 (issue #44 Half A): `sha256_file_cancellable` short-circuits to
    /// `JmcpError::Cancelled` when the caller's token is already cancelled
    /// before the helper is awaited.
    #[tokio::test]
    async fn sha256_cancellable_pre_cancelled_returns_cancelled() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"abc").unwrap();
        f.flush().unwrap();
        let ct = CancellationToken::new();
        ct.cancel();
        let r = sha256_file_cancellable(f.path(), &ct).await;
        assert!(
            matches!(r, Err(JmcpError::Cancelled)),
            "expected Cancelled, got {r:?}"
        );
    }
}

/// Inputs for one SCP invocation. All fields owned strings/paths so the
/// runner can `tokio::process::Command::new("scp").args(...)` without further
/// shell escaping.
#[derive(Clone, Debug)]
pub struct ScpJob {
    pub private_key_path: PathBuf,
    pub known_hosts_file: PathBuf,
    pub username: String,
    pub host: String,
    pub port: u16,
    pub local_path: PathBuf,
    pub remote_dir: String, // e.g. "/var/tmp/"
    /// When `true`, emit `StrictHostKeyChecking=accept-new` (TOFU); when
    /// `false`, emit `StrictHostKeyChecking=yes` (strict — refuses unknown
    /// host keys). Default for the server is `false` as of v0.5.2; opt in
    /// via `--ssh-accept-new-host-keys` for lab provisioning.
    pub accept_new_host_keys: bool,
}

/// Build the argv vector that `OpenSshScpRunner` will hand to `scp`. Pulled
/// out so it can be asserted exactly in unit tests without spawning a process.
pub fn build_scp_argv(job: &ScpJob) -> Vec<String> {
    let dest = format!("{}@{}:{}", job.username, job.host, job.remote_dir);
    let host_key_policy = if job.accept_new_host_keys {
        "StrictHostKeyChecking=accept-new"
    } else {
        "StrictHostKeyChecking=yes"
    };
    vec![
        "-O".into(),
        "-i".into(),
        job.private_key_path.display().to_string(),
        "-o".into(),
        host_key_policy.into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", job.known_hosts_file.display()),
        "-o".into(),
        "ConnectTimeout=15".into(),
        "-o".into(),
        "ServerAliveInterval=10".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        // Hardening: never prompt, never fall back to password / kbd-int /
        // ssh-agent identities. The configured -i key is the only credential
        // scp may use. BatchMode also disables tty-based prompts so a hung
        // server can't block forever.
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-P".into(),
        job.port.to_string(),
        job.local_path.display().to_string(),
        dest,
    ]
}

/// Inputs for one SCP download invocation. Mirror image of [`ScpJob`].
/// The remote_path is the FULL path on the device (e.g. `/var/tmp/foo.tgz`),
/// not a directory — `scp` downloads exactly one file.
#[derive(Clone, Debug)]
pub struct ScpFetchJob {
    pub private_key_path: PathBuf,
    pub known_hosts_file: PathBuf,
    pub username: String,
    pub host: String,
    pub port: u16,
    /// Full remote path, e.g. `/var/tmp/foo.tgz`.
    pub remote_path: String,
    /// Full local destination path under the staging directory.
    pub local_path: PathBuf,
    /// When `true`, emit `StrictHostKeyChecking=accept-new` (TOFU); when
    /// `false`, emit `StrictHostKeyChecking=yes` (strict — refuses unknown
    /// host keys). Default for the server is `false` as of v0.5.2; opt in
    /// via `--ssh-accept-new-host-keys` for lab provisioning.
    pub accept_new_host_keys: bool,
}

/// Build the argv vector that downloads `remote_path` from the device to
/// `local_path`. Mirror image of [`build_scp_argv`]: the only structural
/// difference is that the source (user@host:path) comes before the local
/// destination, instead of after the local source.
pub fn build_scp_fetch_argv(job: &ScpFetchJob) -> Vec<String> {
    let source = format!("{}@{}:{}", job.username, job.host, job.remote_path);
    let host_key_policy = if job.accept_new_host_keys {
        "StrictHostKeyChecking=accept-new"
    } else {
        "StrictHostKeyChecking=yes"
    };
    vec![
        "-O".into(),
        "-i".into(),
        job.private_key_path.display().to_string(),
        "-o".into(),
        host_key_policy.into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", job.known_hosts_file.display()),
        "-o".into(),
        "ConnectTimeout=15".into(),
        "-o".into(),
        "ServerAliveInterval=10".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "PasswordAuthentication=no".into(),
        "-o".into(),
        "PreferredAuthentications=publickey".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-P".into(),
        job.port.to_string(),
        source,
        job.local_path.display().to_string(),
    ]
}

#[cfg(test)]
mod argv_tests {
    use super::*;

    fn job() -> ScpJob {
        ScpJob {
            private_key_path: "/etc/jmcp/keys/id".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            local_path: "/var/lib/jmcp/staging/foo.tgz".into(),
            remote_dir: "/var/tmp/".into(),
            accept_new_host_keys: false,
        }
    }

    #[test]
    fn argv_uses_dash_capital_o_for_legacy_protocol() {
        // Junos disables SFTP-over-SSH; -O forces SCP1 wire protocol.
        let v = build_scp_argv(&job());
        assert_eq!(v[0], "-O");
    }

    #[test]
    fn argv_default_uses_strict_host_key_checking_yes() {
        // RJMCP-SEC-004: default policy is strict; TOFU is opt-in.
        let v = build_scp_argv(&job());
        let joined = v.join(" ");
        assert!(
            joined.contains("StrictHostKeyChecking=yes"),
            "expected strict default, got: {joined}"
        );
        assert!(
            !joined.contains("accept-new"),
            "default must not emit accept-new, got: {joined}"
        );
        assert!(joined.contains("UserKnownHostsFile=/etc/jmcp/known_hosts"));
    }

    #[test]
    fn argv_flips_to_accept_new_when_flag_set() {
        let v = build_scp_argv(&ScpJob {
            accept_new_host_keys: true,
            ..job()
        });
        let joined = v.join(" ");
        assert!(
            joined.contains("StrictHostKeyChecking=accept-new"),
            "expected accept-new with flag set, got: {joined}"
        );
        assert!(
            !joined.contains("StrictHostKeyChecking=yes"),
            "must not also emit strict, got: {joined}"
        );
    }

    #[test]
    fn argv_includes_hardening_flags() {
        // Pin the hardened auth posture: no password fallback, no agent keys,
        // no interactive prompts. Regressing any of these would silently widen
        // the credential surface scp uses on every push.
        let v = build_scp_argv(&job());
        let joined = v.join(" ");
        assert!(joined.contains("BatchMode=yes"));
        assert!(joined.contains("PasswordAuthentication=no"));
        assert!(joined.contains("PreferredAuthentications=publickey"));
        assert!(joined.contains("IdentitiesOnly=yes"));
    }

    #[test]
    fn argv_includes_connect_and_alive_timeouts() {
        let v = build_scp_argv(&job());
        let joined = v.join(" ");
        assert!(joined.contains("ConnectTimeout=15"));
        assert!(joined.contains("ServerAliveInterval=10"));
        assert!(joined.contains("ServerAliveCountMax=3"));
    }

    #[test]
    fn argv_uses_uppercase_p_for_port() {
        let v = build_scp_argv(&ScpJob {
            port: 2200,
            ..job()
        });
        let i = v.iter().position(|s| s == "-P").expect("has -P");
        assert_eq!(v[i + 1], "2200");
    }

    #[test]
    fn argv_dest_is_username_host_colon_dir() {
        let v = build_scp_argv(&job());
        assert_eq!(v.last().unwrap(), "root@10.0.0.1:/var/tmp/");
    }

    #[test]
    fn argv_local_path_appears_before_dest() {
        let v = build_scp_argv(&job());
        let local = v
            .iter()
            .position(|s| s == "/var/lib/jmcp/staging/foo.tgz")
            .unwrap();
        let dest = v.iter().position(|s| s.starts_with("root@")).unwrap();
        assert!(local < dest);
    }

    fn fetch_job() -> ScpFetchJob {
        ScpFetchJob {
            private_key_path: "/etc/jmcp/keys/id".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            remote_path: "/var/tmp/foo.tgz".into(),
            local_path: "/var/lib/jmcp/staging/foo.tgz".into(),
            accept_new_host_keys: false,
        }
    }

    #[test]
    fn fetch_argv_uses_dash_capital_o_for_legacy_protocol() {
        let v = build_scp_fetch_argv(&fetch_job());
        assert_eq!(v[0], "-O");
    }

    #[test]
    fn fetch_argv_default_uses_strict_host_key_checking_yes() {
        let v = build_scp_fetch_argv(&fetch_job());
        let joined = v.join(" ");
        assert!(joined.contains("StrictHostKeyChecking=yes"), "{joined}");
        assert!(!joined.contains("accept-new"), "{joined}");
    }

    #[test]
    fn fetch_argv_source_is_user_host_colon_remote_path() {
        let v = build_scp_fetch_argv(&fetch_job());
        let src = v
            .iter()
            .position(|s| s == "root@10.0.0.1:/var/tmp/foo.tgz")
            .expect("source present");
        let dst = v
            .iter()
            .position(|s| s == "/var/lib/jmcp/staging/foo.tgz")
            .expect("dest present");
        assert!(src < dst, "expected source before dest, got argv: {v:?}");
    }

    #[test]
    fn fetch_argv_includes_hardening_flags() {
        let v = build_scp_fetch_argv(&fetch_job());
        let joined = v.join(" ");
        assert!(joined.contains("BatchMode=yes"));
        assert!(joined.contains("PasswordAuthentication=no"));
        assert!(joined.contains("PreferredAuthentications=publickey"));
        assert!(joined.contains("IdentitiesOnly=yes"));
    }
}

/// Outcome of a single SCP invocation.
#[derive(Clone, Debug)]
pub struct ScpOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

#[async_trait::async_trait]
pub trait ScpRunner: Send + Sync {
    /// Run the SCP job, racing against `ct.cancelled()`. On cancel,
    /// production impls MUST kill the underlying child process (or
    /// otherwise abort the work) and return
    /// `std::io::Error::new(ErrorKind::Interrupted, "cancelled")` so
    /// the caller can map it to `JmcpError::Cancelled`.
    async fn run(&self, job: &ScpJob, ct: &CancellationToken) -> std::io::Result<ScpOutcome>;
}

/// Production runner — shells out to `scp` from system openssh-client.
pub struct OpenSshScpRunner;

#[async_trait::async_trait]
impl ScpRunner for OpenSshScpRunner {
    async fn run(&self, job: &ScpJob, ct: &CancellationToken) -> std::io::Result<ScpOutcome> {
        let argv = build_scp_argv(job);
        use tokio::io::AsyncReadExt;
        let mut child = tokio::process::Command::new("scp")
            .args(&argv)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()?;
        let mut stdout_pipe = child.stdout.take().expect("piped");
        let mut stderr_pipe = child.stderr.take().expect("piped");
        let status = tokio::select! {
            biased;
            _ = ct.cancelled() => {
                tracing::info!(pid = ?child.id(), "transfer_file.scp_diag phase=\"cancelled\": killing scp child");
                let _ = child.start_kill();
                // Reap so we don't leak a zombie in the process table.
                let _ = child.wait().await;
                return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
            }
            s = child.wait() => s?,
        };
        let mut so = Vec::new();
        let mut se = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut so).await;
        let _ = stderr_pipe.read_to_end(&mut se).await;
        Ok(ScpOutcome {
            exit_code: status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&so).into_owned(),
            stderr: String::from_utf8_lossy(&se).into_owned(),
        })
    }
}

/// Test double that records calls and returns canned outcomes.
#[cfg(test)]
pub struct MockScpRunner {
    pub outcome: ScpOutcome,
    pub calls: tokio::sync::Mutex<Vec<Vec<String>>>,
    /// When `Some`, the runner sleeps this long (cancel-aware) before
    /// returning the outcome. Used by cancellation tests to assert the
    /// SCP call observes a mid-flight cancel.
    pub delay: Option<std::time::Duration>,
}

#[cfg(test)]
impl MockScpRunner {
    pub fn ok() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            outcome: ScpOutcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
            calls: tokio::sync::Mutex::new(Vec::new()),
            delay: None,
        })
    }
    pub fn with_outcome(o: ScpOutcome) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            outcome: o,
            calls: tokio::sync::Mutex::new(Vec::new()),
            delay: None,
        })
    }
    /// Construct a mock that sleeps `d` (cancel-aware) before returning,
    /// to exercise the cancel-during-scp path in tests.
    pub fn with_delay(d: std::time::Duration) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            outcome: ScpOutcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            },
            calls: tokio::sync::Mutex::new(Vec::new()),
            delay: Some(d),
        })
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl ScpRunner for MockScpRunner {
    async fn run(&self, job: &ScpJob, ct: &CancellationToken) -> std::io::Result<ScpOutcome> {
        self.calls.lock().await.push(build_scp_argv(job));
        if let Some(d) = self.delay {
            tokio::select! {
                biased;
                _ = ct.cancelled() => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "cancelled"));
                }
                _ = tokio::time::sleep(d) => {}
            }
        }
        Ok(self.outcome.clone())
    }
}

#[cfg(test)]
mod runner_tests {
    use super::*;

    #[tokio::test]
    async fn mock_records_argv_for_assertion() {
        let runner = MockScpRunner::ok();
        let job = ScpJob {
            private_key_path: "/k".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            local_path: "/var/lib/jmcp/staging/x.tgz".into(),
            remote_dir: "/var/tmp/".into(),
            accept_new_host_keys: false,
        };
        let ct = CancellationToken::new();
        let out = runner.run(&job, &ct).await.unwrap();
        assert_eq!(out.exit_code, 0);
        let calls = runner.calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "-O");
    }

    /// T4 (issue #44 Half A): a `MockScpRunner::with_delay` runner, raced
    /// against a token that fires mid-flight, returns `io::ErrorKind::Interrupted`
    /// — the same shape the real `OpenSshScpRunner` returns when it calls
    /// `child.start_kill()` on cancel. `transfer_file::handle` then maps
    /// `Interrupted` to `JmcpError::Cancelled`.
    #[tokio::test]
    async fn mock_runner_with_delay_cancels_to_interrupted() {
        let runner = MockScpRunner::with_delay(std::time::Duration::from_secs(5));
        let job = ScpJob {
            private_key_path: "/k".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            username: "root".into(),
            host: "10.0.0.1".into(),
            port: 22,
            local_path: "/var/lib/jmcp/staging/x.tgz".into(),
            remote_dir: "/var/tmp/".into(),
            accept_new_host_keys: false,
        };
        let ct = CancellationToken::new();
        let ct2 = ct.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            ct2.cancel();
        });
        let r = tokio::time::timeout(std::time::Duration::from_millis(500), runner.run(&job, &ct))
            .await
            .expect("runner should return well within 500ms after cancel");
        let err = r.expect_err("expected Interrupted error");
        assert_eq!(err.kind(), std::io::ErrorKind::Interrupted, "got {err:?}");
    }
}

/// Parse the free-bytes column for `/var` from `show system storage no-forwarding`.
/// Junos prints rows like:
/// ```text
/// Filesystem              Size       Used      Avail  Capacity   Mounted on
/// /dev/gpt/junos          14G       8.5G       4.4G       66%   /.mount
/// /dev/gpt/varlog         3.0G      1.1G       1.7G       40%   /.mount/var/log
/// /dev/gpt/var            10G       2.1G       7.0G       23%   /.mount/var
/// ```
/// We want the `Avail` column on the row whose `Mounted on` equals `/.mount/var`
/// (or `/var` for older Junos). On vSRX 24.x and other single-mount layouts
/// where `/var` lives inside the root `/.mount` filesystem rather than being
/// its own mount, we fall back to the `/.mount` row's `Avail`. Returns bytes.
pub fn parse_storage_free_bytes(output: &str) -> Result<u64, JmcpError> {
    let mut root_mount_avail: Option<&str> = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("Filesystem") {
            continue;
        }
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        // Expect: filesystem size used avail capacity mounted_on
        if fields.len() < 6 {
            continue;
        }
        let mount = fields[fields.len() - 1];
        if mount == "/var" || mount == "/.mount/var" {
            return parse_size_with_suffix(fields[3]);
        }
        if mount == "/.mount" {
            // vSRX 24.x and similar single-mount layouts host /var inside the
            // root /.mount filesystem. Remember this row as a fallback for
            // when no dedicated /var row is found.
            root_mount_avail = Some(fields[3]);
        }
    }
    if let Some(avail) = root_mount_avail {
        return parse_size_with_suffix(avail);
    }
    Err(JmcpError::InsufficientDisk {
        free: 0,
        required: 0,
        message: "no /var, /.mount/var, or /.mount row found in storage output".into(),
    })
}

fn parse_size_with_suffix(s: &str) -> Result<u64, JmcpError> {
    let (num_part, mult): (&str, u64) = if let Some(stripped) = s.strip_suffix('G') {
        (stripped, 1024 * 1024 * 1024)
    } else if let Some(stripped) = s.strip_suffix('M') {
        (stripped, 1024 * 1024)
    } else if let Some(stripped) = s.strip_suffix('K') {
        (stripped, 1024)
    } else if let Some(stripped) = s.strip_suffix('B') {
        (stripped, 1)
    } else {
        (s, 1)
    };
    let n: f64 = num_part.parse().map_err(|_| JmcpError::InsufficientDisk {
        free: 0,
        required: 0,
        message: format!("could not parse storage size '{s}'"),
    })?;
    Ok((n * mult as f64) as u64)
}

#[cfg(test)]
mod storage_tests {
    use super::*;

    const SAMPLE: &str = "\
Filesystem              Size       Used      Avail  Capacity   Mounted on
/dev/gpt/junos          14G       8.5G       4.4G       66%   /.mount
/dev/gpt/varlog         3.0G      1.1G       1.7G       40%   /.mount/var/log
/dev/gpt/var            10G       2.1G       7.0G       23%   /.mount/var
";

    #[test]
    fn finds_var_mount_in_modern_layout() {
        let n = parse_storage_free_bytes(SAMPLE).unwrap();
        // 7.0G ≈ 7516192768
        assert!((6_900_000_000..7_600_000_000).contains(&n), "got {n}");
    }

    #[test]
    fn handles_legacy_var_mount() {
        let s = "\
Filesystem      Size   Used  Avail Capacity   Mounted on
/dev/ad0s1f     5.0G   1.0G   4.0G    20%   /var
";
        let n = parse_storage_free_bytes(s).unwrap();
        assert!((3_900_000_000..4_400_000_000).contains(&n));
    }

    #[test]
    fn errors_when_var_row_missing() {
        let s = "Filesystem  Size Used Avail Capacity Mounted on\n/dev/x 1G 0 1G 0% /\n";
        assert!(matches!(
            parse_storage_free_bytes(s),
            Err(JmcpError::InsufficientDisk { .. })
        ));
    }

    #[test]
    fn parses_megabyte_suffix() {
        let s = "\
Filesystem  Size Used Avail Capacity Mounted on
/dev/x      500M 100M 400M 20% /var
";
        let n = parse_storage_free_bytes(s).unwrap();
        assert!((400_000_000..420_000_000).contains(&n));
    }

    #[test]
    fn falls_back_to_root_mount_on_vsrx_24_layout() {
        // vSRX 24.4 reports a single root mount at /.mount with /var
        // living inside it — no dedicated /var or /.mount/var row.
        let s = "\
Filesystem              Size       Used      Avail  Capacity   Mounted on
/dev/gpt/junos           13G       940M        11G        8%  /.mount
tmpfs                   795M        24K       795M        0%  /.mount/tmp
/var/jails/rest-api      13G       940M        11G        8%  /.mount/packages/mnt/junos-runtime/web-api/var
tmpfs                   673M        1.1M      671M        0%  /.mount/mfs
";
        let n = parse_storage_free_bytes(s).unwrap();
        // 11G ≈ 11_811_160_064
        assert!((10_700_000_000..12_000_000_000).contains(&n), "got {n}");
    }

    #[test]
    fn prefers_var_mount_over_root_when_both_present() {
        // When /var/-specific and /.mount rows coexist (a hybrid that
        // could appear on some Junos variants), the dedicated /var row wins.
        let s = "\
Filesystem              Size       Used      Avail  Capacity   Mounted on
/dev/gpt/junos           14G       8.5G       4.4G       66%   /.mount
/dev/gpt/var             10G       2.1G       7.0G       23%   /.mount/var
";
        let n = parse_storage_free_bytes(s).unwrap();
        // Should match the 7.0G /.mount/var row, not the 4.4G /.mount row.
        assert!((6_900_000_000..7_600_000_000).contains(&n), "got {n}");
    }
}

/// Parse the sha256 from `file checksum sha-256 /var/tmp/foo` output. Junos prints:
/// ```text
/// SHA256 (/var/tmp/foo) = abc123...
/// ```
/// On older Junos, when the file is missing:
/// ```text
/// error: stat: /var/tmp/foo: No such file or directory
/// ```
/// On Junos 24.x, the missing-file form wraps the underlying `sha256(1)` stderr
/// into the same line that would normally hold the hash (issue #40):
/// ```text
/// sha256: (sha256: /var/tmp/foo: No such file or directory) = directory
/// ```
/// Returns `Ok(Some([u8;32]))` on hit, `Ok(None)` if absent, `Err` on parse failure.
pub fn parse_checksum_output(output: &str) -> Result<Option<[u8; 32]>, JmcpError> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Any line carrying "No such file or directory" is the missing-file
        // signal. Older Junos: prefixed with `error:`. Junos 24.x: wrapped
        // inside `sha256: (...: No such file or directory) = directory`. The
        // success format below never contains this phrase (it ends in a 64-char
        // hex digest), so we can match it anywhere on the line safely.
        if trimmed.contains("No such file or directory") {
            return Ok(None);
        }
        if let Some(eq) = trimmed.rfind('=') {
            let hex = trimmed[eq + 1..].trim();
            if hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit()) {
                let mut out = [0u8; 32];
                for (i, byte) in out.iter_mut().enumerate() {
                    let hi = u8::from_str_radix(&hex[i * 2..i * 2 + 1], 16).unwrap();
                    let lo = u8::from_str_radix(&hex[i * 2 + 1..i * 2 + 2], 16).unwrap();
                    *byte = (hi << 4) | lo;
                }
                return Ok(Some(out));
            }
        }
    }
    Err(JmcpError::Validation(format!(
        "unable to parse checksum output: {output:?}"
    )))
}

#[cfg(test)]
mod checksum_tests {
    use super::*;

    #[test]
    fn parses_present_file() {
        let s = "SHA256 (/var/tmp/foo.tgz) = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n";
        let h = parse_checksum_output(s).unwrap().unwrap();
        assert_eq!(h[0], 0xba);
        assert_eq!(h[31], 0xad);
    }

    #[test]
    fn returns_none_for_missing_file() {
        let s = "error: stat: /var/tmp/foo: No such file or directory\n";
        assert!(parse_checksum_output(s).unwrap().is_none());
    }

    /// Junos 24.x wraps the BSD `sha256(1)` stderr into the would-be hash
    /// line (issue #40). The trailing `= directory` token can't be confused
    /// with a real 64-char hex digest, but the parser still needs to
    /// recognize the `No such file or directory` phrase as the missing-file
    /// signal rather than fall through to the "unable to parse" error.
    #[test]
    fn returns_none_for_missing_file_junos_24x_format() {
        let s = "\nsha256: (sha256: /var/tmp/smoke.txt: No such file or directory) = directory\n";
        assert!(parse_checksum_output(s).unwrap().is_none());
    }

    #[test]
    fn errors_on_garbage_output() {
        let s = "fzzt fzzt nothing here\n";
        assert!(parse_checksum_output(s).is_err());
    }
}

/// Per-router serialization for transfer_file. A confused or buggy caller
/// fanning out N concurrent transfers to one device could otherwise
/// exhaust the device's `/var/tmp` headroom or its session pool. Junos
/// can't really benefit from concurrent SCP into `/var/tmp` anyway —
/// the underlying transport serializes on the device side. (issue #26, L4)
///
/// Locks are created lazily on first use per router and cached for the
/// lifetime of the process. Concurrency limit is 1 per router; other
/// router pairs proceed in parallel.
#[derive(Default)]
pub struct TransferLocks {
    map: tokio::sync::Mutex<std::collections::HashMap<String, Arc<tokio::sync::Semaphore>>>,
}

impl TransferLocks {
    /// Acquire the per-router permit. The returned guard releases the
    /// permit on drop — including when a `handle()` call hits its outer
    /// `tokio::time::timeout` or returns an error.
    pub async fn acquire(&self, router: &str) -> tokio::sync::OwnedSemaphorePermit {
        let sem = {
            let mut g = self.map.lock().await;
            g.entry(router.to_string())
                .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(1)))
                .clone()
        };
        // Semaphore is never closed (we keep the Arc alive), so the only
        // way `acquire_owned` returns Err is if we explicitly called
        // `close()`, which we never do.
        sem.acquire_owned()
            .await
            .expect("transfer_locks semaphore should never be closed")
    }
}

/// Configuration handed to `handle()`. Holds the staging-dir + known-hosts
/// paths and the (mockable) ScpRunner. Built once in `main.rs` and cloned
/// per call.
#[derive(Clone)]
pub struct TransferConfig {
    pub staging_dir: std::path::PathBuf,
    pub known_hosts_file: std::path::PathBuf,
    pub scp_runner: Arc<dyn ScpRunner>,
    /// Per-router concurrency limiter; defaults to an empty map that
    /// lazy-creates one-permit semaphores on first use. Share the same
    /// `Arc<TransferLocks>` across all transfer_file calls in the process
    /// so the limit is process-wide (not per-call). (issue #26, L4)
    pub transfer_locks: Arc<TransferLocks>,
    /// Host-key policy passed through to every `ScpJob`. When `false`
    /// (default since v0.5.2 — RJMCP-SEC-004) scp uses
    /// `StrictHostKeyChecking=yes`, refusing unknown host keys. Opt in via
    /// `--ssh-accept-new-host-keys` for first-contact TOFU in labs.
    pub accept_new_host_keys: bool,
}

pub async fn handle(
    args: TransferFileArgs,
    dm: Arc<DeviceManager>,
    cfg: TransferConfig,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, async move {
        // Issue #44 Half A: short-circuit if the request was cancelled
        // before we even entered the body (e.g. notifications/cancelled
        // arrived during dispatch).
        if ct.is_cancelled() {
            return Err(JmcpError::Cancelled);
        }
        validate_source_basename(&args.source_path)?;
        // RJMCP-SEC-004: known_hosts is mandatory unless the operator opted
        // into TOFU (`--ssh-accept-new-host-keys`). Probing here keeps the
        // failure mode loud and synchronous instead of hidden inside scp's
        // stderr after a queue + connect round-trip.
        match std::fs::metadata(&cfg.known_hosts_file) {
            Ok(m) if m.is_file() => {}
            _ if cfg.accept_new_host_keys => {
                // TOFU mode tolerates a missing known_hosts (scp will create
                // it on first contact). Still log so operators see what's
                // happening.
                tracing::info!(
                    known_hosts = %cfg.known_hosts_file.display(),
                    "transfer_file: known_hosts missing; running in accept-new (TOFU) mode"
                );
            }
            _ => {
                return Err(JmcpError::KnownHostsMissing(cfg.known_hosts_file.clone()));
            }
        }
        tracing::info!(
            router = %args.router_name,
            host_key_policy = if cfg.accept_new_host_keys { "accept-new" } else { "strict" },
            "transfer_file: host-key policy"
        );
        // Per-router serialization (issue #26, L4). Acquired AFTER basename
        // validation so an obviously-bogus source_path never queues behind
        // a live transfer. Permit is dropped at end-of-block (success or
        // error) when `_permit` falls out of scope.
        tracing::info!(
            router = %args.router_name,
            step = "lock_acquire_pre",
            "transfer_file.step_diag"
        );
        let _permit = select_cancel_raw(&ct, cfg.transfer_locks.acquire(&args.router_name)).await?;
        tracing::info!(
            router = %args.router_name,
            step = "lock_acquire_post",
            "transfer_file.step_diag"
        );
        let local_path = cfg.staging_dir.join(&args.source_path);
        // symlink_metadata() does NOT follow symlinks — combined with the
        // explicit is_symlink() reject below, this guarantees we never read or
        // hash a file outside the staging dir via a symlink in the staging dir.
        let meta = std::fs::symlink_metadata(&local_path).map_err(|_| {
            JmcpError::BadSourcePath(format!(
                "staged file not found or unreadable: {}",
                local_path.display()
            ))
        })?;
        if meta.file_type().is_symlink() {
            return Err(JmcpError::BadSourcePath(format!(
                "staged path is a symlink, refusing to follow: {}",
                local_path.display()
            )));
        }
        if !meta.is_file() {
            return Err(JmcpError::BadSourcePath(format!(
                "staged path is not a regular file: {}",
                local_path.display()
            )));
        }
        // Compute local sha256 + size (streamed).
        tracing::info!(
            router = %args.router_name,
            step = "sha256_pre",
            local_path = %local_path.display(),
            "transfer_file.step_diag"
        );
        let (local_sha, local_size) = sha256_file_cancellable(&local_path, &ct).await?;
        tracing::info!(
            router = %args.router_name,
            step = "sha256_post",
            local_size,
            "transfer_file.step_diag"
        );

        // NOTE: The order is intentional — local sha256 is computed BEFORE the
        // auth check. The `rejects_password_auth_with_unsupported_auth` test
        // assumes UnsupportedAuth fires after a successful sha256, so do not
        // reorder these without updating that test.

        // Resolve device + check auth type. Snapshot the fields we need before
        // dropping the borrow so we can hand `dm` to `dm.open(...)` below.
        let inv = dm.inventory();
        let entry = inv.get(&args.router_name)?;
        let private_key_path = match &entry.auth {
            AuthConfig::Password { .. } => {
                return Err(JmcpError::UnsupportedAuth(args.router_name.clone()));
            }
            AuthConfig::SshKey { private_key_path } => private_key_path.clone(),
        };
        let host = entry.ip.clone();
        let port = entry.port;
        let username = entry.username.clone();
        drop(inv);

        let basename = args.source_path.clone();
        let remote_path = format!("/var/tmp/{}", basename);

        // Open pooled NETCONF session for the pre-flight + post-verify CLI calls.
        tracing::info!(
            router = %args.router_name,
            step = "dm_open_pre",
            "transfer_file.step_diag"
        );
        let mut dev = select_cancel(&ct, dm.open(&args.router_name)).await?;
        tracing::info!(
            router = %args.router_name,
            step = "dm_open_post",
            "transfer_file.step_diag"
        );

        // 1. Free-disk pre-flight.
        let storage_out = select_cancel_raw(&ct, dev.cli("show system storage no-forwarding"))
            .await?
            .map_err(|e| JmcpError::DeviceProbeFailed {
                phase: "storage_probe".into(),
                message: e.to_string(),
            })?;
        let free_bytes = parse_storage_free_bytes(&storage_out)?;
        let required = local_size.saturating_add(MIN_FREE_HEADROOM_BYTES);
        if free_bytes < required {
            return Err(JmcpError::InsufficientDisk {
                free: free_bytes,
                required,
                message: format!("device '{}' /var/tmp", args.router_name),
            });
        }

        // 2. Probe remote checksum to support idempotent skip.
        let probe_cmd = format!("file checksum sha-256 {}", remote_path);
        let probe_out = select_cancel_raw(&ct, dev.cli(&probe_cmd))
            .await?
            .map_err(|e| JmcpError::DeviceProbeFailed {
                phase: "remote_checksum".into(),
                message: e.to_string(),
            })?;
        let remote_sha_pre = parse_checksum_output(&probe_out)?;
        tracing::info!(
            router = %args.router_name,
            step = "remote_checksum_done",
            remote_sha_some = remote_sha_pre.is_some(),
            "transfer_file.step_diag"
        );
        if let Some(remote) = remote_sha_pre {
            if remote == local_sha {
                return Ok(skipped_response(&basename, &local_sha, local_size));
            }
            if !args.force {
                return Err(JmcpError::DestExistsDiffers {
                    dest: remote_path.clone(),
                    local_sha: hex32(&local_sha),
                    remote_sha: hex32(&remote),
                });
            }
            // force=true: fall through to scp (overwrite).
        }

        // 3. SCP the file.
        let job = ScpJob {
            private_key_path,
            known_hosts_file: cfg.known_hosts_file.clone(),
            username,
            host,
            port,
            local_path: local_path.clone(),
            remote_dir: "/var/tmp/".into(),
            accept_new_host_keys: cfg.accept_new_host_keys,
        };
        tracing::info!(
            router = %args.router_name,
            phase = "scp_start",
            "transfer_file.scp_diag"
        );
        let outcome = cfg
            .scp_runner
            .run(&job, &ct)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::Interrupted => JmcpError::Cancelled,
                _ => JmcpError::Io(e),
            })?;
        tracing::info!(
            router = %args.router_name,
            phase = "scp_done",
            exit_code = outcome.exit_code,
            "transfer_file.scp_diag"
        );
        if outcome.exit_code != 0 {
            // OpenSSH scp returns exit 255 on transport failures; pull out the
            // common "connection timed out" / "no route to host" cases so callers
            // get the documented [code=connect_timeout] tag instead of a generic
            // [code=scp_failed] with raw stderr.
            if outcome.exit_code == 255
                && (outcome.stderr.contains("Connection timed out")
                    || outcome.stderr.contains("No route to host"))
            {
                return Err(JmcpError::ConnectTimeout(args.router_name.clone()));
            }
            // Scrub paths/hostnames before surfacing to the MCP caller
            // (issue #26, L1). The connect-timeout heuristic above runs on
            // the unscrubbed stderr so its substring matches are unaffected.
            return Err(JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: scrub_scp_stderr(&outcome.stderr),
            });
        }

        // 4. Post-transfer verify (re-run remote checksum).
        let verify_out = select_cancel_raw(&ct, dev.cli(&probe_cmd))
            .await?
            .map_err(|e| JmcpError::DeviceProbeFailed {
                phase: "verify_checksum".into(),
                message: e.to_string(),
            })?;
        let remote_sha_post = parse_checksum_output(&verify_out)?;
        let (post, verified) = match remote_sha_post {
            Some(s) => {
                let matches = s == local_sha;
                (s, matches)
            }
            None => {
                // Remote file vanished after a successful scp — treat as
                // verify mismatch with a sentinel placeholder so the caller
                // still sees the canonical error.
                if args.verify {
                    return Err(JmcpError::VerifyMismatch {
                        dest: remote_path.clone(),
                        local_sha: hex32(&local_sha),
                        remote_sha: "<missing>".into(),
                    });
                }
                (local_sha, false)
            }
        };
        if args.verify && !verified {
            // Best-effort cleanup: ignore the result, the canonical error wins.
            let _ = dev.cli(&format!("file delete {}", remote_path)).await;
            return Err(JmcpError::VerifyMismatch {
                dest: remote_path.clone(),
                local_sha: hex32(&local_sha),
                remote_sha: hex32(&post),
            });
        }

        Ok(json!({
            "status": "transferred",
            "remote_path": remote_path,
            "size_bytes": local_size,
            "sha256": hex32(&local_sha),
            "verified": verified,
        }))
    })
    .await
    .map_err(|_| JmcpError::TransferOuterTimeout(timeout))?
}

#[cfg(test)]
mod transfer_locks_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Two concurrent acquires on the same router must serialize: the
    /// second can only complete after the first guard is dropped.
    #[tokio::test]
    async fn same_router_serializes() {
        let locks = Arc::new(TransferLocks::default());
        let counter = Arc::new(AtomicUsize::new(0));
        let max_inflight = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let locks = locks.clone();
            let counter = counter.clone();
            let max_inflight = max_inflight.clone();
            handles.push(tokio::spawn(async move {
                let _permit = locks.acquire("r1").await;
                let now = counter.fetch_add(1, Ordering::SeqCst) + 1;
                max_inflight.fetch_max(now, Ordering::SeqCst);
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                counter.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            max_inflight.load(Ordering::SeqCst),
            1,
            "expected serialization to limit inflight to 1, got {}",
            max_inflight.load(Ordering::SeqCst)
        );
    }

    /// Issue #51 regression: holding a permit for a router and then
    /// awaiting `acquire` for the SAME router on the SAME task is a
    /// self-deadlock — the inner future can never make progress because
    /// the outer scope holds the only permit. This test documents that
    /// invariant so the upgrade_junos path (which used to acquire the
    /// permit in `run()` and then call `transfer_file::handle()` which
    /// re-acquires it) cannot regress.
    #[tokio::test]
    async fn same_task_reacquire_deadlocks() {
        let locks = Arc::new(TransferLocks::default());
        let outer = locks.acquire("r1").await;
        let inner =
            tokio::time::timeout(std::time::Duration::from_millis(100), locks.acquire("r1")).await;
        assert!(
            inner.is_err(),
            "re-acquiring the same-router permit on the same task should deadlock; \
             if this test passes, the locking primitive changed and #51's fix may \
             no longer be load-bearing"
        );
        drop(outer);
    }

    /// Different routers must NOT block each other. Two acquires on
    /// distinct routers should be able to run concurrently.
    #[tokio::test]
    async fn different_routers_proceed_in_parallel() {
        let locks = Arc::new(TransferLocks::default());
        let permit1 = locks.acquire("r1").await;
        // If `r2` were blocked by `r1`'s permit, this would hang past the
        // timeout. A short 200ms upper bound is more than enough since
        // there's no contention.
        let acquired =
            tokio::time::timeout(std::time::Duration::from_millis(200), locks.acquire("r2")).await;
        assert!(
            acquired.is_ok(),
            "different routers should not block each other"
        );
        drop(permit1);
    }

    /// Permits are released on Drop — a successful release lets the next
    /// waiter proceed immediately.
    #[tokio::test]
    async fn permit_release_on_drop() {
        let locks = Arc::new(TransferLocks::default());
        {
            let _p = locks.acquire("r1").await;
        } // permit dropped here
        let p2 = tokio::time::timeout(std::time::Duration::from_millis(100), locks.acquire("r1"))
            .await
            .expect("permit should be available after drop");
        drop(p2);
    }
}

#[cfg(test)]
mod handle_validation_tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn cfg(dir: &std::path::Path) -> TransferConfig {
        TransferConfig {
            staging_dir: dir.to_path_buf(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            scp_runner: MockScpRunner::ok(),
            transfer_locks: Arc::new(TransferLocks::default()),
            // Tests don't provide a real known_hosts file; opt into TOFU
            // so the v0.5.2 pre-check (`KnownHostsMissing`) doesn't short-
            // circuit them. A dedicated test below asserts that strict-mode
            // + missing known_hosts fails closed.
            accept_new_host_keys: true,
        }
    }

    fn build_inv(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn rejects_bad_basename() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "../etc/passwd".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
    }

    /// RJMCP-SEC-004: strict-mode (`accept_new_host_keys=false`) must fail
    /// closed when the configured `known_hosts_file` is missing or not a
    /// regular file. This fires before the staged-file check, so even a
    /// missing source surfaces `KnownHostsMissing` first.
    #[tokio::test]
    async fn strict_mode_rejects_missing_known_hosts() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let mut c = cfg(dir.path());
        c.accept_new_host_keys = false;
        c.known_hosts_file = dir.path().join("no-such-known_hosts");
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "foo.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            c,
            CancellationToken::new(),
        )
        .await;
        assert!(
            matches!(r, Err(JmcpError::KnownHostsMissing(_))),
            "expected KnownHostsMissing in strict mode, got {r:?}"
        );
    }

    #[tokio::test]
    async fn rejects_missing_staged_file() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "missing.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn rejects_password_auth_with_unsupported_auth() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"abc").unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "foo.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnsupportedAuth(ref s)) if s == "r1"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_as_source() {
        // Plant a symlink in the staging dir pointing outside it. handle()
        // must reject it as BadSourcePath BEFORE hashing or auth, so we
        // never read or expose the link target.
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(outside.path(), b"secret").unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("link.tgz")).unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "link.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        match r {
            Err(JmcpError::BadSourcePath(msg)) => {
                assert!(
                    msg.contains("symlink"),
                    "expected symlink reject message, got: {msg}"
                );
            }
            other => panic!("expected BadSourcePath(symlink…), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_directory_as_source() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "r1".into(),
                source_path: "subdir".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
    }

    #[tokio::test]
    async fn skip_message_shape_helper_returns_expected_keys() {
        let v = super::skipped_response("foo.tgz", &[0u8; 32], 1234);
        assert_eq!(v["status"], "skipped");
        assert_eq!(v["remote_path"], "/var/tmp/foo.tgz");
        assert_eq!(v["size_bytes"], 1234);
        assert_eq!(v["sha256"], "0".repeat(64));
        assert_eq!(v["verified"], true);
        assert!(v["message"].as_str().unwrap().contains("already present"));
    }

    #[tokio::test]
    async fn unknown_router_propagates_unknown_router_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.tgz"), b"abc").unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            TransferFileArgs {
                router_name: "nope".into(),
                source_path: "foo.tgz".into(),
                force: false,
                verify: true,
                timeout: 5,
            },
            dm,
            cfg(dir.path()),
            CancellationToken::new(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    /// T1 (issue #44 Half A): a token cancelled before `handle` is invoked
    /// must cause `handle` to return `JmcpError::Cancelled` immediately,
    /// before any validation, lock acquisition, or device I/O. The body's
    /// first statement is `if ct.is_cancelled() { return Cancelled }` — this
    /// test pins that fast-path so a future refactor cannot accidentally
    /// move the check.
    #[tokio::test]
    async fn pre_cancelled_token_returns_cancelled_immediately() {
        let dir = tempfile::tempdir().unwrap();
        let inv = build_inv(
            r#"{"r1":{"ip":"127.0.0.1","username":"u",
                     "auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let ct = CancellationToken::new();
        ct.cancel();
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            handle(
                TransferFileArgs {
                    router_name: "r1".into(),
                    // Deliberately invalid basename: if the cancel pre-check
                    // were skipped we would observe `BadSourcePath` instead.
                    source_path: "../etc/passwd".into(),
                    force: false,
                    verify: true,
                    timeout: 5,
                },
                dm,
                cfg(dir.path()),
                ct,
            ),
        )
        .await
        .expect("handle should return well within 200ms when pre-cancelled");
        assert!(
            matches!(r, Err(JmcpError::Cancelled)),
            "expected Cancelled, got {r:?}"
        );
    }
}

#[cfg(test)]
mod scp_unit_tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn mock_runner_records_argv_and_reports_success() {
        let mock = MockScpRunner::with_outcome(ScpOutcome {
            exit_code: 0,
            stdout: String::new(),
            stderr: String::new(),
        });
        let job = ScpJob {
            host: "192.0.2.4".into(),
            port: 22,
            username: "admin".into(),
            private_key_path: "/etc/jmcp/ssh/id_ed25519".into(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            local_path: "/var/lib/jmcp/staging/abc/junos.tgz".into(),
            remote_dir: "/var/tmp/".into(),
            accept_new_host_keys: false,
        };
        let ct = CancellationToken::new();
        let outcome = (mock.clone() as Arc<dyn ScpRunner>)
            .run(&job, &ct)
            .await
            .unwrap();
        assert_eq!(outcome.exit_code, 0);
        let calls = mock.calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert!(calls[0].iter().any(|s| s == "-O"), "argv missing -O");
        assert!(
            calls[0].iter().any(|s| s == "admin@192.0.2.4:/var/tmp/"),
            "argv missing dest"
        );
    }

    /// Exercise the exit-255 + "Connection timed out" remap in isolation, without
    /// standing up the full handle() harness (which requires a staging dir, device
    /// manager, NETCONF session, etc.).  We test the remap logic directly by
    /// constructing the ScpOutcome values that would trigger each branch.
    #[test]
    fn scp_exit_255_connect_timeout_stderr_remaps_to_connect_timeout() {
        // Simulate the remap decision: exit_code == 255 && stderr contains
        // "Connection timed out" → ConnectTimeout; not ScpFailed.
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "ssh: connect to host 192.0.2.1 port 22: Connection timed out".into(),
        };
        let router = "vsrx-test10".to_string();
        let err = if outcome.exit_code == 255
            && (outcome.stderr.contains("Connection timed out")
                || outcome.stderr.contains("No route to host"))
        {
            JmcpError::ConnectTimeout(router.clone())
        } else {
            JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: outcome.stderr.clone(),
            }
        };
        assert!(
            matches!(err, JmcpError::ConnectTimeout(ref r) if r == "vsrx-test10"),
            "expected ConnectTimeout, got: {}",
            err
        );
        let s = err.to_string();
        assert!(s.contains("[code=connect_timeout]"), "got {}", s);
        assert!(s.contains("vsrx-test10"), "got {}", s);
    }

    #[test]
    fn scp_exit_255_no_route_stderr_remaps_to_connect_timeout() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "ssh: connect to host 192.0.2.1 port 22: No route to host".into(),
        };
        let router = "vsrx-test11".to_string();
        let err = if outcome.exit_code == 255
            && (outcome.stderr.contains("Connection timed out")
                || outcome.stderr.contains("No route to host"))
        {
            JmcpError::ConnectTimeout(router.clone())
        } else {
            JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: outcome.stderr.clone(),
            }
        };
        assert!(
            matches!(err, JmcpError::ConnectTimeout(ref r) if r == "vsrx-test11"),
            "expected ConnectTimeout, got: {}",
            err
        );
    }

    #[test]
    fn scp_exit_255_other_stderr_stays_as_scp_failed() {
        let outcome = ScpOutcome {
            exit_code: 255,
            stdout: String::new(),
            stderr: "Permission denied (publickey).".into(),
        };
        let router = "vsrx-test10".to_string();
        let err = if outcome.exit_code == 255
            && (outcome.stderr.contains("Connection timed out")
                || outcome.stderr.contains("No route to host"))
        {
            JmcpError::ConnectTimeout(router)
        } else {
            JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: outcome.stderr.clone(),
            }
        };
        assert!(
            matches!(err, JmcpError::ScpFailed { exit_code: 255, .. }),
            "expected ScpFailed, got: {}",
            err
        );
    }

    #[test]
    fn scp_failed_display_includes_code() {
        let e = JmcpError::ScpFailed {
            exit_code: 1,
            stderr: "permission denied".into(),
        };
        let s = e.to_string();
        assert!(s.contains("[code=scp_failed]"), "got {}", s);
        assert!(s.contains("permission denied"), "got {}", s);
    }

    #[test]
    fn verify_mismatch_display_includes_code() {
        let e = JmcpError::VerifyMismatch {
            dest: "/var/tmp/foo.tgz".into(),
            local_sha: "aa".repeat(32),
            remote_sha: "bb".repeat(32),
        };
        let s = e.to_string();
        assert!(s.contains("[code=verify_mismatch]"), "got {}", s);
        assert!(s.contains("/var/tmp/foo.tgz"), "got {}", s);
    }

    #[test]
    fn transfer_outer_timeout_display_includes_code() {
        let e = JmcpError::TransferOuterTimeout(std::time::Duration::from_secs(600));
        let s = e.to_string();
        // actual Display tag is `[code=outer_timeout]` (error.rs line 76)
        assert!(s.contains("[code=outer_timeout]"), "got {}", s);
        assert!(s.contains("600s"), "got {}", s);
    }
}
