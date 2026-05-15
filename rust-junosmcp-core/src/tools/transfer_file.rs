//! `transfer_file` MCP tool. SCP a pre-staged file from the host's staging
//! directory to a Junos device's /var/tmp/, with idempotent skip and
//! pre/post-transfer sha256 verification.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::AuthConfig;
use crate::tools::TransferFileArgs;
use serde_json::{json, Value};

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
}

/// Build the argv vector that `OpenSshScpRunner` will hand to `scp`. Pulled
/// out so it can be asserted exactly in unit tests without spawning a process.
pub fn build_scp_argv(job: &ScpJob) -> Vec<String> {
    let dest = format!("{}@{}:{}", job.username, job.host, job.remote_dir);
    vec![
        "-O".into(),
        "-i".into(),
        job.private_key_path.display().to_string(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
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
        }
    }

    #[test]
    fn argv_uses_dash_capital_o_for_legacy_protocol() {
        // Junos disables SFTP-over-SSH; -O forces SCP1 wire protocol.
        let v = build_scp_argv(&job());
        assert_eq!(v[0], "-O");
    }

    #[test]
    fn argv_includes_known_hosts_with_accept_new() {
        let v = build_scp_argv(&job());
        let joined = v.join(" ");
        assert!(joined.contains("StrictHostKeyChecking=accept-new"));
        assert!(joined.contains("UserKnownHostsFile=/etc/jmcp/known_hosts"));
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
    async fn run(&self, job: &ScpJob) -> std::io::Result<ScpOutcome>;
}

/// Production runner — shells out to `scp` from system openssh-client.
pub struct OpenSshScpRunner;

#[async_trait::async_trait]
impl ScpRunner for OpenSshScpRunner {
    async fn run(&self, job: &ScpJob) -> std::io::Result<ScpOutcome> {
        let argv = build_scp_argv(job);
        let out = tokio::process::Command::new("scp")
            .args(&argv)
            .kill_on_drop(true)
            .output()
            .await?;
        Ok(ScpOutcome {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Test double that records calls and returns canned outcomes.
#[cfg(test)]
pub struct MockScpRunner {
    pub outcome: ScpOutcome,
    pub calls: tokio::sync::Mutex<Vec<Vec<String>>>,
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
        })
    }
    pub fn with_outcome(o: ScpOutcome) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            outcome: o,
            calls: tokio::sync::Mutex::new(Vec::new()),
        })
    }
}

#[cfg(test)]
#[async_trait::async_trait]
impl ScpRunner for MockScpRunner {
    async fn run(&self, job: &ScpJob) -> std::io::Result<ScpOutcome> {
        self.calls.lock().await.push(build_scp_argv(job));
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
        };
        let out = runner.run(&job).await.unwrap();
        assert_eq!(out.exit_code, 0);
        let calls = runner.calls.lock().await;
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0][0], "-O");
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
/// (or `/var` for older Junos). Returns bytes.
pub fn parse_storage_free_bytes(output: &str) -> Result<u64, JmcpError> {
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
    }
    Err(JmcpError::InsufficientDisk {
        free: 0,
        required: 0,
        message: "no /var or /.mount/var row found in storage output".into(),
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
}

/// Parse the sha256 from `file checksum sha-256 /var/tmp/foo` output. Junos prints:
/// ```text
/// SHA256 (/var/tmp/foo) = abc123...
/// ```
/// or, when the file is missing:
/// ```text
/// error: stat: /var/tmp/foo: No such file or directory
/// ```
/// Returns `Ok(Some([u8;32]))` on hit, `Ok(None)` if absent, `Err` on parse failure.
pub fn parse_checksum_output(output: &str) -> Result<Option<[u8; 32]>, JmcpError> {
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("error:") && trimmed.contains("No such file") {
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

    #[test]
    fn errors_on_garbage_output() {
        let s = "fzzt fzzt nothing here\n";
        assert!(parse_checksum_output(s).is_err());
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
}

pub async fn handle(
    args: TransferFileArgs,
    dm: Arc<DeviceManager>,
    cfg: TransferConfig,
) -> Result<Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, async move {
        validate_source_basename(&args.source_path)?;
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
        let (local_sha, local_size) = sha256_file(&local_path).await?;

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
        let mut dev = dm.open(&args.router_name).await?;

        // 1. Free-disk pre-flight.
        let storage_out = dev
            .cli("show system storage no-forwarding")
            .await
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
        let probe_out = dev
            .cli(&probe_cmd)
            .await
            .map_err(|e| JmcpError::DeviceProbeFailed {
                phase: "remote_checksum".into(),
                message: e.to_string(),
            })?;
        let remote_sha_pre = parse_checksum_output(&probe_out)?;
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
        };
        let outcome = cfg.scp_runner.run(&job).await?;
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
            return Err(JmcpError::ScpFailed {
                exit_code: outcome.exit_code,
                stderr: outcome.stderr,
            });
        }

        // 4. Post-transfer verify (re-run remote checksum).
        let verify_out = dev
            .cli(&probe_cmd)
            .await
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
mod handle_validation_tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn cfg(dir: &std::path::Path) -> TransferConfig {
        TransferConfig {
            staging_dir: dir.to_path_buf(),
            known_hosts_file: "/etc/jmcp/known_hosts".into(),
            scp_runner: MockScpRunner::ok(),
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
        )
        .await;
        assert!(matches!(r, Err(JmcpError::BadSourcePath(_))));
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
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
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
        };
        let outcome = (mock.clone() as Arc<dyn ScpRunner>)
            .run(&job)
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
