//! `transfer_file` MCP tool. SCP a pre-staged file from the host's staging
//! directory to a Junos device's /var/tmp/, with idempotent skip and
//! pre/post-transfer sha256 verification.

use std::path::{Path, PathBuf};

use crate::error::JmcpError;

/// Validate that `source_path` is a safe basename. Rejects:
/// - empty
/// - longer than 255 bytes
/// - leading '.' (dotfiles)
/// - ".." anywhere (whole name or embedded, e.g. "a..b")
/// - any '/', '\\', or "..".
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
