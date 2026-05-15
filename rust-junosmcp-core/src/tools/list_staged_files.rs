//! `list_staged_files` MCP tool. Discovery of host-staged files and (optionally)
//! the device's /var/tmp/.

use crate::error::JmcpError;
use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct DeviceFileEntry {
    pub path: String,
    pub size_bytes: u64,
    pub mtime_iso: String,
}

/// Parse `file list /var/tmp/ detail` output. Junos prints lines like:
/// ```text
/// /var/tmp/:
/// total 1234
/// -rw-r--r--   1 root  wheel  1395212800 May 14 18:01 junos-install-vsrx3.tgz
/// -rw-r--r--   1 root  wheel        4321 May 14  2025 core.thingd.12345.gz
/// ```
/// (For files older than ~6 months Junos shows the year instead of HH:MM.)
/// Skips directories and `.`/`..` entries.
pub fn parse_var_tmp_listing(output: &str, current_year: i32) -> Vec<DeviceFileEntry> {
    let mut out = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() || trimmed.starts_with("total ") || trimmed.ends_with(":") {
            continue;
        }
        // Expect: perms links owner group size MMM DD (HH:MM|YYYY) name
        let fields: Vec<&str> = trimmed.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        if fields[0].starts_with('d') {
            continue; // directory
        }
        let size: u64 = match fields[4].parse() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let month = fields[5];
        let day = fields[6];
        let last = fields[7];
        if month_to_num(month) == 0 {
            continue; // unknown month abbrev — likely garbled output, skip silently
        }
        let name = fields[8..].join(" ");
        if name == "." || name == ".." {
            continue;
        }
        let (date_str, time_str) = if last.contains(':') {
            (
                format!("{}-{}-{:0>2}", current_year, month, day),
                last.to_string(),
            )
        } else {
            (
                format!("{}-{}-{:0>2}", last, month, day),
                "00:00".to_string(),
            )
        };
        let mtime_iso = junos_date_to_iso(&date_str, &time_str);
        out.push(DeviceFileEntry {
            path: format!("/var/tmp/{name}"),
            size_bytes: size,
            mtime_iso,
        });
    }
    out
}

/// Best-effort conversion. Returns "{year}-{mm:02}-{dd:02}T{hh:mm}:00" (no
/// timezone suffix — Junos `file list` reports device-local time, so emitting
/// `Z` would falsely claim UTC).
fn junos_date_to_iso(date: &str, time: &str) -> String {
    // date format: "YYYY-Mon-DD"
    let parts: Vec<&str> = date.split('-').collect();
    if parts.len() != 3 {
        return format!("{date}T{time}");
    }
    let year = parts[0];
    let month = month_to_num(parts[1]);
    let day = parts[2];
    let t = if time.contains(':') {
        format!("{time}:00")
    } else {
        "00:00:00".to_string()
    };
    format!("{year}-{month:02}-{day:0>2}T{t}")
}

fn month_to_num(m: &str) -> u32 {
    match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => 0,
    }
}

use crate::device_manager::DeviceManager;
use crate::tools::ListStagedFilesArgs;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Debug, Serialize)]
pub struct StagedFileEntry {
    pub name: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub mtime_iso: String,
}

/// Maximum number of regular files reported by `read_staging_dir`. An
/// operator who dumps thousands of files into the staging dir would
/// otherwise produce a slow (sha256 is ~3 s/GB) and large MCP response.
/// When the on-disk count exceeds this, the call returns the first N
/// entries by name and sets `truncated = true` so the caller can detect
/// the clamp. (issue #26, L5)
pub const STAGING_DIR_MAX_ENTRIES: usize = 256;

/// Outcome of reading the staging dir: the (possibly truncated) entries
/// plus a flag indicating whether the on-disk count exceeded
/// `STAGING_DIR_MAX_ENTRIES`. The `total_found` field is informational so
/// the caller can show "showing 256 of 1340" in a UI.
#[derive(Debug)]
pub struct StagingDirResult {
    pub entries: Vec<StagedFileEntry>,
    pub truncated: bool,
    pub total_found: usize,
}

/// Read the staging directory and return one entry per regular file. Computes
/// sha256 of every kept file (cost ~3 s/GB on the LXC). Skips directories,
/// symlinks, and dotfiles. Caps at `STAGING_DIR_MAX_ENTRIES`; excess entries
/// are dropped after a name-sort so truncation is deterministic and the
/// sha256 cost is bounded.
pub async fn read_staging_dir(staging_dir: &Path) -> Result<StagingDirResult, JmcpError> {
    if !staging_dir.exists() {
        return Ok(StagingDirResult {
            entries: Vec::new(),
            truncated: false,
            total_found: 0,
        });
    }
    // First pass: gather (name, path, size, mtime) cheaply. No sha256 yet.
    let mut prelim: Vec<(String, PathBuf, u64, Option<std::time::SystemTime>)> = Vec::new();
    let mut rd = tokio::fs::read_dir(staging_dir).await?;
    while let Some(entry) = rd.next_entry().await? {
        // DirEntry::metadata() does not follow symlinks (uses fstatat with
        // AT_SYMLINK_NOFOLLOW on Unix), so we get the metadata of the link
        // itself. Reject symlinks explicitly as defense-in-depth so we never
        // hash or expose the target of a link planted in the staging dir.
        let meta = entry.metadata().await?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        prelim.push((name, entry.path(), meta.len(), meta.modified().ok()));
    }
    prelim.sort_by(|a, b| a.0.cmp(&b.0));
    let total_found = prelim.len();
    let truncated = total_found > STAGING_DIR_MAX_ENTRIES;
    if truncated {
        prelim.truncate(STAGING_DIR_MAX_ENTRIES);
    }

    // Second pass: hash only the kept entries.
    let mut out = Vec::with_capacity(prelim.len());
    for (name, path, _size_from_meta, mtime) in prelim {
        let (sha, size) = crate::tools::transfer_file::sha256_file(&path).await?;
        let mtime_iso = systemtime_to_iso(mtime);
        let mut hex = String::with_capacity(64);
        for b in sha {
            use std::fmt::Write as _;
            let _ = write!(&mut hex, "{:02x}", b);
        }
        out.push(StagedFileEntry {
            name,
            size_bytes: size,
            sha256: hex,
            mtime_iso,
        });
    }
    Ok(StagingDirResult {
        entries: out,
        truncated,
        total_found,
    })
}

fn systemtime_to_iso(t: Option<std::time::SystemTime>) -> String {
    let Some(t) = t else {
        return String::from("unknown");
    };
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dt =
        chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).unwrap_or_else(chrono::Utc::now);
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

pub async fn handle(
    args: ListStagedFilesArgs,
    dm: Arc<DeviceManager>,
    staging_dir: PathBuf,
) -> Result<Value, JmcpError> {
    let timeout = std::time::Duration::from_secs(args.timeout);
    tokio::time::timeout(timeout, async move {
        let staged = read_staging_dir(&staging_dir).await?;
        let mut payload = json!({
            "staging_dir": staging_dir.display().to_string(),
            "staged_files": staged.entries,
            "staged_files_truncated": staged.truncated,
            "staged_files_total_found": staged.total_found,
            "device": Value::Null,
            "device_files": Value::Null,
        });
        if let Some(router) = args.router_name {
            let _ = dm.inventory().get(&router)?;
            let mut dev = dm.open(&router).await?;
            let raw = dev.cli("file list /var/tmp/ detail").await.map_err(|e| {
                JmcpError::DeviceProbeFailed {
                    phase: "list_var_tmp".into(),
                    message: e.to_string(),
                }
            })?;
            let now = chrono::Utc::now();
            let year = now.format("%Y").to_string().parse::<i32>().unwrap_or(2026);
            let entries = parse_var_tmp_listing(&raw, year);
            payload["device"] = json!(router);
            payload["device_files"] = serde_json::to_value(&entries)?;
        }
        Ok::<_, JmcpError>(payload)
    })
    .await
    .map_err(|_| JmcpError::Timeout(timeout))?
}

#[cfg(test)]
mod parse_tests {
    use super::*;

    const SAMPLE: &str = "\
/var/tmp/:
total 1234
-rw-r--r--   1 root  wheel  1395212800 May 14 18:01 junos-install-vsrx3.tgz
-rw-r--r--   1 root  wheel        4321 May 14  2025 core.thingd.12345.gz
drwxr-xr-x   2 root  wheel         512 May 14 18:01 some_dir
-rw-r--r--   1 root  wheel         100 May 14 18:01 .
";

    #[test]
    fn parses_two_files_and_skips_dir_and_dot() {
        let v = parse_var_tmp_listing(SAMPLE, 2026);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].path, "/var/tmp/junos-install-vsrx3.tgz");
        assert_eq!(v[0].size_bytes, 1_395_212_800);
        assert!(v[0].mtime_iso.starts_with("2026-05-14T18:01"));
    }

    #[test]
    fn older_file_with_year_column_uses_year() {
        let v = parse_var_tmp_listing(SAMPLE, 2026);
        let core = v
            .iter()
            .find(|e| e.path.ends_with("core.thingd.12345.gz"))
            .unwrap();
        assert!(core.mtime_iso.starts_with("2025-05-14"));
    }

    #[test]
    fn skips_total_line_and_header() {
        let v = parse_var_tmp_listing(SAMPLE, 2026);
        assert!(v.iter().all(|e| !e.path.contains("total")));
    }

    #[test]
    fn single_digit_day_is_zero_padded() {
        let s = "\
/var/tmp/:
total 100
-rw-r--r--   1 root  wheel  100 Jan 5 12:00 small.txt
";
        let v = parse_var_tmp_listing(s, 2026);
        assert_eq!(v.len(), 1);
        assert!(
            v[0].mtime_iso.starts_with("2026-01-05T12:00"),
            "expected zero-padded day, got: {}",
            v[0].mtime_iso
        );
    }
}

#[cfg(test)]
mod handle_tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[tokio::test]
    async fn reads_empty_staging_dir() {
        let dir = tempfile::tempdir().unwrap();
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs {
                router_name: None,
                timeout: 5,
            },
            dm,
            dir.path().to_path_buf(),
        )
        .await
        .unwrap();
        assert_eq!(r["staged_files"].as_array().unwrap().len(), 0);
        assert_eq!(r["device"], Value::Null);
    }

    #[tokio::test]
    async fn reads_two_files_with_sha256() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.tgz"), b"abc").unwrap();
        std::fs::write(dir.path().join("b.tgz"), b"defg").unwrap();
        std::fs::write(dir.path().join(".hidden"), b"hi").unwrap();
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs {
                router_name: None,
                timeout: 5,
            },
            dm,
            dir.path().to_path_buf(),
        )
        .await
        .unwrap();
        let arr = r["staged_files"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "dotfile should be skipped");
        assert_eq!(arr[0]["name"], "a.tgz");
        assert_eq!(arr[0]["size_bytes"], 3);
        assert_eq!(
            arr[0]["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn cap_at_max_entries_sets_truncated() {
        // Write STAGING_DIR_MAX_ENTRIES + 5 small files; expect the response
        // to clamp to STAGING_DIR_MAX_ENTRIES with truncated=true and the
        // original total surfaced as staged_files_total_found. (#26 L5)
        let dir = tempfile::tempdir().unwrap();
        let n = STAGING_DIR_MAX_ENTRIES + 5;
        for i in 0..n {
            std::fs::write(dir.path().join(format!("f-{i:04}.bin")), b"x").unwrap();
        }
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs {
                router_name: None,
                timeout: 30,
            },
            dm,
            dir.path().to_path_buf(),
        )
        .await
        .unwrap();
        let arr = r["staged_files"].as_array().unwrap();
        assert_eq!(arr.len(), STAGING_DIR_MAX_ENTRIES, "must clamp");
        assert_eq!(r["staged_files_truncated"], serde_json::Value::Bool(true));
        assert_eq!(r["staged_files_total_found"], serde_json::json!(n));
        // Deterministic truncation: kept entries are the alphabetically-first
        // STAGING_DIR_MAX_ENTRIES files (f-0000 .. f-0255 with the 0256+ ones
        // dropped).
        assert_eq!(arr.first().unwrap()["name"], "f-0000.bin");
    }

    #[tokio::test]
    async fn below_cap_reports_truncated_false() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.tgz"), b"abc").unwrap();
        std::fs::write(dir.path().join("b.tgz"), b"def").unwrap();
        let inv = Arc::new(Inventory::empty());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs {
                router_name: None,
                timeout: 5,
            },
            dm,
            dir.path().to_path_buf(),
        )
        .await
        .unwrap();
        assert_eq!(r["staged_files_truncated"], serde_json::Value::Bool(false));
        assert_eq!(r["staged_files_total_found"], serde_json::json!(2));
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{"r1":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        )
        .unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs {
                router_name: Some("nope".into()),
                timeout: 5,
            },
            dm,
            dir.path().to_path_buf(),
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}

#[cfg(test)]
mod device_handle_tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    /// Smoke: when router_name is given but the device is unreachable, the call
    /// returns an error (rustez connect failure), not silent success. This
    /// guards against the device_files key being silently set to []
    /// when the device isn't actually contacted.
    #[tokio::test]
    async fn unreachable_router_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        // 192.0.2.1 is TEST-NET-1, RFC 5737 — guaranteed unreachable.
        let key = tempfile::NamedTempFile::new().unwrap();
        let json = format!(
            r#"{{"r1":{{"ip":"192.0.2.1","username":"u",
                       "auth":{{"type":"ssh_key","private_key_path":"{}"}}}}}}"#,
            key.path().display()
        );
        f.write_all(json.as_bytes()).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            ListStagedFilesArgs {
                router_name: Some("r1".into()),
                timeout: 5,
            },
            dm,
            dir.path().to_path_buf(),
        )
        .await;
        // Either Timeout, ConnectTimeout, or a Rustez connect failure. Just
        // assert it's an error, not Ok with empty device_files.
        assert!(r.is_err(), "expected error against TEST-NET-1, got {r:?}");
    }
}
