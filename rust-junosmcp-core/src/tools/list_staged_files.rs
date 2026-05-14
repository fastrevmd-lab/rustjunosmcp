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

// Stubbed handler so the module compiles; full impl lands in Task 11.
pub async fn handle(
    _args: crate::tools::ListStagedFilesArgs,
    _dm: std::sync::Arc<crate::device_manager::DeviceManager>,
    _staging_dir: std::path::PathBuf,
) -> Result<serde_json::Value, JmcpError> {
    Err(JmcpError::Validation("not yet implemented".into()))
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
