//! Configurable tracing/audit sinks: stderr (text or JSON), an optional
//! dedicated JSON audit file, and an optional native journald target.

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing_subscriber::filter::filter_fn;
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

/// stderr output format for logs and audit events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditFormat {
    Text,
    Json,
}

impl AuditFormat {
    /// Parse from a CLI/env string; unknown → Text.
    pub fn parse(s: &str) -> Self {
        if s.eq_ignore_ascii_case("json") {
            AuditFormat::Json
        } else {
            AuditFormat::Text
        }
    }
}

/// Audit / logging configuration.
#[derive(Debug, Clone)]
pub struct AuditConfig {
    pub format: AuditFormat,
    /// When set, `target="audit"` events are also appended as JSON lines here.
    pub audit_log_file: Option<PathBuf>,
    /// When set, per-field redaction is applied to emitted audit events.
    pub redaction: Option<crate::redact::AuditRedaction>,
    /// When true, `target="audit"` events are also sent to journald natively.
    pub journald: bool,
}

/// A cloneable append writer over a shared file handle.
#[derive(Clone)]
pub struct FileHandle(Arc<Mutex<File>>);

impl FileHandle {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let f = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(FileHandle(Arc::new(Mutex::new(f))))
    }
}

impl Write for FileHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap().flush()
    }
}

impl<'a> MakeWriter<'a> for FileHandle {
    type Writer = FileHandle;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn is_audit(meta: &tracing::Metadata<'_>) -> bool {
    meta.target() == "audit"
}

/// A JSON fmt layer filtered to `target == "audit"`, writing to `handle`.
pub fn audit_file_layer<S>(handle: FileHandle) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer()
        .json()
        .with_writer(handle)
        .with_filter(filter_fn(is_audit))
}

fn audit_journald_layer<S>(layer: tracing_journald::Layer) -> impl Layer<S>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    layer
        .with_field_prefix(Some("AUDIT".to_owned()))
        .with_filter(filter_fn(is_audit))
}

fn make_journald_layer_with<F>(
    enabled: bool,
    factory: F,
) -> io::Result<Option<tracing_journald::Layer>>
where
    F: FnOnce() -> io::Result<tracing_journald::Layer>,
{
    if enabled {
        factory().map(Some)
    } else {
        Ok(None)
    }
}

/// Initialize the global subscriber. Idempotent (`try_init`).
///
/// Returns an error only when the explicitly enabled journald layer cannot be
/// constructed. An already-installed global subscriber remains a no-op.
pub fn init_tracing(cfg: &AuditConfig) -> io::Result<()> {
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stderr = tracing_subscriber::fmt::layer().with_writer(std::io::stderr);
    let stderr = match cfg.format {
        AuditFormat::Text => stderr.boxed(),
        AuditFormat::Json => tracing_subscriber::fmt::layer()
            .json()
            .with_writer(std::io::stderr)
            .boxed(),
    };
    let file_layer = cfg
        .audit_log_file
        .as_ref()
        .and_then(|p| FileHandle::open(p).ok())
        .map(audit_file_layer);
    let journald_layer =
        make_journald_layer_with(cfg.journald, tracing_journald::layer)?
            .map(audit_journald_layer);

    let _ = tracing_subscriber::registry()
        .with(env)
        .with(stderr)
        .with(file_layer)
        .with(journald_layer)
        .try_init();

    if let Some(redaction) = cfg.redaction.clone() {
        crate::redact::install(redaction);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_line_written_to_audit_file_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        // Build only the file layer + a temporary subscriber (not the global one,
        // which other tests may have set). Verify a target="audit" event lands as JSON.
        let handle = FileHandle::open(&path).unwrap();
        let layer = audit_file_layer(handle.clone());
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "audit", tool = "t", result = "ok", "audit");
            tracing::info!(target: "not_audit", "ignored");
        });
        drop(handle); // flush
        let body = std::fs::read_to_string(&path).unwrap();
        let line = body.lines().next().expect("one audit line");
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["fields"]["tool"], "t");
        assert!(
            !body.contains("ignored"),
            "non-audit events must not hit the audit file"
        );
    }

    #[test]
    fn disabled_journald_does_not_call_factory() {
        let layer = make_journald_layer_with(
            false,
            || -> std::io::Result<tracing_journald::Layer> {
                panic!("disabled journald must not construct a socket")
            },
        )
        .expect("disabled journald is infallible");

        assert!(layer.is_none());
    }

    #[test]
    fn enabled_journald_propagates_factory_error() {
        let result = make_journald_layer_with(true, || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "journal unavailable",
            ))
        });

        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("enabled journald must propagate construction failure"),
        };
        assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(error.to_string(), "journal unavailable");
    }
}
