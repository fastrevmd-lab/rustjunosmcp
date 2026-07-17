//! Symlink-resistant local staging and safe bundle filename construction.

use crate::SrxError;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

/// Packaged default support-bundle staging directory.
pub const DEFAULT_STAGING_DIR: &str = "/var/lib/jmcp/srx-staging/bundles";

/// Packaged default support-bundle staging cap (500 MiB).
pub const DEFAULT_STAGING_MAX_BYTES: u64 = 500 * 1024 * 1024;

/// Maximum byte length for any caller- or inventory-derived path component.
pub const MAX_PATH_COMPONENT_BYTES: usize = 64;

/// Process-level support-bundle staging policy, resolved once during bootstrap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportBundleStagingConfig {
    directory: PathBuf,
    max_bytes: u64,
}

impl SupportBundleStagingConfig {
    pub fn new(directory: PathBuf, max_bytes: u64) -> Self {
        Self {
            directory,
            max_bytes,
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }

    pub fn max_bytes(&self) -> u64 {
        self.max_bytes
    }
}

impl Default for SupportBundleStagingConfig {
    fn default() -> Self {
        Self::new(
            PathBuf::from(DEFAULT_STAGING_DIR),
            DEFAULT_STAGING_MAX_BYTES,
        )
    }
}

fn invalid_component(kind: &str) -> SrxError {
    SrxError::InvalidInput(format!(
        "{kind} must be 1..={MAX_PATH_COMPONENT_BYTES} ASCII characters from [A-Za-z0-9_.-], must not be '.' or '..', and must not start with '-'"
    ))
}

/// Validate one path component before it reaches a local or device path.
pub fn validate_path_component(kind: &str, value: &str) -> Result<(), SrxError> {
    if value.is_empty()
        || value.len() > MAX_PATH_COMPONENT_BYTES
        || value == "."
        || value == ".."
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        return Err(invalid_component(kind));
    }
    Ok(())
}

fn filesystem_id_stem(filesystem_id: &str) -> Result<&str, SrxError> {
    validate_path_component("filesystem_id", filesystem_id)?;
    let stem = filesystem_id
        .strip_prefix("srxmcp-")
        .unwrap_or(filesystem_id);
    validate_path_component("filesystem_id", stem)?;
    Ok(stem)
}

fn bundle_filename(filesystem_id: &str, extension: &str) -> Result<String, SrxError> {
    let stem = filesystem_id_stem(filesystem_id)?;
    Ok(format!("srxmcp-{stem}.{extension}"))
}

/// Per-router subdirectory path under the configured staging root.
pub fn router_staging_dir(
    config: &SupportBundleStagingConfig,
    router: &str,
) -> Result<PathBuf, SrxError> {
    validate_path_component("router", router)?;
    Ok(config.directory().join(router))
}

/// Canonical on-LXC path for a bundle tarball.
pub fn bundle_tarball_path(
    config: &SupportBundleStagingConfig,
    router: &str,
    filesystem_id: &str,
) -> Result<PathBuf, SrxError> {
    Ok(router_staging_dir(config, router)?.join(bundle_filename(filesystem_id, "tgz")?))
}

/// Canonical on-LXC path for a bundle sidecar manifest.
pub fn bundle_manifest_path(
    config: &SupportBundleStagingConfig,
    router: &str,
    filesystem_id: &str,
) -> Result<PathBuf, SrxError> {
    Ok(router_staging_dir(config, router)?.join(bundle_filename(filesystem_id, "json")?))
}

/// Canonical on-device staging path for a tarball.
pub fn device_tarball_path(filesystem_id: &str) -> Result<String, SrxError> {
    Ok(format!(
        "/var/tmp/{}",
        bundle_filename(filesystem_id, "tgz")?
    ))
}

/// Convert a configured Junos log path into a validated tarball-relative path.
pub fn device_log_tarball_path(device_path: &str) -> Result<PathBuf, SrxError> {
    let relative = Path::new(device_path)
        .strip_prefix("/var/log")
        .map_err(|_| SrxError::InvalidInput("device log path must be below /var/log".into()))?;
    let mut result = PathBuf::from("logs");
    let mut components = 0usize;
    for component in relative.components() {
        match component {
            Component::Normal(value) => {
                let value = value.to_str().ok_or_else(|| {
                    SrxError::InvalidInput("device log filename must be ASCII".into())
                })?;
                validate_path_component("device log filename", value)?;
                result.push(value);
                components += 1;
            }
            _ => {
                return Err(SrxError::InvalidInput(
                    "device log path contains an unsafe component".into(),
                ));
            }
        }
    }
    if components == 0 {
        return Err(SrxError::InvalidInput(
            "device log path must name a file below /var/log".into(),
        ));
    }
    Ok(result)
}

fn checked_directory(path: &Path, kind: &str) -> Result<PathBuf, SrxError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| SrxError::InvalidInput(format!("inspect {kind}: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SrxError::InvalidInput(format!(
            "{kind} must be a real directory, not a symlink or file: {}",
            path.display()
        )));
    }
    fs::canonicalize(path)
        .map_err(|error| SrxError::InvalidInput(format!("canonicalize {kind}: {error}")))
}

fn ensure_descendant(path: &Path, root: &Path, kind: &str) -> Result<(), SrxError> {
    if path == root || !path.starts_with(root) {
        return Err(SrxError::InvalidInput(format!(
            "{kind} escapes configured staging root"
        )));
    }
    Ok(())
}

fn create_or_check_directory(path: &Path, kind: &str) -> Result<(), SrxError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(SrxError::InvalidInput(format!(
                "{kind} must be a real directory, not a symlink or file: {}",
                path.display()
            )))
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => create_private_directory(path, kind),
        Err(error) => Err(SrxError::InvalidInput(format!("inspect {kind}: {error}"))),
    }
}

fn create_private_directory(path: &Path, kind: &str) -> Result<(), SrxError> {
    let mut builder = DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|error| SrxError::InvalidInput(format!("create {kind}: {error}")))
}

fn remove_without_following(path: &Path) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        let _ = fs::remove_file(path);
    } else if metadata.is_dir() {
        let _ = fs::remove_dir_all(path);
    }
}

/// Validated staging paths for one support-bundle collection.
///
/// Dropping this value removes its scratch tree. Until [`Self::commit_tarball`]
/// is called, it also removes a partial tarball.
#[derive(Debug)]
pub struct PreparedBundlePaths {
    staging_root: PathBuf,
    staging_max_bytes: u64,
    router_dir: PathBuf,
    scratch_dir: PathBuf,
    tarball_path: PathBuf,
    keep_tarball: bool,
}

impl PreparedBundlePaths {
    pub fn prepare(
        config: &SupportBundleStagingConfig,
        router: &str,
        filesystem_id: &str,
    ) -> Result<Self, SrxError> {
        Self::prepare_under(
            config.directory(),
            config.max_bytes(),
            router,
            filesystem_id,
        )
    }

    pub(crate) fn prepare_under(
        configured_root: &Path,
        staging_max_bytes: u64,
        router: &str,
        filesystem_id: &str,
    ) -> Result<Self, SrxError> {
        validate_path_component("router", router)?;
        let scratch_name = format!("srxmcp-{}-scratch", filesystem_id_stem(filesystem_id)?);
        validate_path_component("scratch directory", &scratch_name)?;
        let tarball_name = bundle_filename(filesystem_id, "tgz")?;

        fs::create_dir_all(configured_root).map_err(|error| {
            SrxError::InvalidInput(format!(
                "create staging root {}: {error}",
                configured_root.display()
            ))
        })?;
        let staging_root = checked_directory(configured_root, "staging root")?;

        let router_candidate = staging_root.join(router);
        create_or_check_directory(&router_candidate, "router staging directory")?;
        let router_dir = checked_directory(&router_candidate, "router staging directory")?;
        ensure_descendant(&router_dir, &staging_root, "router staging directory")?;

        let scratch_candidate = router_dir.join(scratch_name);
        create_private_directory(&scratch_candidate, "bundle scratch directory")?;
        let scratch_dir = match checked_directory(&scratch_candidate, "bundle scratch directory") {
            Ok(path) => path,
            Err(error) => {
                remove_without_following(&scratch_candidate);
                return Err(error);
            }
        };
        if let Err(error) = ensure_descendant(&scratch_dir, &router_dir, "bundle scratch directory")
        {
            remove_without_following(&scratch_dir);
            return Err(error);
        }

        let tarball_path = router_dir.join(tarball_name);
        if fs::symlink_metadata(&tarball_path).is_ok() {
            remove_without_following(&scratch_dir);
            return Err(SrxError::InvalidInput(
                "bundle tarball destination already exists".into(),
            ));
        }

        Ok(Self {
            staging_root,
            staging_max_bytes,
            router_dir,
            scratch_dir,
            tarball_path,
            keep_tarball: false,
        })
    }

    pub fn router_dir(&self) -> &Path {
        &self.router_dir
    }

    pub(crate) fn staging_max_bytes(&self) -> u64 {
        self.staging_max_bytes
    }

    pub fn scratch_dir(&self) -> &Path {
        &self.scratch_dir
    }

    pub fn tarball_path(&self) -> &Path {
        &self.tarball_path
    }

    pub fn ensure_confined(&self) -> Result<(), SrxError> {
        let root = checked_directory(&self.staging_root, "staging root")?;
        let router = checked_directory(&self.router_dir, "router staging directory")?;
        let scratch = checked_directory(&self.scratch_dir, "bundle scratch directory")?;
        if root != self.staging_root || router != self.router_dir || scratch != self.scratch_dir {
            return Err(SrxError::InvalidInput(
                "staging path changed during bundle collection".into(),
            ));
        }
        ensure_descendant(&router, &root, "router staging directory")?;
        ensure_descendant(&scratch, &router, "bundle scratch directory")?;
        if self.tarball_path.parent() != Some(router.as_path()) {
            return Err(SrxError::InvalidInput(
                "bundle tarball escapes router staging directory".into(),
            ));
        }
        Ok(())
    }

    pub fn create_tarball(&self) -> Result<File, SrxError> {
        self.ensure_confined()?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(&self.tarball_path).map_err(|error| {
            SrxError::InvalidInput(format!("create bundle tarball securely: {error}"))
        })
    }

    pub fn commit_tarball(&mut self) {
        self.keep_tarball = true;
    }
}

impl Drop for PreparedBundlePaths {
    fn drop(&mut self) {
        remove_without_following(&self.scratch_dir);
        if !self.keep_tarball {
            remove_without_following(&self.tarball_path);
        }
    }
}

/// LRU eviction stub.
pub fn enforce_staging_cap(_cap_bytes: u64) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_config_controls_all_host_paths() {
        let root = tempfile::tempdir().unwrap();
        let config = SupportBundleStagingConfig::new(root.path().to_path_buf(), 123_456);

        assert_eq!(config.directory(), root.path());
        assert_eq!(config.max_bytes(), 123_456);
        assert_eq!(
            bundle_tarball_path(&config, "srx-01", "srxmcp-request-1").unwrap(),
            root.path().join("srx-01/srxmcp-request-1.tgz")
        );

        let paths = PreparedBundlePaths::prepare(&config, "srx-01", "srxmcp-request-1").unwrap();
        assert_eq!(paths.staging_max_bytes(), 123_456);
    }

    #[test]
    fn packaged_defaults_are_stable() {
        let config = SupportBundleStagingConfig::default();
        assert_eq!(
            config.directory(),
            Path::new("/var/lib/jmcp/srx-staging/bundles")
        );
        assert_eq!(config.max_bytes(), 500 * 1024 * 1024);
    }

    #[test]
    fn default_staging_dir_matches_packaged_systemd_write_path() {
        assert!(DEFAULT_STAGING_DIR.starts_with("/var/lib/jmcp/"));
    }

    #[test]
    fn path_components_accept_expected_ids() {
        for value in ["r1", "vSRX-test10", "ticket_123", "srxmcp-a783d1a5"] {
            validate_path_component("test", value).unwrap();
        }
    }

    #[test]
    fn path_components_reject_traversal_controls_and_long_values() {
        let long = "x".repeat(MAX_PATH_COMPONENT_BYTES + 1);
        for value in [
            "",
            " ",
            ".",
            "..",
            "../escape",
            "/absolute",
            "a/b",
            "a\\b",
            "line\nbreak",
            "-leading-option",
            "non-ascii-é",
            &long,
        ] {
            assert!(
                validate_path_component("test", value).is_err(),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn path_builders_use_one_prefix_and_reject_bad_inputs() {
        let config = SupportBundleStagingConfig::default();
        let minted = "srxmcp-a783d1a5";
        assert!(bundle_tarball_path(&config, "vSRX-test10", minted)
            .unwrap()
            .ends_with("srxmcp-a783d1a5.tgz"));
        assert!(bundle_manifest_path(&config, "vSRX-test10", "deadbeef")
            .unwrap()
            .ends_with("srxmcp-deadbeef.json"));
        assert_eq!(
            device_tarball_path(minted).unwrap(),
            "/var/tmp/srxmcp-a783d1a5.tgz"
        );
        assert!(bundle_tarball_path(&config, "../router", minted).is_err());
        assert!(device_tarball_path("../../escape").is_err());
    }

    #[test]
    fn device_log_paths_are_confined_and_component_validated() {
        assert_eq!(
            device_log_tarball_path("/var/log/messages").unwrap(),
            PathBuf::from("logs/messages")
        );
        for bad in [
            "/etc/passwd",
            "/var/log/../etc/passwd",
            "/var/log/a/b/../../escape",
            "/var/log/a\\b",
            "/var/log/",
        ] {
            assert!(device_log_tarball_path(bad).is_err(), "accepted {bad:?}");
        }
    }

    #[test]
    fn drop_removes_scratch_and_partial_tarball() {
        let temp = tempfile::tempdir().unwrap();
        let (scratch, tarball) = {
            let paths = PreparedBundlePaths::prepare_under(
                temp.path(),
                DEFAULT_STAGING_MAX_BYTES,
                "vSRX-test10",
                "srxmcp-cleanup-test",
            )
            .unwrap();
            fs::write(paths.scratch_dir().join("partial.txt"), b"partial").unwrap();
            drop(paths.create_tarball().unwrap());
            (
                paths.scratch_dir().to_path_buf(),
                paths.tarball_path().to_path_buf(),
            )
        };
        assert!(!scratch.exists());
        assert!(!tarball.exists());
    }

    #[test]
    fn existing_tarball_rejection_removes_new_scratch() {
        let temp = tempfile::tempdir().unwrap();
        let router_dir = temp.path().join("vSRX-test10");
        fs::create_dir(&router_dir).unwrap();
        let tarball = router_dir.join("srxmcp-collision-test.tgz");
        fs::write(&tarball, b"existing").unwrap();

        let result = PreparedBundlePaths::prepare_under(
            temp.path(),
            DEFAULT_STAGING_MAX_BYTES,
            "vSRX-test10",
            "srxmcp-collision-test",
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&tarball).unwrap(), b"existing");
        assert!(!router_dir.join("srxmcp-collision-test-scratch").exists());
    }

    #[cfg(unix)]
    #[test]
    fn tarball_symlink_is_rejected_without_touching_target() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let router_dir = temp.path().join("vSRX-test10");
        fs::create_dir(&router_dir).unwrap();
        let outside = temp.path().join("outside.tgz");
        fs::write(&outside, b"do not overwrite").unwrap();
        symlink(&outside, router_dir.join("srxmcp-symlink-target.tgz")).unwrap();

        let result = PreparedBundlePaths::prepare_under(
            temp.path(),
            DEFAULT_STAGING_MAX_BYTES,
            "vSRX-test10",
            "srxmcp-symlink-target",
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&outside).unwrap(), b"do not overwrite");
        assert!(!router_dir.join("srxmcp-symlink-target-scratch").exists());
    }

    #[cfg(unix)]
    #[test]
    fn router_symlink_escape_is_rejected() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        fs::create_dir(&root).unwrap();
        fs::create_dir(&outside).unwrap();
        symlink(&outside, root.join("router1")).unwrap();

        let result = PreparedBundlePaths::prepare_under(
            &root,
            DEFAULT_STAGING_MAX_BYTES,
            "router1",
            "srxmcp-symlink-test",
        );
        assert!(result.is_err());
        assert!(fs::read_dir(&outside).unwrap().next().is_none());
    }
}
