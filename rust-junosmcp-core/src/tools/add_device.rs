//! `add_device` — validate, persist atomically, swap inventory.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::validation::{
    is_valid_auth_path, is_valid_device_name, is_valid_ip_or_hostname, is_valid_ssh_username,
};
use crate::inventory::AuthConfig;
use crate::tools::AddDeviceArgs;
use std::sync::Arc;

/// Resolved + validated argument bundle. Produced by `validate()`.
#[derive(Debug)]
pub struct ResolvedAdd {
    pub device_name: String,
    pub device_ip: String,
    pub device_port: u32,
    pub username: String,
    pub auth: AuthConfig,
}

/// Pure validation: returns the resolved bundle or the most specific error.
/// Does NOT touch disk or the device manager's locks.
pub fn validate(args: &AddDeviceArgs, dm: &DeviceManager) -> Result<ResolvedAdd, JmcpError> {
    if dm.inventory_readonly() {
        return Err(JmcpError::InventoryReadonly);
    }

    let mut missing: Vec<String> = Vec::new();
    if args.device_name.is_none() {
        missing.push("device_name".into());
    }
    if args.device_ip.is_none() {
        missing.push("device_ip".into());
    }
    if args.username.is_none() {
        missing.push("username".into());
    }
    if args.auth.is_none() {
        missing.push("auth".into());
    }
    if !missing.is_empty() {
        return Err(JmcpError::MissingArguments(missing));
    }

    let device_name = args.device_name.clone().unwrap();
    if !is_valid_device_name(&device_name) {
        return Err(JmcpError::InvalidDeviceName(device_name));
    }
    let inv = dm.inventory();
    if inv.get(&device_name).is_ok() {
        return Err(JmcpError::DeviceExists(device_name));
    }

    let device_ip = args.device_ip.clone().unwrap();
    if !is_valid_ip_or_hostname(&device_ip) {
        return Err(JmcpError::InvalidDeviceIp(device_ip));
    }

    let device_port = args.device_port.unwrap_or(22);
    if !(1..=65535).contains(&device_port) {
        return Err(JmcpError::InvalidDevicePort(device_port));
    }

    let auth = args.auth.clone().unwrap();
    if matches!(auth, AuthConfig::Password { .. }) && !dm.allow_password_auth_add() {
        return Err(JmcpError::PasswordAuthDisabled);
    }
    if let AuthConfig::SshKey { private_key_path } = &auth {
        if !is_valid_auth_path(private_key_path) {
            return Err(JmcpError::Validation(format!(
                "invalid private_key_path `{}`: must be non-empty and must not start with '-'",
                private_key_path.display()
            )));
        }
    }

    let username = args.username.clone().unwrap();
    if !is_valid_ssh_username(&username) {
        return Err(JmcpError::Validation(format!(
            "invalid username `{username}`: must match ^[A-Za-z0-9_.-]{{1,64}}$ and must not start with '-'"
        )));
    }

    Ok(ResolvedAdd {
        device_name,
        device_ip,
        device_port,
        username,
        auth,
    })
}

pub async fn handle(
    args: AddDeviceArgs,
    dm: Arc<DeviceManager>,
) -> Result<serde_json::Value, JmcpError> {
    let resolved = validate(&args, &dm)?;

    let lock = dm.write_lock();
    let _guard = lock.lock().await;

    let path = dm.inventory_path();
    if path.as_os_str().is_empty() {
        return Err(JmcpError::InventoryWrite(
            "inventory has no on-disk path; add_device requires --device-mapping to point at a writable file".into(),
        ));
    }

    // TOCTOU guard: re-read disk and verify hash.
    let on_disk_hash =
        crate::inventory::hash_file(&path).map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    if on_disk_hash != dm.inventory_hash() {
        return Err(JmcpError::InventoryDriftedOnDisk);
    }

    let raw = std::fs::read(&path).map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    let value: serde_json::Value =
        serde_json::from_slice(&raw).map_err(|e| JmcpError::InventoryParse(e.to_string()))?;

    let updated = crate::inventory::insert_device(
        &value,
        &resolved.device_name,
        &resolved.device_ip,
        resolved.device_port,
        &resolved.username,
        &resolved.auth,
    )?;

    crate::inventory::write_atomic(&path, &updated)
        .map_err(|e| JmcpError::InventoryWrite(e.to_string()))?;

    let new_hash =
        crate::inventory::hash_file(&path).map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    let new_inv = Arc::new(
        crate::inventory::Inventory::load(&path)
            .map_err(|e| JmcpError::InventoryParse(e.to_string()))?,
    );
    dm.store_inventory(new_inv, path.clone(), new_hash);

    Ok(serde_json::json!({
        "added": resolved.device_name,
        "inventory_path": path,
        "router_count": dm.inventory().len(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn dm_with(json: &str, readonly: bool, allow_pw: bool) -> Arc<DeviceManager> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        Arc::new(DeviceManager::with_path(
            inv,
            f.path().to_path_buf(),
            crate::inventory::hash_file(f.path()).unwrap(),
            readonly,
            allow_pw,
        ))
    }

    fn args_full() -> AddDeviceArgs {
        AddDeviceArgs {
            device_name: Some("core-3".into()),
            device_ip: Some("10.0.0.3".into()),
            device_port: Some(22),
            username: Some("automation".into()),
            auth: Some(AuthConfig::SshKey {
                private_key_path: "/etc/jmcp/keys/id".into(),
            }),
        }
    }

    #[test]
    fn rejects_when_inventory_readonly() {
        let dm = dm_with(r#"{}"#, true, false);
        let r = validate(&args_full(), &dm);
        assert!(matches!(r, Err(JmcpError::InventoryReadonly)));
    }

    #[test]
    fn rejects_existing_device_name() {
        let dm = dm_with(
            r#"{"core-3":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
            false,
            true,
        );
        let r = validate(&args_full(), &dm);
        assert!(matches!(r, Err(JmcpError::DeviceExists(ref n)) if n == "core-3"));
    }

    #[test]
    fn rejects_missing_required_fields_with_list() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_name = None;
        a.username = None;
        let r = validate(&a, &dm);
        match r {
            Err(JmcpError::MissingArguments(v)) => {
                assert!(v.contains(&"device_name".to_string()));
                assert!(v.contains(&"username".to_string()));
            }
            other => panic!("expected MissingArguments, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_name_with_shell_meta() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_name = Some("evil; rm -rf /".into());
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDeviceName(_))));
    }

    #[test]
    fn rejects_invalid_ip_garbage() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_ip = Some("not an ip or host".into());
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDeviceIp(_))));
    }

    #[test]
    fn accepts_hostname_form() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_ip = Some("router-3.example.net".into());
        let r = validate(&a, &dm).unwrap();
        assert_eq!(r.device_ip, "router-3.example.net");
    }

    #[test]
    fn rejects_out_of_range_port() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.device_port = Some(70_000);
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::InvalidDevicePort(70_000))));
    }

    #[test]
    fn rejects_password_auth_when_flag_disabled() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.auth = Some(AuthConfig::Password {
            password: "x".into(),
        });
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::PasswordAuthDisabled)));
    }

    #[test]
    fn accepts_password_auth_when_flag_enabled() {
        let dm = dm_with(r#"{}"#, false, true);
        let mut a = args_full();
        a.auth = Some(AuthConfig::Password {
            password: "x".into(),
        });
        validate(&a, &dm).unwrap();
    }

    #[test]
    fn rejects_username_starting_with_dash() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.username = Some("-oProxyCommand=foo".into());
        let r = validate(&a, &dm);
        assert!(
            matches!(r, Err(JmcpError::Validation(ref s)) if s.contains("username")),
            "expected Validation error for dash-prefixed username, got {r:?}"
        );
    }

    #[test]
    fn rejects_username_with_space() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.username = Some("user with space".into());
        let r = validate(&a, &dm);
        assert!(matches!(r, Err(JmcpError::Validation(_))));
    }

    #[test]
    fn rejects_private_key_path_starting_with_dash() {
        let dm = dm_with(r#"{}"#, false, false);
        let mut a = args_full();
        a.auth = Some(AuthConfig::SshKey {
            private_key_path: "-evil".into(),
        });
        let r = validate(&a, &dm);
        assert!(
            matches!(r, Err(JmcpError::Validation(ref s)) if s.contains("private_key_path")),
            "expected Validation error for dash-prefixed key path, got {r:?}"
        );
    }

    #[test]
    fn accepts_typical_usernames() {
        let dm = dm_with(r#"{}"#, false, false);
        for name in ["admin", "netconf", "user.name", "user-name", "user_name"] {
            let mut a = args_full();
            a.username = Some(name.into());
            validate(&a, &dm).unwrap_or_else(|e| panic!("expected '{name}' accepted, got {e:?}"));
        }
    }

    #[tokio::test]
    async fn add_device_persists_to_disk_and_swaps_in_memory() {
        // Use a tempdir so the inventory file outlives dm_with's scope.
        let dir = tempfile::TempDir::new().unwrap();
        let inv_path = dir.path().join("devices.json");
        let json = r#"{"core-1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#;
        std::fs::write(&inv_path, json).unwrap();
        let inv = Arc::new(Inventory::load(&inv_path).unwrap());
        let hash = crate::inventory::hash_file(&inv_path).unwrap();
        let dm = Arc::new(DeviceManager::with_path(
            inv,
            inv_path.clone(),
            hash,
            false,
            true,
        ));

        let key = tempfile::NamedTempFile::new().unwrap();
        let mut args = args_full();
        args.auth = Some(AuthConfig::SshKey {
            private_key_path: key.path().to_path_buf(),
        });
        let r = handle(args, dm.clone()).await.unwrap();
        assert_eq!(r["added"], "core-3");
        assert_eq!(dm.inventory().len(), 2);
        // Verify disk was updated.
        let on_disk: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dm.inventory_path()).unwrap()).unwrap();
        assert!(on_disk.get("core-3").is_some());
        // key tempfile must stay alive until after handle() returns.
        drop(key);
    }

    #[tokio::test]
    async fn add_device_drift_check_rejects_external_edit() {
        // Use a tempdir so the inventory file stays alive after setup.
        let dir = tempfile::TempDir::new().unwrap();
        let inv_path = dir.path().join("devices.json");
        std::fs::write(&inv_path, r#"{}"#).unwrap();
        let inv = Arc::new(Inventory::load(&inv_path).unwrap());
        let hash = crate::inventory::hash_file(&inv_path).unwrap();
        let dm = Arc::new(DeviceManager::with_path(
            inv,
            inv_path.clone(),
            hash,
            false,
            true,
        ));

        // Mutate the file from underneath us, but leave the in-memory hash stale.
        std::fs::write(
            dm.inventory_path(),
            r#"{"sneaky":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        )
        .unwrap();
        let r = handle(args_full(), dm).await;
        assert!(matches!(r, Err(JmcpError::InventoryDriftedOnDisk)));
    }
}
