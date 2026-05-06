//! `reload_devices` — re-read the current inventory or swap to a new path.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::inventory::{hash_file, Inventory};
use crate::tools::ReloadDevicesArgs;
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;

pub async fn handle(
    args: ReloadDevicesArgs,
    dm: Arc<DeviceManager>,
) -> Result<serde_json::Value, JmcpError> {
    if dm.inventory_readonly() {
        return Err(JmcpError::InventoryReadonly);
    }

    let lock = dm.write_lock();
    let _guard = lock.lock().await;

    let path: PathBuf = match args.file_name.as_deref() {
        None | Some("") => dm.inventory_path(),
        Some(p) => {
            let candidate = PathBuf::from(p);
            // Reject path traversal
            if candidate
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(JmcpError::InventoryInvalid(
                    "file_name must not contain '..' path components".into(),
                ));
            }
            // If relative, resolve relative to current inventory directory
            if candidate.is_relative() {
                if let Some(parent) = dm.inventory_path().parent() {
                    parent.join(&candidate)
                } else {
                    candidate
                }
            } else {
                candidate
            }
        }
    };

    if !path.is_file() {
        return Err(JmcpError::InventoryRead(format!(
            "not a regular file: {}",
            path.display(),
        )));
    }

    let new_inv = Inventory::load(&path).map_err(|e| JmcpError::InventoryParse(e.to_string()))?;
    if new_inv.is_empty() {
        return Err(JmcpError::EmptyInventory);
    }

    let prev = dm.inventory();
    let prev_count = prev.len();
    let new_count = new_inv.len();

    let prev_names: std::collections::BTreeSet<String> = prev.names().into_iter().collect();
    let new_names: std::collections::BTreeSet<String> = new_inv.names().into_iter().collect();
    let added: Vec<String> = new_names.difference(&prev_names).cloned().collect();
    let removed: Vec<String> = prev_names.difference(&new_names).cloned().collect();
    let mut changed: Vec<String> = Vec::new();
    for name in prev_names.intersection(&new_names) {
        if let (Ok(p), Ok(n)) = (prev.get(name), new_inv.get(name)) {
            if !inventory_entry_equal(p, n) {
                changed.push(name.clone());
            }
        }
    }

    let new_hash = hash_file(&path).map_err(|e| JmcpError::InventoryRead(e.to_string()))?;
    dm.store_inventory(Arc::new(new_inv), path.clone(), new_hash);

    // Invalidate pooled sessions for removed or changed routers.
    let invalidate: Vec<String> = removed.iter().chain(changed.iter()).cloned().collect();
    if !invalidate.is_empty() {
        dm.invalidate_pool(&invalidate).await;
    }

    Ok(json!({
        "previous_router_count": prev_count,
        "new_router_count": new_count,
        "added": added,
        "removed": removed,
        "changed": changed,
        "inventory_path": path,
    }))
}

fn inventory_entry_equal(
    a: &crate::inventory::DeviceEntry,
    b: &crate::inventory::DeviceEntry,
) -> bool {
    a.ip == b.ip && a.port == b.port && a.username == b.username && a.auth == b.auth
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dm_at(path: &std::path::Path, readonly: bool) -> Arc<DeviceManager> {
        let inv = Arc::new(Inventory::load(path).unwrap());
        let hash = crate::inventory::hash_file(path).unwrap();
        Arc::new(DeviceManager::with_path(
            inv,
            path.to_path_buf(),
            hash,
            readonly,
            false,
        ))
    }

    fn write_file(json: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[tokio::test]
    async fn reload_no_args_re_reads_current_path() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), false);

        // Edit the file externally.
        std::fs::write(
            f.path(),
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                 "r2":{"ip":"127.0.0.2","username":"u","auth":{"type":"password","password":"x"}}}"#,
        ).unwrap();

        let r = handle(ReloadDevicesArgs::default(), dm.clone())
            .await
            .unwrap();
        assert_eq!(r["previous_router_count"], 1);
        assert_eq!(r["new_router_count"], 2);
        assert!(r["added"].as_array().unwrap().iter().any(|v| v == "r2"));
        assert!(dm.inventory().get("r2").is_ok());
    }

    #[tokio::test]
    async fn reload_with_file_name_swaps_inventory() {
        let f1 = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let f2 = write_file(
            r#"{"r9":{"ip":"127.0.0.9","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f1.path(), false);

        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(f2.path().to_string_lossy().to_string()),
            },
            dm.clone(),
        )
        .await
        .unwrap();

        assert_eq!(r["new_router_count"], 1);
        assert_eq!(r["inventory_path"], f2.path().to_string_lossy().as_ref());
        assert!(dm.inventory().get("r9").is_ok());
        assert!(dm.inventory().get("r1").is_err());
    }

    #[tokio::test]
    async fn reload_empty_inventory_rejected() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), false);
        let f_empty = write_file(r#"{}"#);
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(f_empty.path().to_string_lossy().to_string()),
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::EmptyInventory)));
    }

    #[tokio::test]
    async fn reload_inventory_readonly_rejected() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), true);
        let r = handle(ReloadDevicesArgs::default(), dm).await;
        assert!(matches!(r, Err(JmcpError::InventoryReadonly)));
    }

    #[tokio::test]
    async fn reload_reports_added_removed_changed_diff() {
        let f1 = write_file(
            r#"{
                "keep":{"ip":"10.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                "gone":{"ip":"10.0.0.2","username":"u","auth":{"type":"password","password":"x"}},
                "mut":{"ip":"10.0.0.3","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let f2 = write_file(
            r#"{
                "keep":{"ip":"10.0.0.1","username":"u","auth":{"type":"password","password":"x"}},
                "mut":{"ip":"10.0.0.3","username":"v","auth":{"type":"password","password":"x"}},
                "new":{"ip":"10.0.0.4","username":"u","auth":{"type":"password","password":"x"}}
            }"#,
        );
        let dm = dm_at(f1.path(), false);
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(f2.path().to_string_lossy().to_string()),
            },
            dm,
        )
        .await
        .unwrap();
        let added: Vec<String> = serde_json::from_value(r["added"].clone()).unwrap();
        let removed: Vec<String> = serde_json::from_value(r["removed"].clone()).unwrap();
        let changed: Vec<String> = serde_json::from_value(r["changed"].clone()).unwrap();
        assert_eq!(added, vec!["new"]);
        assert_eq!(removed, vec!["gone"]);
        assert_eq!(changed, vec!["mut"]);
    }

    #[tokio::test]
    async fn reload_rejects_path_traversal() {
        let f = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = dm_at(f.path(), false);
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some("../../../etc/shadow".into()),
            },
            dm,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::InventoryInvalid(ref msg)) if msg.contains("..")));
    }

    #[tokio::test]
    async fn reload_detects_password_change() {
        let f1 = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"old"}}}"#,
        );
        let f2 = write_file(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"new"}}}"#,
        );
        let dm = dm_at(f1.path(), false);
        let r = handle(
            ReloadDevicesArgs {
                file_name: Some(f2.path().to_string_lossy().to_string()),
            },
            dm,
        )
        .await
        .unwrap();
        let changed: Vec<String> = serde_json::from_value(r["changed"].clone()).unwrap();
        assert_eq!(changed, vec!["r1"], "password change must be detected");
    }
}
