//! `get_router_list` — return the inventory's router names. Pure, no device contact.

use crate::error::JmcpError;
use crate::inventory::Inventory;
use serde_json::{json, Value};
use std::sync::Arc;

pub async fn handle(inv: Arc<Inventory>) -> Result<Value, JmcpError> {
    Ok(json!(inv.names()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_inv(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn returns_sorted_names() {
        let inv = make_inv(r#"{
            "z":{"ip":"1.1.1.1","username":"u","auth":{"type":"password","password":"x"}},
            "a":{"ip":"1.1.1.2","username":"u","auth":{"type":"password","password":"x"}}
        }"#);
        let v = handle(inv).await.unwrap();
        assert_eq!(v, json!(["a", "z"]));
    }
}
