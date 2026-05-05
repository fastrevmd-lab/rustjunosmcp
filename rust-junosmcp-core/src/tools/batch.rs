//! `execute_junos_command_batch` — N routers x M commands, parallel across routers.

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait RouterSession: Send {
    async fn cli(&mut self, command: &str) -> Result<String, JmcpError>;
    async fn close(&mut self) -> Result<(), JmcpError>;
}

#[async_trait]
pub trait BatchRunner: Send + Sync {
    async fn open(&self, router: &str) -> Result<Box<dyn RouterSession>, JmcpError>;
}

struct RustEzSession(rustez::Device);

#[async_trait]
impl RouterSession for RustEzSession {
    async fn cli(&mut self, command: &str) -> Result<String, JmcpError> {
        Ok(self.0.cli(command).await?)
    }
    async fn close(&mut self) -> Result<(), JmcpError> {
        Ok(self.0.close().await?)
    }
}

pub struct DeviceManagerRunner(pub Arc<DeviceManager>);

#[async_trait]
impl BatchRunner for DeviceManagerRunner {
    async fn open(&self, router: &str) -> Result<Box<dyn RouterSession>, JmcpError> {
        let dev = self.0.open(router).await?;
        Ok(Box::new(RustEzSession(dev)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    #[tokio::test]
    async fn device_manager_runner_propagates_unknown_router() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(
            br#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        )
        .unwrap();
        let inv = Arc::new(Inventory::load(f.path()).unwrap());
        let runner = DeviceManagerRunner(Arc::new(DeviceManager::new(inv)));
        let r = runner.open("ghost").await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }
}
