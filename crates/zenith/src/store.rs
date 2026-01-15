use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use tokio::fs;

pub struct VaultStore {
    pub id: String,
}

pub struct LocalStore {
    pub path: PathBuf,
}

#[async_trait]
pub trait Store: Send + Sync {
    async fn get_account_key(&self) -> Result<Option<String>>;
    async fn get_cert_key(&self) -> Result<Option<Vec<u8>>>;
    async fn get_cert(&self) -> Result<Option<Vec<u8>>>;
    async fn get_chain(&self) -> Result<Option<Vec<u8>>>;
    async fn store_certificate(&self, key: &str, cert: &str, chain: &str) -> Result<()>;
    async fn store_account_key(&self, account_key: &str) -> Result<()>;
}

impl LocalStore {
    pub async fn new(base: PathBuf, id: &str) -> Result<Self> {
        let path = base.join(id);
        fs::create_dir_all(&path).await.unwrap();
        Ok(Self { path })
    }
}

impl VaultStore {
    pub async fn new(id: String) -> Result<Self> {
        Ok(Self { id })
    }
}

#[async_trait]
impl Store for LocalStore {

    async fn get_account_key(&self) -> Result<Option<String>> {
        let path = self.path.join("account.key");
        if !path.exists() {
            return Ok(None);
        }
        let key = fs::read_to_string(path).await?;
        Ok(Some(key))
    }

    async fn get_cert_key(&self) -> Result<Option<Vec<u8>>> {
        let path = self.path.join("cert.key");
        if !path.exists() {
            return Ok(None);
        }
        let key = fs::read(path).await?;
        Ok(Some(key))
    }

    async fn get_cert(&self) -> Result<Option<Vec<u8>>> {
        let path = self.path.join("cert.pem");
        if !path.exists() {
            return Ok(None);
        }
        let cert = fs::read(path).await?;
        Ok(Some(cert))
    }

    async fn get_chain(&self) -> Result<Option<Vec<u8>>> {
        let path = self.path.join("chain.pem");
        if !path.exists() {
            return Ok(None);
        }
        let chain = fs::read(path).await?;
        Ok(Some(chain))
    }

    async fn store_certificate(&self, key: &str, cert: &str, chain: &str) -> Result<()> {
        let key_path = self.path.join("cert.key");
        let cert_path = self.path.join("cert.pem");
        let chain_path = self.path.join("chain.pem");
        let fullchain_path = self.path.join("fullchain.pem");
        fs::write(key_path, key).await?;
        fs::write(cert_path, cert).await?;
        fs::write(chain_path, chain).await?;
        let fullchain = format!("{}{}", cert, chain);
        fs::write(fullchain_path, fullchain).await?;
        Ok(())
    }

    async fn store_account_key(&self, account_key: &str) -> Result<()> {
        let path = self.path.join("account.key");
        fs::write(path, account_key).await?;
        Ok(())
    }
}

#[async_trait]
impl Store for VaultStore {

    async fn get_account_key(&self) -> Result<Option<String>> {
        todo!()
    }

    async fn get_cert_key(&self) -> Result<Option<Vec<u8>>> {
        todo!()
    }

    async fn get_cert(&self) -> Result<Option<Vec<u8>>> {
        todo!()
    }

    async fn get_chain(&self) -> Result<Option<Vec<u8>>> {
        todo!()
    }

    async fn store_certificate(&self, key: &str, cert: &str, chain: &str) -> Result<()> {
        todo!()
    }

    async fn store_account_key(&self, account_key: &str) -> Result<()> {
        todo!()
    }
}