use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use zenith_types::CertificateConfig;

use crate::environment::CONFIG_FILE;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub certificates: HashMap<String, CertificateConfig>,
    pub dns_providers: DnsProviders,
    pub store_location: StoreLocation,
    pub control_socket_path: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StoreLocation {
    Local { path: String },
    Vault,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsProviders {
    #[serde(default)]
    pub cloudflare: Option<CloudflareConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CloudflareConfig {
    pub api_key: String,
}

impl Config {
    pub fn load() -> Result<Self> {
        if PathBuf::from(&*CONFIG_FILE).exists() {
            return Self::from_file(&*CONFIG_FILE);
        }

        Err(anyhow!(
            "No configuration file found. Please set CONFIG_FILE environment variable or create zenith.toml"
        ))
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.certificates.is_empty() {
            return Err(anyhow!("No certificates configured"));
        }

        for (_, cert) in &self.certificates {
            if cert.domains.is_empty() {
                return Err(anyhow!(
                    "Certificate '{}' has no domains specified",
                    cert.name
                ));
            }
            if cert.account_email.is_empty() {
                return Err(anyhow!("Certificate '{}' has no account email", cert.name));
            }
        }

        Ok(())
    }
}
