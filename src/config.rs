use anyhow::{anyhow, Result};
use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub cloudflare_api_key: String,
    pub account_email: String,
    pub domains: Vec<String>,
    pub use_production: bool,
    pub output_dir: String,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let cloudflare_api_key = env::var("CLOUDFLARE_API_KEY")
            .map_err(|_| {
                anyhow!("CLOUDFLARE_API_KEY environment variable not set")
            })?;
        let account_email = env::var("ACME_EMAIL")
            .map_err(|_| {
                anyhow!("ACME_EMAIL environment variable not set")
            })?;
        let domains_str = env::var("DOMAINS")
            .map_err(|_| anyhow!("DOMAINS environment variable not set (comma-separated list)"))?;
        let domains: Vec<String> = domains_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if domains.is_empty() {
            return Err(anyhow!("No domains specified in DOMAINS variable"));
        }
        let use_production = env::var("USE_PRODUCTION")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);
        let output_dir = env::var("OUTPUT_DIR").unwrap_or_else(|_| "./certs".to_string());

        Ok(Self {
            cloudflare_api_key,
            account_email,
            domains,
            use_production,
            output_dir,
        })
    }

    pub fn validate(&self) -> Result<()> {
        if self.cloudflare_api_key.is_empty() {
            return Err(anyhow!("Cloudflare API key is empty"));
        }
        if self.account_email.is_empty() {
            return Err(anyhow!("Account email is empty"));
        }
        if self.domains.is_empty() {
            return Err(anyhow!("No domains specified"));
        }

        Ok(())
    }
}
