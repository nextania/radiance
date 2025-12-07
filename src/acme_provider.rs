use anyhow::Result;
use instant_acme::{LetsEncrypt, ZeroSsl};

#[derive(Debug, Clone)]
pub enum AcmeProviderType {
    LetsEncryptProduction,
    LetsEncryptStaging,
    ZeroSslProduction,
    Custom(String),
}

impl AcmeProviderType {
    pub fn directory_url(&self) -> &str {
        match self {
            AcmeProviderType::LetsEncryptProduction => LetsEncrypt::Production.url(),
            AcmeProviderType::LetsEncryptStaging => LetsEncrypt::Staging.url(),
            AcmeProviderType::ZeroSslProduction => ZeroSsl::Production.url(),
            AcmeProviderType::Custom(url) => url.as_str(),
        }
    }

    pub fn name(&self) -> &str {
        match self {
            AcmeProviderType::LetsEncryptProduction => "Let's Encrypt (production)",
            AcmeProviderType::LetsEncryptStaging => "Let's Encrypt (staging)",
            AcmeProviderType::ZeroSslProduction => "ZeroSSL",
            AcmeProviderType::Custom(_) => "Custom provider",
        }
    }

    pub fn from_string(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "letsencrypt" | "letsencrypt-production" => Ok(AcmeProviderType::LetsEncryptProduction),
            "letsencrypt-staging" => Ok(AcmeProviderType::LetsEncryptStaging),
            "zerossl" => Ok(AcmeProviderType::ZeroSslProduction),
            _ => {
                if s.starts_with("http://") || s.starts_with("https://") {
                    Ok(AcmeProviderType::Custom(s.to_string()))
                } else {
                    Err(anyhow::anyhow!("Unknown ACME provider: {}", s))
                }
            }
        }
    }
}

