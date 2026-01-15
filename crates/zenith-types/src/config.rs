use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CertificateConfig {
    pub name: String,
    pub domains: Vec<String>,
    pub acme_provider: String,
    pub dns_provider: String,
    pub account_email: String,
    pub control_socket: Option<String>,
}
