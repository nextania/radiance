use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiConfig {
    pub listen: String,
    pub socket_path: PathBuf,
    pub password_hash: Option<String>,
    pub oidc_providers: Vec<OidcProvider>,
}

impl ApiConfig {
    pub fn has_authentication(&self) -> bool {
        self.password_hash.is_some() || !self.oidc_providers.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcProvider {
    pub id: String,
    pub display_name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub logo_path: Option<String>,
}
