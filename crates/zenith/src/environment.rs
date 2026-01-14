use lazy_static::lazy_static;
use std::env;

lazy_static! {
    // TODO: load certs from vault
    pub static ref VAULT_URI: Option<String> =
        env::var("VAULT_URI").ok();
    pub static ref VAULT_TOKEN: Option<String> =
        env::var("VAULT_TOKEN").ok();
    pub static ref CONFIG_FILE: String =
        env::var("CONFIG_FILE").unwrap_or_else(|_| "zenith.toml".to_string());
}
