use lazy_static::lazy_static;
use std::env;

lazy_static! {
    // TODO: load certs from vault
    // pub static ref VAULT_URI: String =
    //     env::var("VAULT_URI").expect("Missing VAULT_URI environment variable");
    // pub static ref VAULT_TOKEN: String =
    //     env::var("VAULT_TOKEN").expect("Missing VAULT_TOKEN environment variable");
    pub static ref CONFIG_FILE: String =
        env::var("CONFIG_FILE").unwrap_or_else(|_| "radiance.toml".to_string());
}
