use lazy_static::lazy_static;
use std::env;

lazy_static! {
    pub static ref RADIANCE_API_CONFIG: String =
        env::var("RADIANCE_API_CONFIG").unwrap_or_else(|_| "radiance-api.toml".to_string());
    pub static ref MONGODB_URI: String =
        env::var("MONGODB_URI").expect("Missing MONGODB_URI environment variable");
    pub static ref MONGODB_DATABASE: String =
        env::var("MONGODB_DATABASE").unwrap_or_else(|_| "radiance-api".to_string());
}