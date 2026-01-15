pub mod control_socket;
pub mod config;

pub use control_socket::*;
pub use config::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
    pub chain: Vec<u8>,
}
