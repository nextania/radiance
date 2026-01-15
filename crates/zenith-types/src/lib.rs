pub mod config;
pub mod control_socket;

pub use config::*;
pub use control_socket::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
    pub chain: Vec<u8>,
}
