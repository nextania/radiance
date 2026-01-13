
use serde::{Deserialize, Serialize};

use crate::{HostConfig, PartialHostConfig};
use crate::config::TlsCertConfig;

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlCommand {
    AddHost { id: String, host: HostConfig },
    UpdateHost { id: String, host: PartialHostConfig },
    RemoveHost { id: String },
    ListHosts,
    Reload,
    GetHost { id: String },
    SetHttpChallenge { domain: String, token: String, thumbprint: String },
    ClearHttpChallenge { domain: String, token: String },
    AddCertificate { certificate: TlsCertConfig },
    RemoveCertificate { id: String },
    ListCertificates,
    GetCertificate { id: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ControlResponse {
    Success {
        data: Option<serde_json::Value>,
    },
    Error {
        error: ControlError,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlError {
    HostNotFound,
    HostAlreadyExists,
    CertificateNotFound,
    CertificateAlreadyExists,
    InvalidCertificate,
    HttpChallengeNotFound,
    FailedToReload,
    FailedToSave,
    MalformedCommand,
    InternalError(String),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::HostNotFound => write!(f, "Host not found"),
            ControlError::HostAlreadyExists => write!(f, "Host already exists"),
            ControlError::CertificateNotFound => write!(f, "Certificate not found"),
            ControlError::CertificateAlreadyExists => write!(f, "Certificate already exists"),
            ControlError::InvalidCertificate => write!(f, "Invalid certificate"),
            ControlError::HttpChallengeNotFound => write!(f, "HTTP challenge not found"),
            ControlError::FailedToReload => write!(f, "Failed to reload configuration"),
            ControlError::FailedToSave => write!(f, "Failed to save configuration"),
            ControlError::MalformedCommand => write!(f, "Malformed command"),
            ControlError::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}
impl std::error::Error for ControlError {}
