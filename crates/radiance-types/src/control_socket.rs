
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
        message: String,
        data: Option<serde_json::Value>,
    },
    Error {
        message: String,
    },
}