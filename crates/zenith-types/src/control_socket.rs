use serde::{Deserialize, Serialize};

use crate::{Certificate, CertificateConfig};

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlCommand {
    GetCertificate {
        id: String,
    },
    SubscribeCertificate {
        id: String,
    },
    AddCertificate {
        certificate: CertificateConfig,
        id: String,
    },
    RemoveCertificate {
        id: String,
    },
    ListCertificates,
    GetRenewStatus {
        id: String,
    },
    ForceRenew {
        id: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "lowercase")]
pub enum ControlResponse {
    Success { data: serde_json::Value },
    Error { error: ControlError },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlError {
    CertificateNotFound,
    CertificateAlreadyExists,
    NoDnsProviderConfigured,
    CertificateAdditionFailed,
    CertificateReadError,
    RenewalAlreadyInProgress,
    FailedToSave,
    MalformedCommand,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DetailedCertificate {
    pub config: CertificateConfig,
    pub cert: Option<Certificate>,
    pub days_remaining: Option<i64>,
}
