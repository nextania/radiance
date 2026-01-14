use serde::{Deserialize, Serialize};

use crate::CertificateConfig;

#[derive(Debug, Serialize, Deserialize)]
pub enum ControlCommand {
    GetCertificate { id: String },
    SubscribeCertificate { id: String },
    AddCertificate { certificate: CertificateConfig },
    RemoveCertificate { id: String },
    ListCertificates,
    GetRenewStatus { id: String },
    ForceRenew { id: String },
}