use partially::Partial;
use radiance_types::{ControlCommand, ControlError, ControlResponse, Empty};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;
use tracing::{error, info};

use crate::config::{Config, FullConfig, TlsCertConfigExt, TlsCertConfigState};
use crate::environment::CONFIG_FILE;
use radiance_types::{HostConfig, PartialHostConfig};

pub type SharedConfig = Arc<RwLock<FullConfig>>;

pub struct ControlSocket {
    socket_path: String,
    config: SharedConfig,
}

impl ControlSocket {
    pub fn new(socket_path: String, config: SharedConfig) -> Self {
        Self {
            socket_path,
            config,
        }
    }

    pub async fn start(self) -> Result<(), Box<dyn std::error::Error>> {
        let socket_path = Path::new(&self.socket_path);
        if socket_path.exists() {
            std::fs::remove_file(socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("Control socket listening on: {}", self.socket_path);

        std::fs::set_permissions(&self.socket_path, std::fs::Permissions::from_mode(0o660))?;

        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let config = self.config.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, config).await {
                            error!("Error handling connection: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting connection: {}", e);
                }
            }
        }
    }
}

async fn handle_connection(stream: UnixStream, config: SharedConfig) -> anyhow::Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let response = match serde_json::from_str::<ControlCommand>(trimmed) {
            Ok(command) => process_command(command, config.clone()).await,
            Err(_) => ControlResponse::Error {
                error: ControlError::MalformedCommand,
            },
        };

        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;

        line.clear();
    }

    Ok(())
}

async fn process_command(command: ControlCommand, config: SharedConfig) -> ControlResponse {
    match command {
        ControlCommand::AddHost { id, host } => add_host(config, id, host).await,
        ControlCommand::UpdateHost { id, host } => update_host(config, id, host).await,
        ControlCommand::RemoveHost { id } => remove_host(config, id).await,
        ControlCommand::ListHosts => list_hosts(config).await,
        ControlCommand::GetHost { id } => get_host(config, id).await,
        ControlCommand::Reload => reload_config(config).await,
        ControlCommand::ClearHttpChallenge { domain, token } => {
            clear_http_challenge(config, domain, token).await
        }
        ControlCommand::SetHttpChallenge {
            domain,
            token,
            thumbprint,
        } => set_http_challenge(config, domain, token, thumbprint).await,
        ControlCommand::AddCertificate { id, certificate } => {
            add_certificate(config, &id, certificate).await
        }
        ControlCommand::RemoveCertificate { id } => remove_certificate(config, id).await,
        ControlCommand::ListCertificates => list_certificates(config).await,
        ControlCommand::GetCertificate { id } => get_certificate(config, id).await,
    }
}

fn empty() -> serde_json::Value {
    serde_json::to_value(Empty {}).unwrap()
}

async fn set_http_challenge(
    config: SharedConfig,
    domain: String,
    token: String,
    thumbprint: String,
) -> ControlResponse {
    let mut cfg = config.write().await;
    cfg.active_challenges
        .insert(domain.clone(), (token.clone(), thumbprint.clone()));
    info!("Set HTTP challenge for domain: {}", domain);
    ControlResponse::Success { data: empty() }
}

async fn clear_http_challenge(
    config: SharedConfig,
    domain: String,
    token: String,
) -> ControlResponse {
    let mut cfg = config.write().await;
    match cfg.active_challenges.get(&domain) {
        Some((stored_token, _)) if *stored_token == token => {
            cfg.active_challenges.remove(&domain);
            info!("Cleared HTTP challenge for domain: {}", domain);
            ControlResponse::Success { data: empty() }
        }
        _ => ControlResponse::Error {
            error: ControlError::HttpChallengeNotFound,
        },
    }
}

async fn add_host(config: SharedConfig, id: String, new_host: HostConfig) -> ControlResponse {
    let mut cfg = config.write().await;
    for domain in &new_host.domains {
        if cfg
            .hosts
            .iter()
            .any(|(_, h)| h.config.domains.contains(domain))
        {
            return ControlResponse::Error {
                error: ControlError::HostAlreadyExists,
            };
        }
    }
    cfg.hosts.insert(id, Arc::new(new_host.clone().into()));
    if cfg.save_to_file(&CONFIG_FILE).await.is_err() {
        return ControlResponse::Error {
            error: ControlError::FailedToSave,
        };
    }
    info!("Added new host with domains: {:?}", new_host.domains);
    ControlResponse::Success { data: empty() }
}

async fn update_host(
    config: SharedConfig,
    id: String,
    updated_host: PartialHostConfig,
) -> ControlResponse {
    let mut cfg = config.write().await;
    let host = cfg.hosts.get_mut(&id);
    match host {
        Some(index) => {
            let mut config = index.config.clone();
            config.apply_some(updated_host);
            *index = Arc::new(config.into());
            if cfg.save_to_file(&CONFIG_FILE).await.is_err() {
                return ControlResponse::Error {
                    error: ControlError::FailedToSave,
                };
            }

            info!("Updated host for ID: {}", id);
            ControlResponse::Success { data: empty() }
        }
        None => ControlResponse::Error {
            error: ControlError::HostNotFound,
        },
    }
}

async fn remove_host(config: SharedConfig, id: String) -> ControlResponse {
    let mut cfg = config.write().await;
    let removed_host = cfg.hosts.remove(&id);
    match removed_host {
        Some(removed_host) => {
            if cfg.save_to_file(&CONFIG_FILE).await.is_err() {
                return ControlResponse::Error {
                    error: ControlError::FailedToSave,
                };
            }

            info!(
                "Removed host with domains: {:?}",
                removed_host.config.domains
            );
            ControlResponse::Success { data: empty() }
        }
        None => ControlResponse::Error {
            error: ControlError::HostNotFound,
        },
    }
}

async fn list_hosts(config: SharedConfig) -> ControlResponse {
    let cfg = config.read().await;
    let cfg: Config = (&*cfg).into();
    let hosts_json = serde_json::to_value(&cfg.hosts).unwrap_or(serde_json::Value::Null);
    ControlResponse::Success { data: hosts_json }
}

async fn get_host(config: SharedConfig, id: String) -> ControlResponse {
    let cfg = config.read().await;
    match cfg.hosts.get(&id) {
        Some(host) => {
            let host_json = serde_json::to_value(&host.config).unwrap_or(serde_json::Value::Null);
            ControlResponse::Success { data: host_json }
        }
        None => ControlResponse::Error {
            error: ControlError::HostNotFound,
        },
    }
}

async fn reload_config(config: SharedConfig) -> ControlResponse {
    match crate::config::FullConfig::load_from_file(&CONFIG_FILE).await {
        Ok((raw, new_config)) => {
            let mut cfg = config.write().await;
            // replace everything but certificates
            let current_certs = std::mem::take(&mut cfg.certificates);
            *cfg = new_config;
            cfg.certificates = current_certs;
            // find all certs that exist in the old config but not in the new one and mark them as discarded
            let removed = cfg
                .certificates
                .extract_if(|k, _| !raw.certificates.contains_key(k))
                .collect::<Vec<_>>();
            for (_, removed_cert) in removed {
                removed_cert.discarded.store(true, Ordering::SeqCst);
            }
            // spawn loading for new certs
            FullConfig::spawn_certificate_loading(raw, config.clone());
            info!("Configuration reloaded from file");
            ControlResponse::Success { data: empty() }
        }
        Err(_) => ControlResponse::Error {
            error: ControlError::FailedToReload,
        },
    }
}

async fn add_certificate(
    config: SharedConfig,
    id: &str,
    certificate: radiance_types::config::TlsCertConfig,
) -> ControlResponse {
    let mut cfg = config.write().await;
    if cfg.certificates.contains_key(id) {
        return ControlResponse::Error {
            error: ControlError::CertificateAlreadyExists,
        };
    }
    let cert_key = match certificate.read_cert().await {
        Ok(cert) => cert,
        Err(_) => {
            return ControlResponse::Error {
                error: ControlError::InvalidCertificate,
            };
        }
    };
    cfg.certificates.insert(
        id.to_string(),
        Arc::new(crate::config::TlsCertConfigWithKey {
            config: certificate.clone(),
            cert: TlsCertConfigState::Loaded(cert_key),
            discarded: Arc::new(AtomicBool::new(false)),
        }),
    );
    if cfg.save_to_file(&CONFIG_FILE).await.is_err() {
        return ControlResponse::Error {
            error: ControlError::FailedToSave,
        };
    }
    info!("Added new certificate with ID: {}", id);
    ControlResponse::Success { data: empty() }
}

async fn remove_certificate(config: SharedConfig, id: String) -> ControlResponse {
    let mut cfg = config.write().await;
    let removed = cfg
        .certificates
        .extract_if(|k, _| k != &id)
        .collect::<Vec<_>>();
    if removed.is_empty() {
        return ControlResponse::Error {
            error: ControlError::CertificateNotFound,
        };
    }
    for (_, removed_cert) in removed {
        removed_cert.discarded.store(true, Ordering::SeqCst);
    }
    if cfg.save_to_file(&CONFIG_FILE).await.is_err() {
        return ControlResponse::Error {
            error: ControlError::FailedToSave,
        };
    }
    info!("Removed certificate with ID: {}", id);
    ControlResponse::Success { data: empty() }
}

#[derive(serde::Serialize)]
pub struct TlsCertificateInfo {
    pub config: radiance_types::config::TlsCertConfig,
    pub days_remaining: Option<i64>,
}

async fn list_certificates(config: SharedConfig) -> ControlResponse {
    let cfg = config.read().await;
    let certificates = cfg.certificates.iter().map(|(id, cert)| {
        let days_remaining = match cert.cert {
            TlsCertConfigState::Loaded(ref c) => c.cert.get(0).map(|cert_der| get_expiration(&cert_der)),
            _ => None,
        }.flatten();
        (id.clone(), TlsCertificateInfo {
            config: cert.config.clone(),
            days_remaining,
        })
    }).collect::<std::collections::HashMap<_, _>>();
    let certs_json = serde_json::to_value(&certificates).unwrap_or(serde_json::Value::Null);
    ControlResponse::Success { data: certs_json }
}

fn get_expiration(cert: &[u8]) -> Option<i64> {
    let (_, parsed) = x509_parser::parse_x509_certificate(cert).ok()?;
    let timestamp = parsed.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    let remaining = (timestamp - now) / 86400;
    Some(remaining)
}

async fn get_certificate(config: SharedConfig, id: String) -> ControlResponse {
    let cfg = config.read().await;
    match cfg.certificates.get(&id) {
        Some(cert) => {
            let exp = match cert.cert {
                TlsCertConfigState::Loaded(ref c) => c.cert.get(0).map(|cert_der| get_expiration(&cert_der)),
                _ => None,
            }.flatten();
            let cert_json = json!({
                "config": &cert.config,
                "days_remaining": exp,
            });
            ControlResponse::Success { data: cert_json }
        }
        None => ControlResponse::Error {
            error: ControlError::CertificateNotFound,
        },
    }
}
