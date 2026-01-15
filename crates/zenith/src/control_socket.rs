use zenith_types::{ControlCommand, ControlError, ControlResponse, CertificateConfig};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{broadcast},
};
use anyhow::Result;
use serde_json::json;
use std::{collections::HashMap, path::Path, sync::Arc};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

use crate::{certificate_manager::CertificateManager, config::StoreLocation, dns_provider::{DnsProvider}};

pub struct ControlSocketServer {
    socket_path: String,
    certificates: Arc<RwLock<HashMap<String, Arc<CertificateManager>>>>,
    dns_providers: Arc<HashMap<String, Arc<dyn DnsProvider>>>,
    store_location: StoreLocation,
    certificate_update_channels: Arc<RwLock<HashMap<String, broadcast::Sender<String>>>>,
}

impl ControlSocketServer {
    pub fn new(
        socket_path: String,
        certificates: Arc<RwLock<HashMap<String, Arc<CertificateManager>>>>,
        dns_providers: Arc<HashMap<String, Arc<dyn DnsProvider>>>,
        store_location: StoreLocation,
    ) -> Self {
        Self {
            socket_path,
            certificates,
            dns_providers,
            store_location,
            certificate_update_channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn start(self: Arc<Self>) -> Result<()> {
        if Path::new(&self.socket_path).exists() {
            std::fs::remove_file(&self.socket_path)?;
        }

        let listener = UnixListener::bind(&self.socket_path)?;
        info!("Control socket listening on: {}", self.socket_path);

        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream).await {
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

    async fn handle_connection(&self, stream: UnixStream) -> Result<()> {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();

        loop {
            line.clear();
            let bytes_read = reader.read_line(&mut line).await?;
            
            if bytes_read == 0 {
                break;
            }

            match serde_json::from_str::<ControlCommand>(&line) {
                Ok(ControlCommand::SubscribeCertificate { id }) => {
                    if let Err(e) = self.handle_subscription(id, reader.get_mut()).await {
                        error!("Error handling subscription: {}", e);
                    }
                    break;
                }
                Ok(command) => {
                    let response = self.handle_command(command).await;
                    let response_json = serde_json::to_string(&response)? + "\n";
                    reader.get_mut().write_all(response_json.as_bytes()).await?;
                }
                Err(e) => {
                    warn!("Malformed command: {}", e);
                    let response = ControlResponse::Error {
                        error: ControlError::MalformedCommand,
                    };
                    let response_json = serde_json::to_string(&response)? + "\n";
                    reader.get_mut().write_all(response_json.as_bytes()).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_command(&self, command: ControlCommand) -> ControlResponse {
        match command {
            ControlCommand::GetCertificate { id } => self.get_certificate(id).await,
            ControlCommand::SubscribeCertificate { .. } => {
                unreachable!() // handled separately in handle_connection
            }
            ControlCommand::AddCertificate { certificate, id } => {
                self.add_certificate(certificate, id).await
            }
            ControlCommand::RemoveCertificate { id } => self.remove_certificate(id).await,
            ControlCommand::ListCertificates => self.list_certificates().await,
            ControlCommand::GetRenewStatus { id } => self.get_renew_status(id).await,
            ControlCommand::ForceRenew { id } => self.force_renew(id).await,
        }
    }

    async fn get_certificate(&self, id: String) -> ControlResponse {
        let certificates = self.certificates.read().await;
        
        match certificates.get(&id) {
            Some(cert_manager) => {
                let config = cert_manager.config();
                ControlResponse::Success {
                    data: json!({
                        "id": id,
                        "certificate": config,
                    }),
                }
            }
            None => ControlResponse::Error {
                error: ControlError::CertificateNotFound,
            },
        }
    }

    async fn handle_subscription(&self, id: String, stream: &mut UnixStream) -> Result<()> {
        let certificates = self.certificates.read().await;
        
        if !certificates.contains_key(&id) {
            let response = ControlResponse::Error {
                error: ControlError::CertificateNotFound,
            };
            let response_json = serde_json::to_string(&response)? + "\n";
            stream.write_all(response_json.as_bytes()).await?;
            return Ok(());
        }
        
        drop(certificates);
        
        let mut channels = self.certificate_update_channels.write().await;
        let mut rx = if let Some(tx) = channels.get(&id) {
            tx.subscribe()
        } else {
            let (tx, rx) = broadcast::channel(100);
            channels.insert(id.clone(), tx);
            rx
        };
        drop(channels);
        
        info!("Client subscribed to certificate updates for id: {}", id);
        
        loop {
            match rx.recv().await {
                Ok(cert_data) => {
                    let update = ControlResponse::Success {
                        data: json!({
                            "certificate": cert_data,
                        }),
                    };
                    let update_json = serde_json::to_string(&update)? + "\n";
                    if let Err(e) = stream.write_all(update_json.as_bytes()).await {
                        info!("Client disconnected from subscription for id {}: {}", id, e);
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("Subscription lagged, skipped {} messages for id: {}", skipped, id);
                    continue;
                }
                Err(broadcast::error::RecvError::Closed) => {
                    info!("Certificate update channel closed for id: {}", id);
                    break;
                }
            }
        }
        
        Ok(())
    }

    pub async fn notify_certificate_update(&self, id: &str, cert_data: String) {
        let channels = self.certificate_update_channels.read().await;
        if let Some(tx) = channels.get(id) {
            if let Err(e) = tx.send(cert_data) {
                warn!("Failed to broadcast certificate update for id {}: {}", id, e);
            } else {
                info!("Broadcast certificate update for id: {}", id);
            }
        }
    }

    async fn add_certificate(&self, certificate: CertificateConfig, id: String) -> ControlResponse {
        let mut certificates = self.certificates.write().await;
        
        if certificates.contains_key(&id) {
            return ControlResponse::Error {
                error: ControlError::CertificateAlreadyExists,
            };
        }
        let dns_provider = self.dns_providers
            .get(&certificate.dns_provider)
            .cloned();
        if dns_provider.is_none() && certificate.control_socket.is_none() {
            return ControlResponse::Error {
                error: ControlError::NoDnsProviderConfigured,
            };
        }
        // TODO: persist to config file
        match CertificateManager::new(id.clone(), certificate, dns_provider, self.store_location.clone()).await {
            Ok(manager) => {
                certificates.insert(id.clone(), Arc::new(manager));
                ControlResponse::Success {
                    data: json!({}),
                }
            }
            Err(e) => {
                error!("Failed to add certificate '{}': {}", id, e);
                ControlResponse::Error {
                    error: ControlError::CertificateAdditionFailed,
                }
            }
        }
    }

    async fn remove_certificate(&self, id: String) -> ControlResponse {
        let mut certificates = self.certificates.write().await;
        
        if let Some(cert) = certificates.remove(&id) {
            // TODO: Also remove from config file
            cert.mark_discarded();
            ControlResponse::Success {
                data: json!({}),
            }
        } else {
            ControlResponse::Error {
                error: ControlError::CertificateNotFound,
            }
        }
    }

    async fn list_certificates(&self) -> ControlResponse {
        let certificates = self.certificates.read().await;
        
        let cert_list: Vec<_> = certificates
            .iter()
            .map(|(id, manager)| {
                json!({
                    "id": id,
                    "config": manager.config(),
                })
            })
            .collect();

        ControlResponse::Success {
            data: json!({
                "certificates": cert_list,
            }),
        }
    }

    async fn get_renew_status(&self, id: String) -> ControlResponse {
        let certificates = self.certificates.read().await;
        
        match certificates.get(&id) {
            Some(cert_manager) => {
                ControlResponse::Success {
                    data: json!({
                        "renewal_in_progress": cert_manager.is_renewal_in_progress(),
                    }),
                }
            }
            None => ControlResponse::Error {
                error: ControlError::CertificateNotFound,
            },
        }
    }

    async fn force_renew(&self, id: String) -> ControlResponse {
        let certificates = self.certificates.read().await;
        
        if !certificates.contains_key(&id) {
            return ControlResponse::Error {
                error: ControlError::CertificateNotFound,
            };
        }

        if let Some(certificate) = certificates.get(&id) {
            let certificate = Arc::clone(certificate);
            if certificate.is_renewal_in_progress() {
                return ControlResponse::Error {
                    error: ControlError::RenewalAlreadyInProgress,
                };
            }
            
            let cert_id = id.clone();
            let channels = Arc::clone(&self.certificate_update_channels);
            
            tokio::spawn(async move {
                match certificate.check_and_renew().await {
                    Ok(renewed) => {
                        info!("Certificate '{}': Force renewal completed", certificate.name());
                        
                        if renewed {
                            let cert_data = serde_json::to_string(&certificate.read_current().await?.expect("Certificate data should be present after renewal"))?;
                            
                            let channels_read = channels.read().await;
                            if let Some(tx) = channels_read.get(&cert_id) {
                                if let Err(e) = tx.send(cert_data) {
                                    warn!("Failed to broadcast certificate update for id {}: {}", cert_id, e);
                                } else {
                                    info!("Broadcast certificate update for id: {}", cert_id);
                                }
                            }
                        }
                    }
                    Err(e) => error!("Certificate '{}': Force renewal failed: {}", certificate.name(), e),
                }
                Ok::<(), anyhow::Error>(())
            });
        } else {
            return ControlResponse::Error {
                error: ControlError::CertificateNotFound,
            };
        }

        ControlResponse::Success {
            data: json!({}),
        }
    }
}
