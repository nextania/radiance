mod acme;
mod acme_provider;
mod certificate_manager;
mod cloudflare;
mod config;
mod dns_provider;
pub mod control_socket;
pub mod environment;
pub mod store;

use anyhow::{Result, anyhow};
use certificate_manager::CertificateManager;
use cloudflare::CloudflareClient;
use config::Config;
use control_socket::{ControlSocketServer};
use dns_provider::DnsProvider;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock};
use tracing::{error, info};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    info!("Starting Zenith ACME certificate service");
    let config = Config::load()?;
    info!(
        "Configuration loaded with {} certificate(s)",
        config.certificates.len()
    );

    let mut dns_providers: HashMap<String, Arc<dyn DnsProvider>> = HashMap::new();

    if let Some(cloudflare_config) = &config.dns_providers.cloudflare {
        let cloudflare = CloudflareClient::new(cloudflare_config.api_key.clone());
        dns_providers.insert("cloudflare".to_string(), Arc::new(cloudflare));
        info!("Cloudflare DNS provider initialized");
    }

    let certificates = config
        .certificates
        .iter()
        .map(|(id, c)| async {
            let dns_provider = dns_providers
                .get(&c.dns_provider)
                .cloned();
            if dns_provider.is_none() && c.control_socket.is_none() {
                return Err(anyhow!(
                    "Certificate '{}' requires a challenge provider, but none was found",
                    c.name
                ));
            }
            CertificateManager::new(id.clone(), c.clone(), dns_provider, config.store_location.clone())
                .await
                .map(|manager| (id.clone(), Arc::new(manager)))
        })
        .collect::<Vec<_>>();
    let certificates = futures::future::join_all(certificates).await.into_iter().collect::<Result<HashMap<_, _>>>()?;

    if certificates.is_empty() {
        return Err(anyhow!("No certificate managers were successfully created"));
    }

    let certificates = Arc::new(RwLock::new(certificates));
    let dns_providers = Arc::new(dns_providers);

    let control_server = if let Some(socket_path) = config.control_socket_path.clone() {
        let server = Arc::new(ControlSocketServer::new(
            socket_path.clone(),
            Arc::clone(&certificates),
            dns_providers,
            config.store_location.clone(),
        ));
        
        let server_clone = Arc::clone(&server);
        tokio::spawn(async move {
            if let Err(e) = server_clone.start().await {
                error!("Control socket server error: {}", e);
            }
        });
        
        info!("Control socket server started on: {}", socket_path);
        Some(server)
    } else {
        None
    };

    let certs_read = certificates.read().await;
    for (id, certificate) in certs_read.iter() {
        let certificate = Arc::clone(certificate);
        let cert_id = id.clone();
        let server = control_server.clone();
        
        tokio::spawn(async move {
            let mut failures = 0;
            loop {
                if certificate.is_discarded() {
                    info!("Certificate '{}': Discarded, stopping renewal checks", certificate.name());
                    break;
                }
                match certificate.check_and_renew().await {
                    Ok(renewed) => {
                        if renewed {
                            info!("Certificate '{}': Successfully renewed", certificate.name());
                            
                            if let Some(ref server) = server {
                                let cert_data = serde_json::to_string(&certificate.read_current().await?.expect("No certificate data"))?;
                                server.notify_certificate_update(&cert_id, cert_data).await;
                            }
                        } else {
                            info!("Certificate '{}': No renewal needed", certificate.name());
                        }
                        failures = 0;
                    }
                    Err(e) => {
                        error!(
                            "Certificate '{}': Error during renewal check: {}",
                            certificate.name(),
                            e
                        );
                        failures += 1;
                        if failures >= 5 {
                            error!(
                                "Certificate '{}': Too many consecutive failures, stopping checks",
                                certificate.name()
                            );
                            break;
                        }
                        info!(
                            "Certificate '{}': Retrying in 5 minutes (failure count: {})",
                            certificate.name(),
                            failures
                        );
                        tokio::time::sleep(std::time::Duration::from_mins(5)).await;
                        continue;
                    }
                }
                info!("Certificate '{}': Sleeping for 24 hours before next check", certificate.name());
                tokio::time::sleep(std::time::Duration::from_hours(24)).await;
            }
            Ok::<(), anyhow::Error>(())
        });
    }
    drop(certs_read);

    tokio::signal::ctrl_c().await?;
    info!("Shutting down Zenith ACME certificate service");
    Ok(())
}
