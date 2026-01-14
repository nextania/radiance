use crate::acme::AcmeService;
use crate::acme_provider::AcmeProviderType;
use crate::config::StoreLocation;
use crate::control_socket::ControlSocket;
use crate::dns_provider::DnsProvider;
use crate::store::{LocalStore, Store, VaultStore};
use anyhow::Result;
use zenith_types::CertificateConfig;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;

pub struct CertificateManager {
    id: String,
    config: CertificateConfig,
    acme_service: AcmeService,
    socket: Option<ControlSocket>,
    store_location: StoreLocation,
}

impl CertificateManager {
    pub fn new(id: String, config: CertificateConfig, dns_provider: Option<Arc<dyn DnsProvider>>, store_location: StoreLocation) -> Result<Self> {
        let acme_provider = AcmeProviderType::from_string(&config.acme_provider)?;
        let socket = config.control_socket.clone().map(|s| ControlSocket::new(s));
        let acme_service =
            AcmeService::new(config.account_email.clone(), acme_provider, dns_provider, socket.clone());

        Ok(Self {
            id,
            config,
            acme_service,
            socket,
            store_location,
        })
    }
    pub async fn initialize(&self) -> Result<Arc<dyn Store>> {
        let store: Arc<dyn Store> = match self.store_location {
            StoreLocation::Local { ref path } => {
                let store = LocalStore::new(PathBuf::from(path.clone()), &self.id.clone()).await?;
                Arc::new(store)
            }
            StoreLocation::Vault => {
                let store = VaultStore::new(self.id.clone()).await?;
                Arc::new(store)
            }
        };

        info!(
            "Certificate '{}': Store initialized",
            self.config.name,
        );

        Ok(store)
    }
    pub async fn check_and_renew(&self, store: Arc<dyn Store>) -> Result<bool> {
        if self.acme_service.needs_renewal(store.clone()).await? {
            info!("Certificate '{}': Renewal needed", self.config.name);

            let result = self
                .acme_service
                .request_certificate(
                    self.config.domains.clone(),
                    store.clone()
                )
                .await?;

            info!("Certificate '{}': Obtained successfully", self.config.name);

            store.store_certificate(&result.private_key, &result.certificate, &result.chain).await?;
            info!("Certificate '{}': Stored successfully", self.config.name);

            if let Some(hot_reload_socket) = &self.socket {
                hot_reload_socket
                    .send_reload_command()
                    .await?;
                info!(
                    "Certificate '{}': Sent reload command to socket: {:?}",
                    self.config.name, hot_reload_socket
                );
            }

            info!("Certificate '{}': Issuance complete", self.config.name);
            Ok(true)
        } else {
            info!(
                "Certificate '{}': Still valid, no renewal needed",
                self.config.name
            );
            Ok(false)
        }
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }
}
