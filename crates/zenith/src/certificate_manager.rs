use crate::acme::{AcmeService, RenewalStatus};
use crate::acme_provider::AcmeProviderType;
use crate::config::StoreLocation;
use crate::dns_provider::DnsProvider;
use crate::store::{LocalStore, Store, VaultStore};
use anyhow::Result;
use radiance_control::RadianceControlClient;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tracing::info;
use zenith_types::CertificateConfig;

pub struct CertificateManager {
    config: CertificateConfig,
    acme_service: AcmeService,
    store: Arc<dyn Store>,
    renewal_in_progress: AtomicBool,
    discarded: AtomicBool,
}

impl CertificateManager {
    pub async fn new(
        id: String,
        config: CertificateConfig,
        dns_provider: Option<Arc<dyn DnsProvider>>,
        store_location: StoreLocation,
    ) -> Result<Self> {
        let acme_provider = AcmeProviderType::from_string(&config.acme_provider)?;
        let socket = config
            .control_socket
            .clone()
            .map(|s| RadianceControlClient::new(s));
        let acme_service = AcmeService::new(
            config.account_email.clone(),
            acme_provider,
            dns_provider,
            socket.clone(),
        );
        let store: Arc<dyn Store> = match store_location {
            StoreLocation::Local { ref path } => {
                let store = LocalStore::new(PathBuf::from(path.clone()), &id.clone()).await?;
                Arc::new(store)
            }
            StoreLocation::Vault => {
                let store = VaultStore::new(id.clone()).await?;
                Arc::new(store)
            }
        };

        info!("Certificate '{}': Initialized", config.name,);

        Ok(Self {
            config,
            acme_service,
            store,
            renewal_in_progress: AtomicBool::new(false),
            discarded: AtomicBool::new(false),
        })
    }
    pub async fn check_and_renew(&self) -> Result<bool> {
        if self
            .acme_service
            .needs_renewal(self.store.clone())
            .await?
            .needs_renewal
        {
            info!("Certificate '{}': Renewal needed", self.config.name);
            self.renewal_in_progress
                .store(true, std::sync::atomic::Ordering::SeqCst);
            let result = self
                .acme_service
                .request_certificate(self.config.domains.clone(), self.store.clone())
                .await?;
            info!("Certificate '{}': Obtained successfully", self.config.name);
            self.store
                .store_certificate(&result.private_key, &result.certificate, &result.chain)
                .await?;
            info!("Certificate '{}': Stored successfully", self.config.name);
            self.renewal_in_progress
                .store(false, std::sync::atomic::Ordering::SeqCst);
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

    pub fn config(&self) -> &CertificateConfig {
        &self.config
    }

    pub async fn check_renewal_status(&self) -> Result<RenewalStatus> {
        self.acme_service.needs_renewal(self.store.clone()).await
    }

    pub fn is_renewal_in_progress(&self) -> bool {
        self.renewal_in_progress
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn is_discarded(&self) -> bool {
        self.discarded.load(std::sync::atomic::Ordering::SeqCst)
    }
    pub fn mark_discarded(&self) {
        self.discarded
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub async fn read_current(&self) -> Result<Option<zenith_types::Certificate>> {
        let cert_key = self.store.get_cert_key().await?;
        let cert = self.store.get_cert().await?;
        let chain = self.store.get_chain().await?;
        if let Some(cert_key_data) = cert_key
            && let Some(cert_data) = cert
            && let Some(chain_data) = chain
        {
            let certificate = zenith_types::Certificate {
                key: cert_key_data,
                cert: cert_data,
                chain: chain_data,
            };
            Ok(Some(certificate))
        } else {
            Ok(None)
        }
    }
}
