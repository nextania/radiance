use std::{
    collections::{BTreeSet, HashMap},
    net::ToSocketAddrs,
    sync::Arc,
};

use async_trait::async_trait;
use futures_util::FutureExt;
use http::Extensions;
use pingora::{
    protocols::l4::{
        socket::SocketAddr,
    },
};
use pingora_load_balancing::{
    Backend, Backends, LoadBalancer, discovery::Static, prelude::RoundRobin,
};
use radiance_types::{HostConfig, ServerConfig, TlsCertConfig};
use rustls::{crypto::{ring::sign::any_supported_type}, sign::CertifiedKey};
use serde::{Deserialize, Serialize};

use crate::virtual_connector::VirtualConnector;

#[async_trait]
pub trait TlsCertConfigExt {
    async fn read_cert(&self) -> anyhow::Result<rustls::sign::CertifiedKey>;
}

#[async_trait]
impl TlsCertConfigExt for TlsCertConfig {
    async fn read_cert(&self) -> anyhow::Result<rustls::sign::CertifiedKey> {
        match self {
            TlsCertConfig::Local {
                cert_file,
                key_file,
                ..
            } => read_local_cert(cert_file, key_file),
            TlsCertConfig::Vault { .. } => {
                Err(anyhow::anyhow!("Vault certificate loading not implemented"))
            }
            TlsCertConfig::Managed { .. } => {
                Err(anyhow::anyhow!("Managed certificate loading not implemented"))
            }
        }
    }
}

fn read_local_cert(
    cert_file_path: &str,
    key_file_path: &str,
) -> anyhow::Result<rustls::sign::CertifiedKey> {
    let cert_file = std::fs::File::open(cert_file_path)?;
    let mut reader = std::io::BufReader::new(cert_file);
    let certs: Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs?;
    let key_file = std::fs::File::open(key_file_path)?;
    let mut reader = std::io::BufReader::new(key_file);
    let keys = rustls_pemfile::private_key(&mut reader)?;
    let key = keys.ok_or(anyhow::anyhow!(
        "No private keys found in {}",
        key_file_path
    ))?;
    let certified_key = rustls::sign::CertifiedKey::new(certs, any_supported_type(&key)?);
    Ok(certified_key)
}

pub struct TlsCertConfigWithKey {
    pub config: TlsCertConfig,
    pub cert: TlsCertConfigState,
}

pub enum TlsCertConfigState {
    Loading,
    Loaded(CertifiedKey),
    Failed,
}


#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub listen_port: u16,
    pub listen_port_tls: Option<u16>,
    pub outpost_listen_port: Option<u16>,
    pub hosts: HashMap<String, HostConfig>,
    pub certificates: Vec<TlsCertConfig>,
    pub outposts: Option<HashMap<String, OutpostConfig>>,
    pub transports: Option<HashMap<String, TransportConfig>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransportConfig {
    pub r#type: TransportType,
    pub listen_address: String,
    pub upstreams: Vec<ServerConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportType {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutpostConfig {
    pub shared_secret: String,
}

pub struct FullConfig {
    pub listen_port: u16,
    pub listen_port_tls: Option<u16>,
    pub outpost_listen_port: Option<u16>,
    pub hosts: HashMap<String, Arc<HostConfigWithBalancer>>,
    pub certificates: Vec<Arc<TlsCertConfigWithKey>>,
    pub outposts: Option<HashMap<String, OutpostConfig>>,
    pub transports: Option<HashMap<String, TransportConfig>>,
    pub active_challenges: HashMap<String, (String, String)>, // domain -> (token, thumbprint)
}

pub struct HostConfigWithBalancer {
    pub config: HostConfig,
    pub load_balancer: LoadBalancer<RoundRobin>,
}

fn into_backends(servers: &Vec<ServerConfig>) -> anyhow::Result<Backends> {
    let mut upstreams = BTreeSet::new();
    for server in servers.into_iter() {
        match server {
            ServerConfig::Local { address } => {
                let addrs = address.to_socket_addrs()?.map(|addr| Backend {
                    addr: SocketAddr::Inet(addr),
                    weight: 1,
                    ext: Extensions::new(),
                });
                upstreams.extend(addrs);
            }
            ServerConfig::Outpost { address, id } => {
                upstreams.insert(Backend {
                    addr: SocketAddr::Custom(
                        address.clone(),
                        Arc::new(VirtualConnector::new(id, address)),
                    ),
                    weight: 1,
                    ext: Extensions::new(),
                });
            }
        }
    }
    Ok(Backends::new(Static::new(upstreams)))
}

impl From<HostConfig> for HostConfigWithBalancer {
    fn from(cfg: HostConfig) -> Self {
        let load_balancer = LoadBalancer::<RoundRobin>::from_backends(
            into_backends(&cfg.upstream.servers).expect("Fail to create load balancer"),
        );
        load_balancer
            .update()
            .now_or_never()
            .expect("static should not block")
            .expect("static should not error");
        HostConfigWithBalancer {
            config: cfg,
            load_balancer,
        }
    }
}

impl From<Config> for FullConfig {
    fn from(cfg: Config) -> Self {
        FullConfig {
            listen_port: cfg.listen_port,
            listen_port_tls: cfg.listen_port_tls,
            outpost_listen_port: cfg.outpost_listen_port,
            hosts: cfg
                .hosts
                .iter()
                .map(|(k, v)| (k.clone(), Arc::new(HostConfigWithBalancer::from(v.clone()))))
                .collect(),
            certificates: cfg
                .certificates
                .iter()
                .map(|c| {
                    Arc::new(TlsCertConfigWithKey {
                        config: c.clone(),
                        cert: TlsCertConfigState::Loading,
                    })
                })
                .collect(),
            outposts: cfg.outposts,
            transports: cfg.transports,
            active_challenges: HashMap::new(),
        }
    }
}

impl From<&FullConfig> for Config {
    fn from(cfg: &FullConfig) -> Self {
        Config {
            listen_port: cfg.listen_port,
            listen_port_tls: cfg.listen_port_tls,
            outpost_listen_port: cfg.outpost_listen_port,
            hosts: cfg
                .hosts
                .iter()
                .map(|(k, v)| (k.clone(), v.config.clone()))
                .collect(),
            certificates: cfg
                .certificates
                .clone()
                .iter()
                .map(|c| c.config.clone())
                .collect(),
            outposts: cfg.outposts.clone(),
            transports: cfg.transports.clone(),
        }
    }
}

impl FullConfig {
    pub async fn load_from_file(path: &str) -> anyhow::Result<(Config, Self)> {
        let contents = tokio::fs::read_to_string(path).await?;
        let config: Config = toml::from_str(&contents)?;
        let full_config: FullConfig = config.clone().into();

        Ok((config, full_config))
    }

    pub fn spawn_certificate_loading(
        config_to_load: Config,
        config_ref: Arc<tokio::sync::RwLock<Self>>,
    ) {
        for cert_config in config_to_load.certificates {
            let config_clone = config_ref.clone();
            let cert_id = cert_config.id().to_string();
            
            tokio::spawn(async move {
                tracing::info!("Loading certificate: {}", cert_id);
                match cert_config.read_cert().await {
                    Ok(cert) => {
                        let mut cfg = config_clone.write().await;
                        if let Some(cert_with_key) = cfg
                            .certificates
                            .iter_mut()
                            .find(|c| c.config.id() == cert_id && matches!(c.cert, TlsCertConfigState::Loading))
                        {
                            *cert_with_key = Arc::new(TlsCertConfigWithKey {
                                config: cert_with_key.config.clone(),
                                cert: TlsCertConfigState::Loaded(cert),
                            });
                            tracing::info!("Successfully loaded certificate: {}", cert_id);
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to load certificate {}: {}", cert_id, e);
                    }
                }
            });
        }
    }

    pub async fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let toml_string = toml::to_string_pretty(&Config::from(self))?;
        tokio::fs::write(path, toml_string).await?;
        Ok(())
    }

    pub fn listen_address(&self) -> String {
        format!("0.0.0.0:{}", self.listen_port)
    }

    pub fn listen_address_tls(&self) -> Option<String> {
        self.listen_port_tls.map(|port| format!("0.0.0.0:{}", port))
    }

    pub fn outpost_listen_address(&self) -> Option<String> {
        // TODO: QUIC doesn't like 0.0.0.0
        self.outpost_listen_port
            .map(|port| format!("127.0.0.1:{}", port))
    }
}
