use std::{
    collections::{BTreeSet, HashMap},
    net::ToSocketAddrs,
    sync::{Arc, atomic::{AtomicBool, Ordering}}, time::Duration,
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
use rustls::{crypto::ring::sign::any_supported_type, pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject}, sign::CertifiedKey};
use serde::{Deserialize, Serialize};
use tokio::{fs::File, io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, net::{UnixStream, unix::OwnedReadHalf}, time};
use zenith_types::{Certificate, ControlCommand, ControlResponse};

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
            } => read_local_cert(cert_file, key_file).await,
            TlsCertConfig::Vault { .. } => {
                Err(anyhow::anyhow!("Vault certificate loading not implemented"))
            }
            TlsCertConfig::Managed { .. } => {
                Err(anyhow::anyhow!("Managed certificate loading not implemented"))
            }
        }
    }
}

async fn read_local_cert(
    cert_file_path: &str,
    key_file_path: &str,
) -> anyhow::Result<CertifiedKey> {
    let mut cert_file = File::open(cert_file_path).await?;
    let mut cert = Vec::new();
    cert_file.read_to_end(&mut cert).await?;
    let mut key_file = File::open(key_file_path).await?;
    let mut key = Vec::new();
    key_file.read_to_end(&mut key).await?;
    process_cert(&cert, &key).await
}

async fn process_cert(mut cert: &[u8], mut key: &[u8]) -> anyhow::Result<CertifiedKey> {
    let certs: Vec<CertificateDer> = CertificateDer::pem_reader_iter(&mut cert).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_reader(&mut key)?;
    let certified_key = CertifiedKey::new(certs, any_supported_type(&key)?);
    Ok(certified_key)
}

pub struct TlsCertConfigWithKey {
    pub config: TlsCertConfig,
    pub cert: TlsCertConfigState,
    pub discarded: Arc<AtomicBool>
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
    pub certificates: HashMap<String, TlsCertConfig>,
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
    pub certificates: HashMap<String, Arc<TlsCertConfigWithKey>>,
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

pub struct CertificateClient {
    pub buf_reader: BufReader<OwnedReadHalf>,
}
impl CertificateClient {
    pub async fn new(path: &str, id: &str) -> anyhow::Result<Self> {        
        let stream = UnixStream::connect(path).await?;
        let (reader, mut writer) = stream.into_split();
        let command = ControlCommand::SubscribeCertificate {
            id: id.to_string(),
        };
        let command_json = serde_json::to_string(&command)?;
        writer.write_all(command_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        let buf_reader = BufReader::new(reader);
        Ok(Self { buf_reader })
    }

    pub async fn read(&mut self) -> anyhow::Result<Certificate> {
        let mut response_line = String::new();
        self.buf_reader.read_line(&mut response_line).await?;
        let response: ControlResponse = serde_json::from_str(&response_line)?;
        let ControlResponse::Success { data } = &response else {
            return Err(anyhow::anyhow!("Failed to get certificate: {:?}", response));
        };
        let certificate: Certificate = serde_json::from_value(data.clone())?;
        Ok(certificate)
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
            certificates: HashMap::new(),
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
                .map(|(k,v)| (k.clone(), v.config.clone()))
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
        for (cert_id, cert_config) in config_to_load.certificates {
            let config_clone = config_ref.clone();
            let cert_config = cert_config.clone();
            
            tokio::spawn(async move {
                tracing::info!("Loading certificate: {}", cert_id);
                match time::timeout(Duration::from_secs(10), cert_config.read_cert()).await {
                    Ok(Ok(cert)) => {
                        let mut cfg = config_clone.write().await;
                        let arc = Arc::new(TlsCertConfigWithKey {
                            config: cert_config.clone(),
                            cert: TlsCertConfigState::Loaded(cert),
                            discarded: AtomicBool::new(false).into(),
                        });
                        if let Some(cert_with_key) = cfg
                            .certificates
                            .insert(cert_id.clone(),arc.clone())
                        {
                            tracing::info!("Replaced existing certificate: {}", cert_id);
                            cert_with_key.discarded.store(true, Ordering::SeqCst);
                        }
                        drop(cfg);
                        tracing::info!("Successfully loaded certificate: {}", cert_id);
                        if let TlsCertConfig::Managed { control_socket } = cert_config {
                            tokio::spawn(async move {
                                // listen renewals here
                                let mut cert = Arc::clone(&arc);
                                loop {
                                    // await on unix socket
                                    let mut certificate = CertificateClient::new(&control_socket, &cert_id).await?;
                                    let mut interval = time::interval(Duration::from_secs(60));
                                    tokio::select! { 
                                        new_cert = certificate.read() => {
                                            if !cert.discarded.load(Ordering::SeqCst) &&
                                            let Ok(new_cert) = new_cert {
                                                let mut cfg = config_clone.write().await;
                                                if let Some(cert_with_key) = cfg
                                                    .certificates
                                                    .get_mut(&cert_id)
                                                {
                                                    cert = Arc::new(TlsCertConfigWithKey {
                                                        config: cert_with_key.config.clone(),
                                                        cert: TlsCertConfigState::Loaded(process_cert(
                                                            &new_cert.cert,
                                                            &new_cert.key,
                                                        ).await?),
                                                        discarded: cert_with_key.discarded.clone(),
                                                    });
                                                    *cert_with_key = cert.clone();
                                                    tracing::info!("Renewed managed certificate: {}", cert_id);
                                                }
                                            } else {
                                                tracing::info!("Certificate {} has been dropped, stopping renewal task", cert_id);
                                                break;
                                            }
                                        }
                                        _ = interval.tick() => {
                                            if cert.discarded.load(Ordering::SeqCst) {
                                                tracing::info!("Certificate {} has been dropped, stopping renewal task", cert_id);
                                                break;
                                            }
                                        }
                                    }
                                    
                                }
                                Ok::<(), anyhow::Error>(())
                            });
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::error!("Failed to load certificate {}: {}", cert_id, e);
                    }
                    Err(_) => {
                        // TODO: retry later, for now, insert a failed state
                        let mut cfg = config_clone.write().await;
                        let arc = Arc::new(TlsCertConfigWithKey {
                            config: cert_config.clone(),
                            cert: TlsCertConfigState::Failed,
                            discarded: AtomicBool::new(false).into(),
                        });
                        if let Some(cert_with_key) = cfg
                            .certificates
                            .insert(cert_id.clone(), arc.clone())
                        {
                            tracing::info!("Replaced existing certificate: {}", cert_id);
                            cert_with_key.discarded.store(true, Ordering::SeqCst);
                        }
                        drop(cfg);
                        tracing::error!("Timeout while loading certificate {}", cert_id);
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
