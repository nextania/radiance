
use std::{collections::HashMap, sync::Arc};

use partially::Partial;
use pingora_load_balancing::{LoadBalancer, prelude::RoundRobin};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TlsCertConfig {
    pub id: String,
    pub cert_file: String,
    pub key_file: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpstreamConfig {
    pub tls: bool,
    pub servers: Vec<String>,
    pub path: String
}

#[derive(Clone, Debug, Deserialize, Serialize, Partial)]
#[partially(derive(Default, Debug, Serialize, Deserialize))]
pub struct HostConfig  {
    pub domains: Vec<String>,
    pub enabled: bool,
    pub tls_cert_id: Option<String>,
    pub upstream: UpstreamConfig,
    pub header_rewrites: Option<HashMap<String, String>>,
    pub upgrade_https: Option<bool>,
    pub forward_auth: Option<ForwardAuthConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ForwardAuthConfig {
    pub url: String,
    pub response_headers: Vec<String>,
}

#[derive(Clone, Debug,Deserialize, Serialize)]
pub struct Config {
    pub listen_port: u16,
    pub listen_port_tls: Option<u16>,
    pub hosts: HashMap<String, HostConfig>,
    pub certificates: Vec<TlsCertConfig>,
}

pub struct FullConfig {
    pub listen_port: u16,
    pub listen_port_tls: Option<u16>,
    pub hosts: HashMap<String, Arc<HostConfigWithBalancer>>,
    pub certificates: Vec<TlsCertConfig>,
}

pub struct HostConfigWithBalancer {
    pub config: HostConfig,
    pub load_balancer: LoadBalancer<RoundRobin>,
}

impl From<HostConfig> for HostConfigWithBalancer {
    fn from(cfg: HostConfig) -> Self {
        let load_balancer = LoadBalancer::<RoundRobin>::try_from_iter(
            cfg.upstream.servers.clone(),
        ).expect("Fail to create load balancer");
        
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
            hosts: cfg.hosts.iter().map(|(k, v)| (k.clone(), Arc::new(HostConfigWithBalancer::from(v.clone())))).collect(),
            certificates: cfg.certificates,
        }
    }
}

impl From<&FullConfig> for Config {
    fn from(cfg: &FullConfig) -> Self {
        Config {
            listen_port: cfg.listen_port,
            listen_port_tls: cfg.listen_port_tls,
            hosts: cfg.hosts.iter().map(|(k, v)| (k.clone(), v.config.clone())).collect(),
            certificates: cfg.certificates.clone(),
        }
    }
}

impl FullConfig {
    pub async fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let contents = tokio::fs::read_to_string(path).await?;
        let full_config: FullConfig = toml::from_str::<Config>(&contents)?.into();

        Ok(full_config)
    }

    pub async fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let toml_string = toml::to_string_pretty(&Config::from(self))?;
        tokio::fs::write(path, toml_string).await?;
        Ok(())
    }
    
    pub fn listen_address(&self) -> String {
        format!("0.0.0.0:{}", self.listen_port)
    }
}
