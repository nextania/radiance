mod config;
mod proxy;
mod control_socket;
pub mod environment;
pub mod vault;

use log::info;
use pingora::prelude::*;
use std::{env, sync::Arc, thread};
use tokio::sync::RwLock;
use proxy::RadianceProxy;
use control_socket::ControlSocket;

use crate::config::FullConfig;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    env_logger::init();
    rustls::crypto::ring::default_provider().install_default().ok();
    info!("Starting Radiance reverse proxy");

    let config_path = env::var("CONFIG_FILE").unwrap_or_else(|_| "radiance.toml".to_string());
    if !std::path::Path::new(&config_path).exists() {
        panic!("Configuration file not found at path: {}", config_path);
    }
    let config = FullConfig::load_from_file(&config_path)
        .await
        .expect("Failed to load configuration");
    info!("Configuration loaded");

    let listen_address = config.listen_address();
    let shared_config = Arc::new(RwLock::new(config));

    let control_socket_path = std::env::var("CONTROL_SOCKET_PATH")
        .unwrap_or_else(|_| "/tmp/radiance.sock".to_string());
    let control_socket = ControlSocket::new(control_socket_path, shared_config.clone());
    tokio::spawn(async move {
        if let Err(e) = control_socket.start().await {
            log::error!("Control socket error: {}", e);
        }
    });

    let mut proxy = Server::new(Some(Opt::default())).unwrap();
    proxy.bootstrap();
    let mut proxy_service_http = pingora_proxy::http_proxy_service(
        &proxy.configuration,
        RadianceProxy::new(shared_config.clone()),
    );
    proxy_service_http.add_tcp(&listen_address);
    proxy.add_service(proxy_service_http);
    
    info!("Radiance proxy server starting...");
    thread::spawn(|| proxy.run_forever());
    
    tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl-c");
    info!("Shutting down Radiance proxy server");
}
