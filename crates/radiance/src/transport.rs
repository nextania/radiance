use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use dashmap::DashMap;
use radiance_types::ServerConfig;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::RwLock,
    time::Instant,
};
use tracing::{debug, error, info, warn};

use crate::{
    config::{FullConfig, TransportConfig, TransportType},
    outpost::{ACTIVE_TCP_STREAMS, OutpostRequest, OutpostResponse},
};

struct UdpSession {
    upstream_socket: Arc<UdpSocket>,
    last_activity: Instant,
}

type UdpSessionMap = Arc<DashMap<(String, SocketAddr), UdpSession>>;

// TODO: be able to modify config at runtime
pub async fn start_transports(config: Arc<RwLock<FullConfig>>) -> anyhow::Result<()> {
    let transports = {
        let cfg = config.read().await;
        cfg.transports.clone()
    };
    if let Some(transports) = transports {
        for (name, transport_config) in transports {
            tokio::spawn(async move {
                info!(
                    "Starting transport '{}' ({:?}) on {}",
                    name, transport_config.r#type, transport_config.listen_address
                );
                let result = match transport_config.r#type {
                    TransportType::Tcp => start_tcp_transport(name.clone(), transport_config).await,
                    TransportType::Udp => start_udp_transport(name.clone(), transport_config).await,
                };

                if let Err(e) = result {
                    error!("Transport '{}' error: {}", name, e);
                }
            });
        }
    }

    Ok(())
}

async fn start_tcp_transport(name: String, config: TransportConfig) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&config.listen_address)
        .await
        .context(format!(
            "Failed to bind TCP listener on {}",
            config.listen_address
        ))?;
    info!(
        "TCP transport '{}' listening on {}",
        name, config.listen_address
    );
    loop {
        match listener.accept().await {
            Ok((client_stream, client_addr)) => {
                let upstreams = config.upstreams.clone();
                let name_clone = name.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_tcp_connection(client_stream, client_addr, upstreams, name_clone)
                            .await
                    {
                        error!("TCP connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept TCP connection on '{}': {}", name, e);
            }
        }
    }
}

async fn handle_tcp_connection(
    client_stream: TcpStream,
    client_addr: SocketAddr,
    upstreams: Vec<ServerConfig>,
    transport_name: String,
) -> anyhow::Result<()> {
    debug!(
        "TCP transport '{}': New connection from {}",
        transport_name, client_addr
    );
    // TODO: proper load balancing
    // TODO: TLS termination
    let upstream = upstreams.first().context("No upstreams configured")?;
    match upstream {
        ServerConfig::Local { address } => handle_tcp_local_upstream(client_stream, address).await,
        ServerConfig::Outpost { id, address } => {
            handle_tcp_outpost_upstream(client_stream, id, address).await
        }
    }
}

async fn handle_tcp_local_upstream(
    mut client_stream: TcpStream,
    upstream_address: &str,
) -> anyhow::Result<()> {
    let mut upstream_stream = TcpStream::connect(upstream_address).await.context(format!(
        "Failed to connect to upstream {}",
        upstream_address
    ))?;
    debug!("Connected to local upstream {}", upstream_address);
    let result = tokio::io::copy_bidirectional(&mut upstream_stream, &mut client_stream).await;
    if let Err(e) = result {
        error!("TCP bidirectional copy error: {}", e);
    }
    debug!("TCP connection closed");
    Ok(())
}

async fn handle_tcp_outpost_upstream(
    client_stream: TcpStream,
    outpost_id: &str,
    upstream_address: &str,
) -> anyhow::Result<()> {
    let (host, port) = parse_address(upstream_address)?;
    let resolved_host = if host.parse::<std::net::IpAddr>().is_err() {
        match crate::outpost::request(
            outpost_id.to_string(),
            OutpostRequest::Dns { host: host.clone() },
        )
        .await
        {
            Ok(OutpostResponse::Dns((_, ip))) => ip,
            Ok(_) => anyhow::bail!("Unexpected DNS response"),
            Err(e) => anyhow::bail!("DNS resolution failed: {}", e),
        }
    } else {
        host
    };
    let connection_id = rand::Rng::random::<u64>(&mut rand::rng());
    match crate::outpost::request(
        outpost_id.to_string(),
        OutpostRequest::TcpConnect {
            destination_host: resolved_host,
            destination_port: port,
            id: connection_id,
        },
    )
    .await
    {
        Ok(OutpostResponse::Ack) => {
            debug!(
                "Connected to outpost {} for upstream {}",
                outpost_id, upstream_address
            );
        }
        Ok(_) => anyhow::bail!("Unexpected TcpConnect response"),
        Err(e) => anyhow::bail!("TcpConnect failed: {}", e),
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    ACTIVE_TCP_STREAMS.insert(connection_id, tx);

    let (mut client_read, mut client_write) = client_stream.into_split();
    let outpost_id_clone = outpost_id.to_string();
    let client_to_outpost = tokio::spawn(async move {
        let mut buffer = vec![0u8; 8192];
        loop {
            match client_read.read(&mut buffer).await {
                Ok(0) => {
                    debug!("Client closed connection, sending disconnect to outpost");
                    let _ = crate::outpost::request(
                        outpost_id_clone.clone(),
                        OutpostRequest::TcpDisconnect { id: connection_id },
                    )
                    .await;
                    break;
                }
                Ok(n) => {
                    if let Err(e) = crate::outpost::request(
                        outpost_id_clone.clone(),
                        OutpostRequest::Tcp {
                            data: buffer[..n].to_vec(),
                            id: connection_id,
                        },
                    )
                    .await
                    {
                        error!("Failed to send data to outpost: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Error reading from client: {}", e);
                    break;
                }
            }
        }
    });
    let outpost_to_client = tokio::spawn(async move {
        while let Some(data) = rx.recv().await {
            if let Err(e) = client_write.write_all(&data).await {
                error!("Error writing to client: {}", e);
                break;
            }
        }
    });

    let _ = tokio::try_join!(client_to_outpost, outpost_to_client);
    ACTIVE_TCP_STREAMS.remove(&connection_id);
    debug!("TCP outpost connection closed");
    Ok(())
}

async fn start_udp_transport(name: String, config: TransportConfig) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(&config.listen_address)
        .await
        .context(format!(
            "Failed to bind UDP socket on {}",
            config.listen_address
        ))?;
    info!(
        "UDP transport '{}' listening on {}",
        name, config.listen_address
    );

    let socket = Arc::new(socket);
    let sessions: UdpSessionMap = Arc::new(DashMap::new());
    let mut buffer = vec![0u8; 65536];

    let sessions_cleanup = sessions.clone();
    let name_cleanup = name.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            let now = Instant::now();
            let timeout = Duration::from_secs(60);

            sessions_cleanup.retain(|key, session| {
                let elapsed = now.duration_since(session.last_activity);
                if elapsed > timeout {
                    debug!(
                        "UDP transport '{}': Cleaning up stale session for {}",
                        name_cleanup, key.1
                    );
                    false
                } else {
                    true
                }
            });
        }
    });

    loop {
        match socket.recv_from(&mut buffer).await {
            Ok((n, client_addr)) => {
                let data = buffer[..n].to_vec();
                let upstreams = config.upstreams.clone();
                let socket_clone = socket.clone();
                let sessions_clone = sessions.clone();
                let name_clone = name.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_udp_packet(
                        socket_clone,
                        client_addr,
                        data,
                        upstreams,
                        sessions_clone,
                        name_clone,
                    )
                    .await
                    {
                        error!("UDP packet handling error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to receive UDP packet on '{}': {}", name, e);
            }
        }
    }
}

async fn handle_udp_packet(
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    data: Vec<u8>,
    upstreams: Vec<ServerConfig>,
    sessions: UdpSessionMap,
    transport_name: String,
) -> anyhow::Result<()> {
    debug!(
        "UDP transport '{}': Received {} bytes from {}",
        transport_name,
        data.len(),
        client_addr
    );
    // TODO: proper load balancing
    let upstream = upstreams.first().context("No upstreams configured")?;
    match upstream {
        ServerConfig::Local { address } => {
            handle_udp_local_upstream(socket, client_addr, data, address, sessions, transport_name)
                .await
        }
        ServerConfig::Outpost { id, address } => {
            warn!(
                "UDP outpost forwarding not yet fully implemented for outpost '{}' to {}",
                id, address
            );
            // TODO: send UDP via outpost
            Ok(())
        }
    }
}

async fn handle_udp_local_upstream(
    client_socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    data: Vec<u8>,
    upstream_address: &str,
    sessions: UdpSessionMap,
    transport_name: String,
) -> anyhow::Result<()> {
    let session_key = (transport_name.clone(), client_addr);
    let session = if let Some(mut existing_session) = sessions.get_mut(&session_key) {
        existing_session.last_activity = Instant::now();
        existing_session.upstream_socket.clone()
    } else {
        let upstream_socket = Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .await
                .context("Failed to create upstream UDP socket")?,
        );
        debug!(
            "UDP transport '{}': Created new session for client {}",
            transport_name, client_addr
        );
        let client_socket_clone = client_socket.clone();
        let upstream_socket_clone = upstream_socket.clone();
        let sessions_clone = sessions.clone();
        let session_key_clone = session_key.clone();
        let transport_name_clone = transport_name.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 65536];
            loop {
                match tokio::time::timeout(
                    Duration::from_secs(60),
                    upstream_socket_clone.recv(&mut buffer),
                )
                .await
                {
                    Ok(Ok(n)) => {
                        if let Some(mut session) = sessions_clone.get_mut(&session_key_clone) {
                            session.last_activity = Instant::now();
                        }
                        if let Err(e) = client_socket_clone.send_to(&buffer[..n], client_addr).await
                        {
                            error!(
                                "UDP transport '{}': Failed to send {} bytes to client {}: {}",
                                transport_name_clone, n, client_addr, e
                            );
                            break;
                        }
                        debug!(
                            "UDP transport '{}': Sent {} bytes from upstream to client {}",
                            transport_name_clone, n, client_addr
                        );
                    }
                    Ok(Err(e)) => {
                        error!(
                            "UDP transport '{}': Error receiving from upstream for {}: {}",
                            transport_name_clone, client_addr, e
                        );
                        break;
                    }
                    Err(_) => {
                        debug!(
                            "UDP transport '{}': Session timeout for client {}",
                            transport_name_clone, client_addr
                        );
                        break;
                    }
                }
            }
            sessions_clone.remove(&session_key_clone);
            debug!(
                "UDP transport '{}': Closed session for client {}",
                transport_name_clone, client_addr
            );
        });
        sessions.insert(
            session_key.clone(),
            UdpSession {
                upstream_socket: upstream_socket.clone(),
                last_activity: Instant::now(),
            },
        );
        upstream_socket
    };
    session
        .send_to(&data, upstream_address)
        .await
        .context(format!("Failed to send to upstream {}", upstream_address))?;
    debug!(
        "UDP transport '{}': Sent {} bytes from {} to upstream {}",
        transport_name,
        data.len(),
        client_addr,
        upstream_address
    );
    Ok(())
}

fn parse_address(address: &str) -> anyhow::Result<(String, u16)> {
    if let Some(colon_pos) = address.rfind(':') {
        let host_part = &address[..colon_pos];
        let port_part = &address[colon_pos + 1..];
        let port = port_part.parse::<u16>().context("Invalid port number")?;
        Ok((host_part.to_string(), port))
    } else {
        anyhow::bail!("Invalid address format: missing port")
    }
}
