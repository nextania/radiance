use anyhow::Result;
use radiance_types::control_socket::{ControlCommand, ControlResponse};
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixStream, unix::OwnedReadHalf};

#[derive(Clone, Debug)]
pub struct RadianceControlClient {
    socket_path: String,
}

impl RadianceControlClient {
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_string_lossy().to_string(),
        }
    }

    pub async fn send_command(&self, command: ControlCommand) -> Result<ControlResponse> {
        let stream = UnixStream::connect(&self.socket_path).await?;
        let (reader, mut writer) = stream.into_split();
        let command_json = serde_json::to_string(&command)?;
        writer.write_all(command_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        let mut buf_reader = BufReader::new(reader);
        let mut response_line = String::new();
        buf_reader.read_line(&mut response_line).await?;
        let response: ControlResponse = serde_json::from_str(&response_line)?;
        Ok(response)
    }

    pub async fn add_host(
        &self,
        id: String,
        host: radiance_types::config::HostConfig,
    ) -> Result<ControlResponse> {
        self.send_command(ControlCommand::AddHost { id, host }).await
    }

    pub async fn update_host(
        &self,
        id: String,
        host: radiance_types::config::PartialHostConfig,
    ) -> Result<ControlResponse> {
        self.send_command(ControlCommand::UpdateHost { id, host })
            .await
    }

    pub async fn remove_host(&self, id: String) -> Result<ControlResponse> {
        self.send_command(ControlCommand::RemoveHost { id }).await
    }

    pub async fn list_hosts(&self) -> Result<ControlResponse> {
        self.send_command(ControlCommand::ListHosts).await
    }

    pub async fn get_host(&self, id: String) -> Result<ControlResponse> {
        self.send_command(ControlCommand::GetHost { id }).await
    }

    pub async fn reload(&self) -> Result<ControlResponse> {
        self.send_command(ControlCommand::Reload).await
    }

    pub async fn set_http_challenge(
        &self,
        domain: String,
        token: String,
        thumbprint: String,
    ) -> Result<ControlResponse> {
        self.send_command(ControlCommand::SetHttpChallenge {
            domain,
            token,
            thumbprint,
        })
        .await
    }

    pub async fn clear_http_challenge(&self, domain: String, token: String) -> Result<ControlResponse> {
        self.send_command(ControlCommand::ClearHttpChallenge { domain, token })
            .await
    }

    pub async fn add_certificate(&self, id: String, certificate: radiance_types::config::TlsCertConfig) -> Result<ControlResponse> {
        self.send_command(ControlCommand::AddCertificate { id, certificate }).await
    }

    pub async fn remove_certificate(&self, id: String) -> Result<ControlResponse> {
        self.send_command(ControlCommand::RemoveCertificate { id }).await
    }

    pub async fn list_certificates(&self) -> Result<ControlResponse> {
        self.send_command(ControlCommand::ListCertificates).await
    }

    pub async fn get_certificate(&self, id: String) -> Result<ControlResponse> {
        self.send_command(ControlCommand::GetCertificate { id }).await
    }
}

/// Streaming client for subscribing to certificate updates from zenith's control socket
pub struct ZenithCertificateClient {
    buf_reader: BufReader<OwnedReadHalf>,
    buffer: Vec<u8>,
}

impl ZenithCertificateClient {
    pub async fn new(path: &str, id: &str) -> anyhow::Result<Self> {        
        let stream = UnixStream::connect(path).await?;
        let (reader, mut writer) = stream.into_split();
        let command = zenith_types::ControlCommand::SubscribeCertificate {
            id: id.to_string(),
        };
        let command_json = serde_json::to_string(&command)?;
        writer.write_all(command_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;
        let buf_reader = BufReader::new(reader);
        Ok(Self { buf_reader, buffer: Vec::new() })
    }

    pub async fn read(&mut self) -> anyhow::Result<zenith_types::Certificate> {
        self.buf_reader.read_until(b'\n', &mut self.buffer).await?;
        let response: zenith_types::ControlResponse = serde_json::from_slice(&self.buffer)?;
        self.buffer.clear();
        let zenith_types::ControlResponse::Success { data } = &response else {
            return Err(anyhow::anyhow!("Failed to get certificate: {:?}", response));
        };
        let certificate: zenith_types::Certificate = serde_json::from_value(data.clone())?;
        Ok(certificate)
    }
}

#[derive(Clone, Debug)]
pub struct ZenithControlClient {
    socket_path: String,
}

impl ZenithControlClient {
    pub fn new(socket_path: String) -> Self {
        Self { socket_path }
    }
}
