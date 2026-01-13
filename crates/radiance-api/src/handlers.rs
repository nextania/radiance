use actix_web::{web, HttpResponse};
use radiance_types::{ControlResponse, config::{HostConfig, PartialHostConfig, TlsCertConfig}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::{errors::ApiError, socket_client::ControlSocketClient};

#[derive(Debug, Serialize, Deserialize)]
pub struct AddHostRequest {
    pub id: String,
    pub config: HostConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateHostRequest {
    pub config: PartialHostConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SetHttpChallengeRequest {
    pub domain: String,
    pub token: String,
    pub thumbprint: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ClearHttpChallengeRequest {
    pub domain: String,
    pub token: String,
}

pub async fn add_host(
    client: web::Data<Arc<ControlSocketClient>>,
    request: web::Json<AddHostRequest>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .add_host(request.id.clone(), request.config.clone())
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn update_host(
    client: web::Data<Arc<ControlSocketClient>>,
    id: web::Path<String>,
    request: web::Json<UpdateHostRequest>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .update_host(id.into_inner(), request.into_inner().config)
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn remove_host(
    client: web::Data<Arc<ControlSocketClient>>,
    id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .remove_host(id.into_inner())
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn get_host(
    client: web::Data<Arc<ControlSocketClient>>,
    id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .get_host(id.into_inner())
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn list_hosts(
    client: web::Data<Arc<ControlSocketClient>>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .list_hosts()
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn reload(
    client: web::Data<Arc<ControlSocketClient>>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .reload()
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn set_http_challenge(
    client: web::Data<Arc<ControlSocketClient>>,
    request: web::Json<SetHttpChallengeRequest>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .set_http_challenge(
            request.domain.clone(),
            request.token.clone(),
            request.thumbprint.clone(),
        )
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn clear_http_challenge(
    client: web::Data<Arc<ControlSocketClient>>,
    request: web::Json<ClearHttpChallengeRequest>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .clear_http_challenge(request.domain.clone(), request.token.clone())
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn add_certificate(
    client: web::Data<Arc<ControlSocketClient>>,
    certificate: web::Json<TlsCertConfig>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .add_certificate(certificate.into_inner())
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn remove_certificate(
    client: web::Data<Arc<ControlSocketClient>>,
    id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .remove_certificate(id.into_inner())
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn list_certificates(
    client: web::Data<Arc<ControlSocketClient>>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .list_certificates()
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}

pub async fn get_certificate(
    client: web::Data<Arc<ControlSocketClient>>,
    id: web::Path<String>,
) -> Result<HttpResponse, ApiError> {
    let response = client
        .get_certificate(id.into_inner())
        .await
        .map_err(|_| ApiError::GeneralError(crate::errors::Error::ControlSocketError))?;

    match response {
        ControlResponse::Success { data } => Ok(HttpResponse::Ok().json(data)),
        ControlResponse::Error { error } => Err(ApiError::ControlError(error)),
    }
}
