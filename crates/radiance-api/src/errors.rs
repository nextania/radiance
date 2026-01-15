use std::fmt::Display;

use actix_web::ResponseError;
use radiance_types::ControlError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "error", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Error {
    DatabaseError,
    MissingToken,
    InvalidToken,
    CredentialError,
    PasswordNotConfigured,
    OidcNotConfigured,
    OidcConfigurationError,
    OidcServerError,
    BackchannelLogoutError,
    ControlSocketError,

    RateLimited {
        limit: u64,
        remaining: u64,
        reset: u64,
    },
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            Error::DatabaseError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::MissingToken => actix_web::http::StatusCode::UNAUTHORIZED,
            Error::InvalidToken => actix_web::http::StatusCode::UNAUTHORIZED,
            Error::CredentialError => actix_web::http::StatusCode::UNAUTHORIZED,
            Error::PasswordNotConfigured => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::OidcNotConfigured => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::OidcConfigurationError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::OidcServerError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::BackchannelLogoutError => actix_web::http::StatusCode::BAD_REQUEST,
            Error::ControlSocketError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            Error::RateLimited { .. } => actix_web::http::StatusCode::TOO_MANY_REQUESTS,
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        actix_web::HttpResponse::build(self.status_code()).json(self)
    }
}

impl From<mongodb::error::Error> for Error {
    fn from(_: mongodb::error::Error) -> Self {
        Error::DatabaseError
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ApiError {
    GeneralError(crate::errors::Error),
    ControlError(ControlError),
}

impl ApiError {
    pub fn from_control_error(error: ControlError) -> Self {
        ApiError::ControlError(error)
    }
}

impl std::error::Error for ApiError {}

impl Display for ApiError {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        unimplemented!()
    }
}

impl ResponseError for ApiError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        match self {
            ApiError::GeneralError(error) => error.status_code(),
            ApiError::ControlError(control_error) => match control_error {
                ControlError::HostNotFound => actix_web::http::StatusCode::NOT_FOUND,
                ControlError::HostAlreadyExists => actix_web::http::StatusCode::CONFLICT,
                ControlError::CertificateNotFound => actix_web::http::StatusCode::NOT_FOUND,
                ControlError::CertificateAlreadyExists => actix_web::http::StatusCode::CONFLICT,
                ControlError::InvalidCertificate => actix_web::http::StatusCode::BAD_REQUEST,
                ControlError::HttpChallengeNotFound => actix_web::http::StatusCode::NOT_FOUND,
                ControlError::FailedToReload => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                ControlError::FailedToSave => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                ControlError::MalformedCommand => actix_web::http::StatusCode::BAD_REQUEST,
            },
        }
    }

    fn error_response(&self) -> actix_web::HttpResponse {
        actix_web::HttpResponse::build(self.status_code()).json(self)
    }
}
