use std::fmt::Display;

use actix_web::ResponseError;
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

pub type Result<T> = std::result::Result<T, Error>;
