use actix_web::{
    Error, HttpMessage, HttpResponse, dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready}, error::{ErrorForbidden, ErrorInternalServerError, ErrorUnauthorized}, web
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use dashmap::DashMap;
use futures_util::future::LocalBoxFuture;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use once_cell::sync::Lazy;
use openidconnect::{AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse, core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata}};
use reqwest::{ClientBuilder, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Arc;

use crate::{config::ApiConfig, sessions::{OidcSessionData, Session}};

static ASYNC_HTTP_CLIENT: Lazy<reqwest::Client> =
    Lazy::new(|| ClientBuilder::new().redirect(Policy::none()).build().unwrap());

#[derive(Clone)]
pub struct AuthMiddleware;

fn verify_password(password_hash: &str, password: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(hash) => hash,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

impl<S, B> Transform<S, ServiceRequest> for AuthMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = AuthMiddlewareService<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(AuthMiddlewareService {
            service: Rc::new(service),
        }))
    }
}

pub struct AuthMiddlewareService<S> {
    service: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for AuthMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();

        Box::pin(async move {    
            let authorization = req
                .headers()
                .get("Authorization")
                .ok_or(ErrorUnauthorized("Missing token"))?;
            let token = &authorization.to_str().map_err(|_| ErrorUnauthorized("Invalid token"))?;
            let session = Session::validate(&token.to_string()).await.map_err(|_| ErrorInternalServerError("Internal error"))?.ok_or(ErrorUnauthorized("Invalid token"))?;
            req.extensions_mut().insert(session);
            srv.call(req).await
        })
    }
}


#[derive(Debug, Deserialize)]
pub struct OidcCallbackQuery {
    pub code: String,
    pub state: String,
}

// this is necessary because of openidconnect crate's complex generics
type ActualCoreClient = CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

pub async fn resolve_oidc_clients(config: &ApiConfig) -> Result<HashMap<String, ActualCoreClient>, anyhow::Error> {
    let mut clients: HashMap<String, ActualCoreClient> = HashMap::new();

    for provider in &config.oidc_providers {
        let issuer_url = IssuerUrl::new(provider.issuer_url.clone())?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url, &*ASYNC_HTTP_CLIENT).await?;

        let client  = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(provider.client_id.clone()),
            Some(ClientSecret::new(provider.client_secret.clone())),
        )
        .set_redirect_uri(RedirectUrl::new(provider.redirect_uri.clone())?);

        clients.insert(provider.id.clone(), client);
    }

    Ok(clients)
}

struct OidcState {
    provider: String,
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    r#continue: Option<String>,
}

lazy_static! {
    static ref OIDC_SESSIONS: DashMap<String, OidcState> = DashMap::new();
}

#[derive(Debug, Deserialize)]
pub struct OidcLoginQuery {
    pub r#continue: Option<String>,
}

pub async fn oidc_login(
    oidc_clients: web::Data<Arc<HashMap<String, ActualCoreClient>>>,
    provider_name: web::Path<String>,
    query: web::Query<OidcLoginQuery>,
) -> Result<HttpResponse, Error> {
    let client = oidc_clients
        .get(provider_name.as_str())
        .ok_or_else(|| ErrorForbidden("Unknown OIDC provider"))?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (auth_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    OIDC_SESSIONS.insert(
        csrf_token.secret().to_string(),
        OidcState {
            provider: provider_name.to_string(),
            nonce,
            pkce_verifier,
            r#continue: query.r#continue.clone(),
        },
    );

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish())
}

pub async fn oidc_callback(
    oidc_clients: web::Data<Arc<HashMap<String, ActualCoreClient>>>,
    query: web::Query<OidcCallbackQuery>,
) -> Result<HttpResponse, Error> {
    let oidc_state = OIDC_SESSIONS
        .remove(&query.state)
        .ok_or_else(|| ErrorForbidden("Invalid state"))?
        .1;
    let client = oidc_clients
        .get(&oidc_state.provider)
        .ok_or_else(|| ErrorForbidden("Unknown OIDC provider"))?;
    let token_response = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .map_err(|_| ErrorForbidden("Token exchange failed"))?
        .set_pkce_verifier(oidc_state.pkce_verifier)
        .request_async(&*ASYNC_HTTP_CLIENT)
        .await
        .map_err(|_| ErrorForbidden("Token exchange failed"))?;
    let id_token = token_response
        .id_token()
        .ok_or_else(|| ErrorForbidden("No ID token in response"))?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &oidc_state.nonce)
        .map_err(|_| ErrorForbidden(format!("Token verification failed")))?;

    let sub = claims.subject().as_str().to_string();
    let session = Session::create(Some(OidcSessionData {
        provider: oidc_state.provider.clone(),
        subject: sub,
    })).await
        .map_err(|_| ErrorInternalServerError(format!("Failed to create session")))?;
    let continue_url = format!("/authenticate?token={}&continue={}", session.token, oidc_state.r#continue.clone().unwrap_or_else(|| "/".to_string()));
    Ok(HttpResponse::Found()
        .append_header(("Location", continue_url))
        .finish())
}

#[derive(Debug, Deserialize)]
pub struct PasswordLogin {
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct PasswordLoginResponse {
    pub token: String,
    pub expires_at: u64,
}

pub async fn password_login(
    config: web::Data<Arc<ApiConfig>>,
    credentials: web::Json<PasswordLogin>,
) -> Result<HttpResponse, Error> {
    let password_hash = config
        .password_hash
        .as_ref()
        .ok_or_else(|| ErrorUnauthorized("Password authentication not enabled"))?;
    if !verify_password(password_hash, &credentials.password) {
        return Err(ErrorUnauthorized("Invalid password"));
    }
    let session = Session::create(None).await
        .map_err(|_| ErrorInternalServerError(format!("Failed to create session")))?;
    Ok(HttpResponse::Ok().json(PasswordLoginResponse {
        token: session.token,
        expires_at: session.expires_at,
    }))
}

pub async fn logout(session: web::ReqData<Session>) -> Result<HttpResponse, Error> {
    session.delete().await.map_err(|_| ErrorInternalServerError(format!("Failed to delete session")))?;
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "message": "Logged out successfully"
    })))
}
