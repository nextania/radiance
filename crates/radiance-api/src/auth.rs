use actix_web::{
    HttpMessage, HttpResponse, dev::{Service, ServiceRequest, ServiceResponse, Transform, forward_ready}, web
};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use dashmap::DashMap;
use futures_util::future::LocalBoxFuture;
use lazy_static::lazy_static;
use mongodb::bson::doc;
use once_cell::sync::Lazy;
use openidconnect::{AdditionalClaims, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet, EndpointNotSet, EndpointSet, IdToken, IdTokenFields, IssuerUrl, Nonce, NonceVerifier, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, StandardErrorResponse, StandardTokenResponse, TokenResponse, core::{CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreClient, CoreErrorResponseType, CoreGenderClaim, CoreIdToken, CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenResponse, CoreTokenType}};
use reqwest::{ClientBuilder, redirect::Policy};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr};
use std::future::{ready, Ready};
use std::rc::Rc;
use std::sync::Arc;

use crate::{config::ApiConfig, sessions::{OidcSessionData, Session}, errors::Error};

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
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
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
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let srv = self.service.clone();

        Box::pin(async move {
            let session = async {
                let authorization = req
                    .headers()
                    .get("Authorization")
                    .ok_or(Error::MissingToken)?;
                let token = &authorization.to_str().map_err(|_| Error::InvalidToken)?;
                Session::validate(&token.to_string()).await?.ok_or(Error::InvalidToken)
            }.await.map_err(|e| actix_web::Error::from(e))?;
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
type ActualClient = Client<
    SidAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    ActualTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet,
>;

type ActualTokenResponse = StandardTokenResponse<IdTokenFields<
    SidAdditionalClaims,
    EmptyExtraTokenFields,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm,
>, CoreTokenType>;

pub async fn resolve_oidc_clients(config: &ApiConfig) -> Result<HashMap<String, ActualClient>, anyhow::Error> {
    let mut clients: HashMap<String, ActualClient> = HashMap::new();

    for provider in &config.oidc_providers {
        let issuer_url = IssuerUrl::new(provider.issuer_url.clone())?;
        let metadata = CoreProviderMetadata::discover_async(issuer_url, &*ASYNC_HTTP_CLIENT).await?;

        let client  = ActualClient::from_provider_metadata(
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
    oidc_clients: web::Data<Arc<HashMap<String, ActualClient>>>,
    provider_name: web::Path<String>,
    query: web::Query<OidcLoginQuery>,
) -> Result<HttpResponse, Error> {
    let client = oidc_clients
        .get(provider_name.as_str())
        .ok_or(Error::OidcNotConfigured)?;
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
    oidc_clients: web::Data<Arc<HashMap<String, ActualClient>>>,
    query: web::Query<OidcCallbackQuery>,
) -> Result<HttpResponse, Error> {
    let oidc_state = OIDC_SESSIONS
        .remove(&query.state)
        .ok_or(Error::CredentialError)?
        .1;
    let client = oidc_clients
        .get(&oidc_state.provider)
        .ok_or(Error::OidcNotConfigured)?;
    let token_response = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .map_err(|_| Error::OidcServerError)?
        .set_pkce_verifier(oidc_state.pkce_verifier)
        .request_async(&*ASYNC_HTTP_CLIENT)
        .await
        .map_err(|_| Error::OidcServerError)?;
    let id_token = token_response
        .id_token()
        .ok_or(Error::OidcServerError)?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &oidc_state.nonce)
        .map_err(|_| Error::CredentialError)?;

    let sub = claims.subject().as_str().to_string();
    let sid = claims.additional_claims().sid.clone();
    let session = Session::create(Some(OidcSessionData {
        provider: oidc_state.provider.clone(),
        subject: sub,
        sid,
    })).await?;
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
        .ok_or(Error::PasswordNotConfigured)?;
    if !verify_password(password_hash, &credentials.password) {
        return Err(Error::CredentialError);
    }
    let session = Session::create(None).await?;
    Ok(HttpResponse::Ok().json(PasswordLoginResponse {
        token: session.token,
        expires_at: session.expires_at,
    }))
}

pub async fn logout(session: web::ReqData<Session>) -> Result<HttpResponse, Error> {
    session.delete().await?;
    Ok(HttpResponse::Ok().json(serde_json::json!({})))
}

#[derive(Debug, Deserialize)]
pub struct LogoutBackchannelRequest {
    pub logout_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SidAdditionalClaims {
    pub sid: Option<String>,
}

impl AdditionalClaims for SidAdditionalClaims {}

pub struct LogoutNonceVerifier;
impl NonceVerifier for LogoutNonceVerifier {
    fn verify(self, nonce: Option<&Nonce>) -> Result<(), String> {
        match nonce {
            None => Ok(()),
            Some(_) => Err("Nonce present in logout token".into()),
        }
    }
}

// see: https://auth0.com/docs/authenticate/login/logout/back-channel-logout/configure-back-channel-logout
pub async fn logout_backchannel(
    oidc_clients: web::Data<Arc<HashMap<String, ActualClient>>>,
    idp: web::Path<String>, 
    token: web::Form<LogoutBackchannelRequest>
) -> Result<HttpResponse, Error> {
    let client = oidc_clients
        .get(idp.as_str())
        .ok_or(Error::OidcNotConfigured)?;
    let id_token: Result<IdToken<SidAdditionalClaims, CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJwsSigningAlgorithm>, serde_json::Error> = IdToken::from_str(&token.logout_token);
    if let Ok(id_token) = id_token {
        let claims = id_token
            .claims(&client.id_token_verifier(), LogoutNonceVerifier)
            .map_err(|_| Error::BackchannelLogoutError)?;
        let sub = claims.subject().as_str().to_string();
        Session::delete_oidc(&idp, &sub, &claims.additional_claims().sid).await
            .map_err(|_| Error::BackchannelLogoutError)?;
        Ok(HttpResponse::Ok().json(serde_json::json!({})))
    } else {
        Err(Error::BackchannelLogoutError)
    }
}
