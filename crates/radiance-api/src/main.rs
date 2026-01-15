pub mod auth;
pub mod config;
pub mod handlers;
pub mod sessions;
pub mod environment;
pub mod errors;

use actix_files::{Files, NamedFile};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{middleware::Logger, web, App, HttpServer};
use anyhow::Result;
use serde::Serialize;
use tracing::{error, info};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth::AuthMiddleware;
use crate::config::ApiConfig;
use radiance_control::RadianceControlClient;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OidcProviderInfo {
    pub id: String,
    pub display_name: String,
    pub logo_path: Option<String>,
    pub auth_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilitiesResponse {
    pub version: String,
    pub oidc_providers: Vec<OidcProviderInfo>,
    pub password_authentication: bool,
}

async fn capabilities(config: web::Data<Arc<ApiConfig>>) -> actix_web::Result<actix_web::HttpResponse> {
    Ok(actix_web::HttpResponse::Ok().json(CapabilitiesResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        oidc_providers: config
            .oidc_providers
            .iter()
            .map(|provider| OidcProviderInfo {
                id: provider.id.clone(),
                display_name: provider.display_name.clone(),
                logo_path: provider.logo_path.clone(),
                auth_path: format!("/api/oidc/{}", provider.id),
            })
            .collect(),
        password_authentication: config.password_hash.is_some(),
    }))
}


#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "radiance_api=info,actix_web=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();

    if !Path::new(&*environment::RADIANCE_API_CONFIG).exists() {
        error!("Config file not found at {}", *environment::RADIANCE_API_CONFIG);
        std::process::exit(1);
    }
    let config_content = fs::read_to_string(&*environment::RADIANCE_API_CONFIG)?;
    let config = Arc::new(toml::from_str::<ApiConfig>(&config_content)?);
    let listen_addr = config.listen.clone();

    info!("Starting Radiance API server on {}", listen_addr);
    info!("Control socket: {:?}", config.socket_path);
    
    if !config.has_authentication() {
        error!("Authentication must be enabled in order to run the API server");
        error!("Please set a password or configure at least one OIDC provider");
        std::process::exit(1);
    }
    if config.password_hash.is_some() {
        info!("Password authentication enabled");
    }
    if !config.oidc_providers.is_empty() {
        info!(
            "OIDC providers configured: {}",
            config.oidc_providers.len()
        );
    }

    info!("Connecting to MongoDB...");
    sessions::connect().await;
    info!("Connected to MongoDB");

    let socket_client = Arc::new(RadianceControlClient::new(&config.socket_path));
    let oidc_clients = 
        Arc::new(auth::resolve_oidc_clients(&config).await?);

    HttpServer::new(move || {
        let mut app = App::new()
            .app_data(web::Data::new(socket_client.clone()))
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(oidc_clients.clone()))
            .wrap(Logger::default());
        let api_scope = web::scope("/api")
            .route("", web::get().to(capabilities))
            .route("/session", web::post().to(auth::password_login))
            .route("/oidc/{provider}", web::get().to(auth::oidc_login))
            .route("/oidc/{provider}/backchannel-logout", web::post().to(auth::logout_backchannel))
            .route("/callback", web::get().to(auth::oidc_callback))
            .service(web::resource("/session")
                .wrap(AuthMiddleware)
                .route(web::get().to(auth::validate)))
            .service(web::resource("/session")
                .wrap(AuthMiddleware)
                .route(web::delete().to(auth::logout)))
            .service(web::scope("/hosts")
                .wrap(AuthMiddleware)
                .route("", web::get().to(handlers::list_hosts))
                .route("", web::post().to(handlers::add_host))
                .route("/{id}", web::get().to(handlers::get_host))
                .route("/{id}", web::put().to(handlers::update_host))
                .route("/{id}", web::delete().to(handlers::remove_host))
            )
            .service(web::scope("/certificates")
                .wrap(AuthMiddleware)
                .route("/", web::get().to(handlers::list_certificates))
                .route("/", web::post().to(handlers::add_certificate))
                .route("/{id}", web::get().to(handlers::get_certificate))
                .route("/{id}", web::delete().to(handlers::remove_certificate))
            )
            .service(web::scope("/reload")
                .wrap(AuthMiddleware)
                .route("", web::post().to(handlers::reload))
            )
            .service(web::scope("/challenges")
                .wrap(AuthMiddleware)
                .route(
                    "/http",
                    web::post().to(handlers::set_http_challenge),
                )
                .route(
                    "/http",
                    web::delete().to(handlers::clear_http_challenge),
                )
            );
        app = app.service(api_scope).service(Files::new("/", "bundle")
                    .index_file("index.html")
                    .default_handler(|req: ServiceRequest| async {
                        let (request, _) = req.into_parts();
                        let response =
                            NamedFile::open("bundle/index.html")?.into_response(&request);
                        Ok(ServiceResponse::new(request, response))
                    }),);
        app
    })
    .bind(&listen_addr)?
    .run()
    .await?;

    Ok(())
}
