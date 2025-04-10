mod tokens;
mod v0;

use crate::{
    domain::{user_repository::UserRepository, user_service::UserRepositoryUserService},
    infra::api::tokens::Tokens,
};
use anyhow::Context;
use api_version::{ApiVersionFilter, ApiVersionLayer, ApiVersions};
use axum::{Router, ServiceExt, http::Uri, response::IntoResponse, routing::post};
use fastrace_axum::FastraceLayer;
use serde::Deserialize;
use std::{convert::Infallible, net::IpAddr};
use tokio::{
    net::TcpListener,
    signal::unix::{SignalKind, signal},
};
use tower::{Layer, ServiceBuilder};
use tower_http::cors::CorsLayer;

const API_VERSIONS: ApiVersions<1> = ApiVersions::new([0]);

/// The API configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub address: IpAddr,

    pub port: u16,

    #[serde(rename = "tokens")]
    pub tokens_config: tokens::Config,
}

/// Serve the API, supporting trace context propagation and permissive CORS.
pub async fn serve<R>(
    config: Config,
    user_service: UserRepositoryUserService<R>,
) -> anyhow::Result<()>
where
    R: UserRepository,
{
    let Config {
        address,
        port,
        tokens_config,
    } = config;

    let tokens = Tokens::new(tokens_config);

    let app_state = AppState {
        user_service,
        tokens,
    };

    let app = app(app_state).layer(
        ServiceBuilder::new()
            .layer(FastraceLayer)
            .layer(CorsLayer::permissive()),
    );
    let app = ApiVersionLayer::new(API_VERSIONS, ReadyFilter).layer(app);

    let listener = TcpListener::bind((address, port))
        .await
        .context("bind TcpListener")?;
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("run server")
}

#[derive(Clone)]
struct AppState<R> {
    user_service: UserRepositoryUserService<R>,
    tokens: Tokens,
}
#[derive(Clone)]
struct ReadyFilter;

impl ApiVersionFilter for ReadyFilter {
    type Error = Infallible;

    async fn should_rewrite(&self, uri: &Uri) -> Result<bool, Self::Error> {
        Ok(uri.path() != "/")
    }
}

fn app<R>(app_state: AppState<R>) -> Router
where
    R: UserRepository,
{
    Router::new()
        .route("/", post(ready))
        .nest("/v0", v0::routes())
        .with_state(app_state)
}

async fn ready() -> impl IntoResponse {
    "ready"
}

async fn shutdown_signal() {
    signal(SignalKind::terminate())
        .expect("install SIGTERM handler")
        .recv()
        .await;
}
