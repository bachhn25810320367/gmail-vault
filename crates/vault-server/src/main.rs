use std::net::SocketAddr;

use vault_server::{AppState, build_router, config::Config, db};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::from_env()?;
    let pool = db::connect(&config.database_url).await?;
    db::migrate(&pool).await?;
    let addr = config.bind_addr;
    let app = build_router(AppState {
        pool,
        config: std::sync::Arc::new(config),
    });
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "vault-server listening");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
