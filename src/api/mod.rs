pub mod auth;
pub mod handlers;

use axum::Router;

use crate::config::ParsedTokensConfig;

pub fn router(tokens: ParsedTokensConfig) -> Router {
    // Tier 1: IP allowlist + token — full CRUD
    let authenticated = handlers::bindings_router()
        .layer(axum::middleware::from_fn_with_state(
            tokens.clone(),
            auth::token_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            tokens.clone(),
            auth::ip_allowlist_middleware,
        ));

    // Tier 2: IP allowlist only — metrics (no token needed for Prometheus)
    let ip_only = Router::new()
        .route("/v1/metrics", axum::routing::get(handlers::metrics_handler))
        .layer(axum::middleware::from_fn_with_state(
            tokens.clone(),
            auth::ip_allowlist_middleware,
        ));

    // Tier 3: No auth — health check only
    Router::new()
        .route("/v1/healthz", axum::routing::get(handlers::healthz))
        .merge(ip_only)
        .merge(authenticated)
}
