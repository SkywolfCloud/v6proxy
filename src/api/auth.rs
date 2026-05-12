use axum::extract::ConnectInfo;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::net::SocketAddr;

use crate::config::ParsedTokensConfig;

pub async fn ip_allowlist_middleware(
    State(tokens): State<ParsedTokensConfig>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let peer_ip = addr.ip();

    let allowed = tokens
        .admin_allowlist
        .iter()
        .any(|net| net.contains(&peer_ip));
    if !allowed {
        tracing::warn!(peer_ip = %peer_ip, "admin request from non-whitelisted IP");
        return (StatusCode::FORBIDDEN, "forbidden: IP not in allowlist").into_response();
    }

    next.run(request).await
}

pub async fn token_middleware(
    State(tokens): State<ParsedTokensConfig>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                "unauthorized: missing or invalid token",
            )
                .into_response();
        }
    };

    // Verify token against argon2id hash
    match verify_token(token, &tokens.admin_token_hash) {
        Ok(true) => next.run(request).await,
        _ => {
            tracing::warn!("admin request with invalid token");
            (StatusCode::UNAUTHORIZED, "unauthorized: invalid token").into_response()
        }
    }
}

fn verify_token(token: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    use argon2::Argon2;

    let parsed_hash = PasswordHash::new(hash)?;
    match Argon2::default().verify_password(token.as_bytes(), &parsed_hash) {
        Ok(()) => Ok(true),
        Err(argon2::password_hash::Error::Password) => Ok(false),
        Err(e) => Err(e),
    }
}
