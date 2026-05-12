use axum::{
    extract::Path,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, patch, post, put},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::state::{self, Binding, HashPolicy, POLICIES};

pub fn bindings_router() -> Router {
    Router::new()
        .route("/v1/bindings", get(list_bindings))
        .route("/v1/bindings/:srcip", get(get_binding))
        .route("/v1/bindings/:srcip", put(put_binding))
        .route("/v1/bindings/:srcip", delete(delete_binding))
        .route("/v1/bindings/:srcip/hash_policy", patch(patch_hash_policy))
        .route("/v1/bindings/:srcip/reseed", post(reseed))
}

#[derive(Serialize)]
struct BindingResponse {
    srcip: String,
    policy: HashPolicy,
    seed: String,
    updated_at: String,
    exists: bool,
}

impl BindingResponse {
    fn from_binding(srcip: IpAddr, b: &Binding, exists: bool) -> Self {
        BindingResponse {
            srcip: srcip.to_string(),
            policy: b.policy,
            seed: format!("0x{:016x}", b.seed),
            updated_at: b.updated_at.to_rfc3339(),
            exists,
        }
    }
}

#[derive(Serialize)]
struct BindingsListResponse {
    bindings: Vec<BindingResponse>,
    total: usize,
}

pub async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

pub async fn metrics_handler() -> impl IntoResponse {
    let policies = POLICIES.load();
    let body = format!(
        "# HELP v6proxy_bindings_total Total number of srcip bindings\n\
         # TYPE v6proxy_bindings_total gauge\n\
         v6proxy_bindings_total {}\n",
        policies.bindings.len()
    );
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        body,
    )
}

async fn list_bindings() -> impl IntoResponse {
    let policies = POLICIES.load();
    let bindings: Vec<BindingResponse> = policies
        .bindings
        .iter()
        .map(|(ip, b)| BindingResponse::from_binding(*ip, b, true))
        .collect();
    let total = bindings.len();
    Json(BindingsListResponse { bindings, total })
}

async fn get_binding(Path(srcip): Path<String>) -> impl IntoResponse {
    let ip: IpAddr = match srcip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid IP address"})),
            )
                .into_response()
        }
    };

    let policies = POLICIES.load();
    match policies.bindings.get(&ip) {
        Some(b) => Json(BindingResponse::from_binding(ip, b, true)).into_response(),
        None => Json(BindingResponse::from_binding(
            ip,
            &state::default_binding(),
            false,
        ))
        .into_response(),
    }
}

#[derive(Deserialize)]
struct PutBindingRequest {
    policy: Option<String>,
    seed: Option<String>,
}

async fn put_binding(
    Path(srcip): Path<String>,
    Json(body): Json<PutBindingRequest>,
) -> impl IntoResponse {
    let ip: IpAddr = match srcip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid IP address"})),
            )
                .into_response()
        }
    };

    let existing = {
        let policies = POLICIES.load();
        policies.bindings.get(&ip).cloned()
    };

    let policy = match body.policy.as_deref() {
        Some(p) => match p.parse::<HashPolicy>() {
            Ok(hp) => hp,
            Err(_) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "invalid policy, must be: src_ip, src_dst, five_tuple"}))).into_response(),
        },
        None => existing
            .as_ref()
            .map(|b| b.policy)
            .unwrap_or_else(state::default_hash_policy),
    };

    let seed = match body.seed.as_deref() {
        Some(s) => match state::parse_seed(s) {
            Ok(v) => v,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "invalid seed, expected decimal or 0x-prefixed hex"})),
                )
                    .into_response()
            }
        },
        None => existing
            .as_ref()
            .map(|b| b.seed)
            .unwrap_or_else(state::default_binding_seed),
    };

    let binding = Binding {
        policy,
        seed,
        updated_at: Utc::now(),
    };

    match state::apply_and_save(|policies| {
        policies.bindings.insert(ip, binding.clone());
    }) {
        Ok(_) => {
            tracing::info!(srcip = %ip, policy = %policy, "binding created/updated");
            (
                StatusCode::OK,
                Json(BindingResponse::from_binding(ip, &binding, true)),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to save policies");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to save"})),
            )
                .into_response()
        }
    }
}

async fn delete_binding(Path(srcip): Path<String>) -> impl IntoResponse {
    let ip: IpAddr = match srcip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid IP address"})),
            )
                .into_response()
        }
    };

    {
        let policies = POLICIES.load();
        if !policies.bindings.contains_key(&ip) {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "srcip not found"})),
            )
                .into_response();
        }
    }

    match state::apply_and_save(|policies| {
        policies.bindings.remove(&ip);
    }) {
        Ok(_) => {
            tracing::info!(srcip = %ip, "binding deleted");
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "deleted"})),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to save policies");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to save"})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct PatchPolicyRequest {
    policy: String,
}

async fn patch_hash_policy(
    Path(srcip): Path<String>,
    Json(body): Json<PatchPolicyRequest>,
) -> impl IntoResponse {
    let ip: IpAddr = match srcip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid IP address"})),
            )
                .into_response()
        }
    };

    let new_policy = match body.policy.parse::<HashPolicy>() {
        Ok(hp) => hp,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid policy"})),
            )
                .into_response()
        }
    };

    {
        let policies = POLICIES.load();
        if !policies.bindings.contains_key(&ip) {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "srcip not found"})),
            )
                .into_response();
        }
    }

    match state::apply_and_save(|policies| {
        if let Some(b) = policies.bindings.get_mut(&ip) {
            b.policy = new_policy;
            b.updated_at = Utc::now();
        }
    }) {
        Ok(new_policies) => {
            let b = new_policies.bindings.get(&ip).unwrap();
            tracing::info!(srcip = %ip, policy = %new_policy, "hash policy updated");
            Json(BindingResponse::from_binding(ip, b, true)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to save policies");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to save"})),
            )
                .into_response()
        }
    }
}

async fn reseed(Path(srcip): Path<String>) -> impl IntoResponse {
    let ip: IpAddr = match srcip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid IP address"})),
            )
                .into_response()
        }
    };

    {
        let policies = POLICIES.load();
        if !policies.bindings.contains_key(&ip) {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "srcip not found"})),
            )
                .into_response();
        }
    }

    let new_seed: u64 = rand::random();

    match state::apply_and_save(|policies| {
        if let Some(b) = policies.bindings.get_mut(&ip) {
            b.seed = new_seed;
            b.updated_at = Utc::now();
        }
    }) {
        Ok(new_policies) => {
            let b = new_policies.bindings.get(&ip).unwrap();
            tracing::info!(srcip = %ip, "seed refreshed");
            Json(BindingResponse::from_binding(ip, b, true)).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to save policies");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to save"})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use chrono::TimeZone;
    use once_cell::sync::Lazy;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::sync::Arc;

    static TEST_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

    fn set_bindings(bindings: HashMap<IpAddr, Binding>) {
        POLICIES.store(Arc::new(state::Policies {
            version: 1,
            updated_at: Utc::now(),
            bindings,
        }));
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn get_binding_returns_default_when_missing() {
        let _guard = TEST_LOCK.lock();
        set_bindings(HashMap::new());

        let response = get_binding(Path("203.0.113.10".to_string()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["srcip"], "203.0.113.10");
        assert_eq!(body["policy"], "src_ip");
        assert_eq!(body["seed"], "0x0000000000000000");
        assert_eq!(body["exists"], false);
    }

    #[tokio::test]
    async fn get_binding_marks_existing_binding() {
        let _guard = TEST_LOCK.lock();
        let ip: IpAddr = "203.0.113.20".parse().unwrap();
        let mut bindings = HashMap::new();
        bindings.insert(
            ip,
            Binding {
                policy: HashPolicy::FiveTuple,
                seed: 0x1234,
                updated_at: Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap(),
            },
        );
        set_bindings(bindings);

        let response = get_binding(Path("203.0.113.20".to_string()))
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["srcip"], "203.0.113.20");
        assert_eq!(body["policy"], "five_tuple");
        assert_eq!(body["seed"], "0x0000000000001234");
        assert_eq!(body["exists"], true);
    }
}
