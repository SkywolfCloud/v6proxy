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
         v6proxy_bindings_total {}\n\
         # HELP v6proxy_domain_blocked_total Connections dropped by the domain ACL\n\
         # TYPE v6proxy_domain_blocked_total counter\n\
         v6proxy_domain_blocked_total {}\n\
         # HELP v6proxy_egress_blocked_total Connections dropped by the egress filter\n\
         # TYPE v6proxy_egress_blocked_total counter\n\
         v6proxy_egress_blocked_total {}\n",
        policies.bindings.len(),
        crate::acl::DOMAIN_BLOCKED.load(std::sync::atomic::Ordering::Relaxed),
        crate::acl::EGRESS_BLOCKED.load(std::sync::atomic::Ordering::Relaxed),
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

// ---------------------------------------------------------------------------
// ACL admin API (/v1/domains and /v1/egress share one code path).
// ---------------------------------------------------------------------------

/// Routes for both ACLs, mounted under the authenticated tier.
pub fn acl_router() -> Router {
    Router::new()
        .route("/v1/domains", get(get_domains))
        .route(
            "/v1/domains/allow",
            post(post_domains_allow).delete(delete_domains_allow),
        )
        .route(
            "/v1/domains/deny",
            post(post_domains_deny).delete(delete_domains_deny),
        )
        .route("/v1/egress", get(get_egress))
        .route(
            "/v1/egress/allow",
            post(post_egress_allow).delete(delete_egress_allow),
        )
        .route(
            "/v1/egress/deny",
            post(post_egress_deny).delete(delete_egress_deny),
        )
}

#[derive(Deserialize)]
pub struct RulesBody {
    rules: Vec<String>,
}

#[derive(Serialize)]
struct AclListView {
    base: Vec<String>,
    add: Vec<String>,
    del: Vec<String>,
    effective: Vec<String>,
}

#[derive(Serialize)]
struct AclView {
    allow: AclListView,
    deny: AclListView,
}

#[derive(Clone, Copy)]
enum AclList {
    Allow,
    Deny,
}

#[derive(Clone, Copy)]
enum AclOp {
    Add,
    Del,
}

/// Static description of one ACL (domain or egress): how to validate a rule,
/// read its config base, select its overlay in `Policies`, rebuild its filter,
/// and render its view.
#[derive(Clone, Copy)]
struct AclKind {
    canonicalize: fn(&str) -> anyhow::Result<String>,
    base: fn() -> (Vec<String>, Vec<String>),
    select: fn(&mut state::Policies) -> &mut state::AclDelta,
    rebuild: fn(),
    view: fn() -> AclView,
}

fn select_domain(p: &mut state::Policies) -> &mut state::AclDelta {
    &mut p.domain_acl
}

fn select_egress(p: &mut state::Policies) -> &mut state::AclDelta {
    &mut p.egress_acl
}

fn domain_kind() -> AclKind {
    AclKind {
        canonicalize: crate::acl::canonicalize_rule,
        base: crate::acl::domain_base,
        select: select_domain,
        rebuild: crate::acl::rebuild_domain_filter,
        view: domain_view,
    }
}

fn egress_kind() -> AclKind {
    AclKind {
        canonicalize: crate::config::canonicalize_net,
        base: crate::acl::egress_base,
        select: select_egress,
        rebuild: crate::acl::rebuild_egress_filter,
        view: egress_view,
    }
}

/// Build a base / add / del / effective view for one ACL.
fn acl_view(base: (Vec<String>, Vec<String>), delta: &state::AclDelta) -> AclView {
    let (base_allow, base_deny) = base;
    AclView {
        allow: AclListView {
            effective: delta.effective_allow(&base_allow),
            add: delta.allow_add.clone(),
            del: delta.allow_del.clone(),
            base: base_allow,
        },
        deny: AclListView {
            effective: delta.effective_deny(&base_deny),
            add: delta.deny_add.clone(),
            del: delta.deny_del.clone(),
            base: base_deny,
        },
    }
}

fn domain_view() -> AclView {
    acl_view(crate::acl::domain_base(), &POLICIES.load().domain_acl)
}

fn egress_view() -> AclView {
    acl_view(crate::acl::egress_base(), &POLICIES.load().egress_acl)
}

pub async fn get_domains() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::to_value(domain_view()).unwrap()),
    )
}

pub async fn get_egress() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::to_value(egress_view()).unwrap()),
    )
}

/// Validate the batch, apply it to the chosen runtime overlay, persist, and
/// hot-swap the compiled filter. The config base is never modified.
fn mutate_acl(
    list: AclList,
    op: AclOp,
    rules: Vec<String>,
    kind: &AclKind,
) -> axum::response::Response {
    // Validate + canonicalize the whole batch up front; reject all on any error.
    let mut canon = Vec::with_capacity(rules.len());
    for r in &rules {
        match (kind.canonicalize)(r) {
            Ok(c) => canon.push(c),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": format!("invalid rule {:?}: {}", r, e)})),
                )
                    .into_response();
            }
        }
    }

    let (base_allow, base_deny) = (kind.base)();
    let result = state::apply_and_save(|p| {
        let delta = (kind.select)(p);
        for r in &canon {
            match (list, op) {
                (AclList::Allow, AclOp::Add) => delta.add_allow(&base_allow, r),
                (AclList::Allow, AclOp::Del) => delta.del_allow(&base_allow, r),
                (AclList::Deny, AclOp::Add) => delta.add_deny(&base_deny, r),
                (AclList::Deny, AclOp::Del) => delta.del_deny(&base_deny, r),
            }
        }
    });

    match result {
        Ok(_) => {
            (kind.rebuild)();
            (
                StatusCode::OK,
                Json(serde_json::to_value((kind.view)()).unwrap()),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to save ACL");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to save"})),
            )
                .into_response()
        }
    }
}

pub async fn post_domains_allow(Json(body): Json<RulesBody>) -> impl IntoResponse {
    mutate_acl(AclList::Allow, AclOp::Add, body.rules, &domain_kind())
}

pub async fn delete_domains_allow(Json(body): Json<RulesBody>) -> impl IntoResponse {
    mutate_acl(AclList::Allow, AclOp::Del, body.rules, &domain_kind())
}

pub async fn post_domains_deny(Json(body): Json<RulesBody>) -> impl IntoResponse {
    mutate_acl(AclList::Deny, AclOp::Add, body.rules, &domain_kind())
}

pub async fn delete_domains_deny(Json(body): Json<RulesBody>) -> impl IntoResponse {
    mutate_acl(AclList::Deny, AclOp::Del, body.rules, &domain_kind())
}

pub async fn post_egress_allow(Json(body): Json<RulesBody>) -> impl IntoResponse {
    mutate_acl(AclList::Allow, AclOp::Add, body.rules, &egress_kind())
}

pub async fn delete_egress_allow(Json(body): Json<RulesBody>) -> impl IntoResponse {
    mutate_acl(AclList::Allow, AclOp::Del, body.rules, &egress_kind())
}

pub async fn post_egress_deny(Json(body): Json<RulesBody>) -> impl IntoResponse {
    mutate_acl(AclList::Deny, AclOp::Add, body.rules, &egress_kind())
}

pub async fn delete_egress_deny(Json(body): Json<RulesBody>) -> impl IntoResponse {
    mutate_acl(AclList::Deny, AclOp::Del, body.rules, &egress_kind())
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
            ..Default::default()
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

    /// Initialize the process-global state path + domain base once, so the
    /// mutation handlers can persist + rebuild during tests.
    fn ensure_acl_test_env() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let p =
                std::env::temp_dir().join(format!("v6proxy-acl-test-{}.json", std::process::id()));
            state::init_state_path(p);
            crate::acl::init_domain_filter(Vec::new(), Vec::new());
            crate::acl::init_egress_filter(Vec::new(), Vec::new());
        });
    }

    #[tokio::test]
    async fn get_domains_reports_overlay() {
        let _guard = TEST_LOCK.lock();
        let mut p = state::Policies::default();
        p.domain_acl.deny_add.push("domain:bad.com".to_string());
        POLICIES.store(Arc::new(p));

        let response = get_domains().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response_json(response).await;
        assert_eq!(body["deny"]["add"][0], "domain:bad.com");
        assert_eq!(body["deny"]["effective"][0], "domain:bad.com");
    }

    #[tokio::test]
    async fn post_domains_rejects_invalid_rule() {
        let _guard = TEST_LOCK.lock();
        let body = RulesBody {
            rules: vec!["regexp:nope".to_string()],
        };
        let response = post_domains_allow(Json(body)).await.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn post_domains_allow_adds_and_activates_whitelist() {
        let _guard = TEST_LOCK.lock();
        ensure_acl_test_env();
        POLICIES.store(Arc::new(state::Policies::default()));

        let body = RulesBody {
            rules: vec!["Bad.COM".to_string()],
        };
        let response = post_domains_allow(Json(body)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        // Input is canonicalized before storage.
        assert_eq!(json["allow"]["effective"][0], "domain:bad.com");

        // allow is now non-empty -> whitelist mode is active in the live filter.
        assert!(crate::acl::DOMAIN_FILTER.load().is_allowed("bad.com"));
        assert!(!crate::acl::DOMAIN_FILTER.load().is_allowed("good.com"));
    }

    #[tokio::test]
    async fn post_egress_deny_adds_and_blocks_range() {
        let _guard = TEST_LOCK.lock();
        ensure_acl_test_env();
        POLICIES.store(Arc::new(state::Policies::default()));

        let body = RulesBody {
            rules: vec!["2606:4700:4700::/48".to_string()],
        };
        let response = post_egress_deny(Json(body)).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        assert_eq!(json["deny"]["effective"][0], "2606:4700:4700::/48");

        // The live egress filter now blocks that range but allows other public IPv6.
        let f = crate::acl::EGRESS_FILTER.load();
        assert!(!f.is_allowed("2606:4700:4700::1111".parse().unwrap()));
        assert!(f.is_allowed("2001:4860:4860::8888".parse().unwrap()));
    }
}
