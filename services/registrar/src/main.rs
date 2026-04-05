//! TrustDID Universal Registrar -- HTTP service for agent lifecycle management.
//!
//! Endpoints:
//! - `GET  /health`             -- health check
//! - `POST /1.0/create`         -- create an agent DID
//! - `POST /1.0/delegate`       -- create a delegation
//! - `POST /1.0/decommission`   -- decommission an agent
//! - `GET  /1.0/agents/{did}`   -- look up an agent record

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::info;
use trustdid_agent::{AgentManager, AgentRecord, DelegationManager, DelegationRecord};
use trustdid_core::{AgentClass, Capability};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Shared state accessible from every handler via Axum's `State` extractor.
#[derive(Clone)]
struct AppState {
    agent_mgr: AgentManager,
    delegation_mgr: DelegationManager,
}

// ---------------------------------------------------------------------------
// Request / response bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateRequest {
    agent_class: AgentClass,
    parent_did: Option<String>,
    #[serde(default)]
    capabilities: Vec<Capability>,
}

#[derive(Deserialize)]
struct DelegateRequest {
    parent_did: String,
    child_did: String,
    child_class: AgentClass,
    #[serde(default)]
    capabilities: Vec<Capability>,
    #[serde(default = "default_max_depth")]
    max_depth: u8,
}

fn default_max_depth() -> u8 {
    5
}

#[derive(Deserialize)]
struct DecommissionRequest {
    did: String,
    #[serde(default)]
    cascade: bool,
}

#[derive(Serialize)]
struct CreateResponse {
    did: String,
    agent: AgentRecord,
}

#[derive(Serialize)]
struct DelegateResponse {
    delegation: DelegationRecord,
}

#[derive(Serialize)]
struct DecommissionResponse {
    decommissioned_agents: Vec<String>,
    revoked_delegations: Vec<String>,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    service: &'static str,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "trustdid-registrar",
    })
}

async fn create_agent(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRequest>,
) -> impl IntoResponse {
    match state
        .agent_mgr
        .create(req.agent_class, req.parent_did, req.capabilities)
        .await
    {
        Ok(record) => {
            let did = record.did.clone();
            (
                StatusCode::CREATED,
                Json(serde_json::to_value(CreateResponse {
                    did,
                    agent: record,
                }).unwrap()),
            )
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ErrorResponse {
                error: e.to_string(),
            }).unwrap()),
        ),
    }
}

async fn delegate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DelegateRequest>,
) -> impl IntoResponse {
    match state
        .delegation_mgr
        .delegate(
            &req.parent_did,
            &req.child_did,
            req.child_class,
            req.capabilities,
            req.max_depth,
        )
        .await
    {
        Ok(record) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(DelegateResponse {
                delegation: record,
            }).unwrap()),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ErrorResponse {
                error: e.to_string(),
            }).unwrap()),
        ),
    }
}

async fn decommission(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DecommissionRequest>,
) -> impl IntoResponse {
    match state.agent_mgr.decommission(&req.did, req.cascade).await {
        Ok(result) => (
            StatusCode::OK,
            Json(serde_json::to_value(DecommissionResponse {
                decommissioned_agents: result.decommissioned_agents,
                revoked_delegations: result.revoked_delegations,
            }).unwrap()),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ErrorResponse {
                error: e.to_string(),
            }).unwrap()),
        ),
    }
}

async fn get_agent(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    match state.agent_mgr.get(&did).await {
        Some(record) => (StatusCode::OK, Json(serde_json::to_value(record).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ErrorResponse {
                error: format!("agent '{did}' not found"),
            }).unwrap()),
        ),
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let delegation_mgr = DelegationManager::new();
    let agent_mgr = AgentManager::new(delegation_mgr.clone());

    let state = Arc::new(AppState {
        agent_mgr,
        delegation_mgr,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/1.0/create", post(create_agent))
        .route("/1.0/delegate", post(delegate))
        .route("/1.0/decommission", post(decommission))
        .route("/1.0/agents/{did}", get(get_agent))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = "0.0.0.0:3001";
    info!("trustdid-registrar listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
