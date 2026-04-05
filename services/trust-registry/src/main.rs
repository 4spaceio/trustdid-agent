//! TrustDID Trust Registry -- HTTP service for ecosystem and participant management.
//!
//! Endpoints:
//! - `GET  /health`                          -- health check
//! - `POST /ecosystems`                      -- create ecosystem
//! - `GET  /ecosystems/{id}`                 -- get ecosystem
//! - `POST /ecosystems/{id}/participants`    -- register participant
//! - `GET  /ecosystems/{id}/participants/{did}` -- check participant
//! - `POST /ecosystems/{id}/query`           -- execute TRQP query

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
use trustdid_trust::{
    ParticipantRole, ParticipantStatus, TrustQuery, TrustQueryResult, TrustRegistry, TrustScorer,
    execute_query,
};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

/// Shared state accessible from every handler via Axum's `State` extractor.
#[derive(Clone)]
#[allow(dead_code)]
struct AppState {
    registry: TrustRegistry,
    scorer: TrustScorer,
}

// ---------------------------------------------------------------------------
// Request / response bodies
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateEcosystemRequest {
    name: String,
    description: String,
    #[serde(default)]
    governance_url: String,
}

#[derive(Deserialize)]
struct RegisterParticipantRequest {
    did: String,
    #[serde(default)]
    roles: Vec<ParticipantRole>,
}

#[derive(Deserialize)]
struct QueryRequest {
    #[serde(default)]
    subject_did: Option<String>,
    #[serde(default)]
    role: Option<ParticipantRole>,
    #[serde(default)]
    status: Option<ParticipantStatus>,
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
        service: "trustdid-trust-registry",
    })
}

async fn create_ecosystem(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateEcosystemRequest>,
) -> impl IntoResponse {
    match state
        .registry
        .create_ecosystem(&req.name, &req.description, &req.governance_url)
        .await
    {
        Ok(ecosystem) => (
            StatusCode::CREATED,
            Json(serde_json::to_value(ecosystem).unwrap()),
        ),
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ErrorResponse {
                error: e.to_string(),
            }).unwrap()),
        ),
    }
}

async fn get_ecosystem(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.registry.get_ecosystem(&id).await {
        Some(ecosystem) => (
            StatusCode::OK,
            Json(serde_json::to_value(ecosystem).unwrap()),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ErrorResponse {
                error: format!("ecosystem '{id}' not found"),
            }).unwrap()),
        ),
    }
}

async fn register_participant(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<RegisterParticipantRequest>,
) -> impl IntoResponse {
    match state
        .registry
        .register_participant(&id, &req.did, req.roles, ParticipantStatus::Active)
        .await
    {
        Ok(()) => {
            // Fetch the just-created record to return it.
            let record = state.registry.check_participant(&id, &req.did).await;
            match record {
                Some(r) => (
                    StatusCode::CREATED,
                    Json(serde_json::to_value(r).unwrap()),
                ),
                None => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::to_value(ErrorResponse {
                        error: "participant registered but could not be retrieved".to_string(),
                    }).unwrap()),
                ),
            }
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::to_value(ErrorResponse {
                error: e.to_string(),
            }).unwrap()),
        ),
    }
}

async fn check_participant(
    State(state): State<Arc<AppState>>,
    Path((id, did)): Path<(String, String)>,
) -> impl IntoResponse {
    match state.registry.check_participant(&id, &did).await {
        Some(record) => (StatusCode::OK, Json(serde_json::to_value(record).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ErrorResponse {
                error: format!("participant '{did}' not found in ecosystem '{id}'"),
            }).unwrap()),
        ),
    }
}

async fn query_ecosystem(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<QueryRequest>,
) -> impl IntoResponse {
    let query = TrustQuery {
        ecosystem_id: id,
        subject_did: req.subject_did,
        role: req.role,
        status: req.status,
    };

    let result: TrustQueryResult = execute_query(&state.registry, &query).await;

    (StatusCode::OK, Json(serde_json::to_value(result).unwrap()))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let registry = TrustRegistry::new();
    let scorer = TrustScorer::new();

    let state = Arc::new(AppState { registry, scorer });

    let app = Router::new()
        .route("/health", get(health))
        .route("/ecosystems", post(create_ecosystem))
        .route("/ecosystems/{id}", get(get_ecosystem))
        .route("/ecosystems/{id}/participants", post(register_participant))
        .route(
            "/ecosystems/{id}/participants/{did}",
            get(check_participant),
        )
        .route("/ecosystems/{id}/query", post(query_ecosystem))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = "0.0.0.0:3003";
    info!("trustdid-trust-registry listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
