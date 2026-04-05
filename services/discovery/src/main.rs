use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use trustdid_core::DID;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A registered agent in the discovery directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentDiscoveryRecord {
    did: String,
    agent_class: String,
    capabilities: Vec<String>,
    trust_score: u16,
    service_endpoints: Vec<String>,
    registered_at: chrono::DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

type AgentRegistry = Arc<RwLock<HashMap<String, AgentDiscoveryRecord>>>;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RegisterAgentRequest {
    did: String,
    agent_class: String,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    trust_score: u16,
    #[serde(default)]
    service_endpoints: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchParams {
    capability: Option<String>,
    min_trust: Option<u16>,
    agent_class: Option<String>,
}

#[derive(Serialize)]
struct VerificationReport {
    did: String,
    did_valid: bool,
    did_parse_error: Option<String>,
    registered: bool,
    agent_class: Option<String>,
    trust_score: Option<u16>,
    delegation_depth: Option<u8>,
    capabilities: Vec<String>,
    verified_at: chrono::DateTime<Utc>,
    overall_status: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /health` -- liveness probe.
async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "trustdid-discovery",
        "version": "0.1.0"
    }))
}

/// `POST /agents/register` -- register an agent for discovery.
async fn register_agent(
    State(registry): State<AgentRegistry>,
    Json(req): Json<RegisterAgentRequest>,
) -> impl IntoResponse {
    // Validate the DID syntax.
    if let Err(e) = DID::parse(&req.did) {
        let err = json!({
            "error": "invalidDid",
            "message": e.to_string()
        });
        return (StatusCode::BAD_REQUEST, Json(err));
    }

    let record = AgentDiscoveryRecord {
        did: req.did.clone(),
        agent_class: req.agent_class,
        capabilities: req.capabilities,
        trust_score: req.trust_score,
        service_endpoints: req.service_endpoints,
        registered_at: Utc::now(),
    };

    let did_key = req.did.clone();
    {
        let mut reg = registry.write().await;
        reg.insert(did_key.clone(), record.clone());
    }

    tracing::info!(did = %did_key, "Agent registered for discovery");

    let resp = json!({
        "status": "registered",
        "did": did_key,
        "registeredAt": record.registered_at,
    });
    (StatusCode::CREATED, Json(resp))
}

/// `GET /agents` -- search agents with optional filters.
async fn search_agents(
    State(registry): State<AgentRegistry>,
    Query(params): Query<SearchParams>,
) -> Json<Value> {
    let reg = registry.read().await;

    let results: Vec<&AgentDiscoveryRecord> = reg
        .values()
        .filter(|record| {
            // Filter by capability (substring match on compact capability strings).
            if let Some(ref cap) = params.capability {
                if !record.capabilities.iter().any(|c| c.contains(cap.as_str())) {
                    return false;
                }
            }
            // Filter by minimum trust score (basis points).
            if let Some(min_trust) = params.min_trust {
                if record.trust_score < min_trust {
                    return false;
                }
            }
            // Filter by agent class.
            if let Some(ref agent_class) = params.agent_class {
                if record.agent_class != *agent_class {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = results.len();
    Json(json!({
        "agents": results,
        "total": total,
    }))
}

/// `GET /agents/{did}` -- look up a single agent's discovery record.
async fn get_agent(
    State(registry): State<AgentRegistry>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    let reg = registry.read().await;
    match reg.get(&did) {
        Some(record) => (StatusCode::OK, Json(json!(record))),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "notFound",
                "message": format!("Agent not found: {did}")
            })),
        ),
    }
}

/// `GET /agents/{did}/capabilities` -- list an agent's capabilities.
async fn get_agent_capabilities(
    State(registry): State<AgentRegistry>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    let reg = registry.read().await;
    match reg.get(&did) {
        Some(record) => (
            StatusCode::OK,
            Json(json!({
                "did": did,
                "capabilities": record.capabilities,
                "count": record.capabilities.len(),
            })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "notFound",
                "message": format!("Agent not found: {did}")
            })),
        ),
    }
}

/// `POST /agents/{did}/verify` -- verify an agent (DID resolution + trust).
async fn verify_agent(
    State(registry): State<AgentRegistry>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    let now = Utc::now();

    // Step 1: Validate DID syntax.
    let (did_valid, did_parse_error, parsed_did) = match DID::parse(&did) {
        Ok(parsed) => (true, None, Some(parsed)),
        Err(e) => (false, Some(e.to_string()), None),
    };

    // Step 2: Check registration in discovery registry.
    let reg = registry.read().await;
    let record = reg.get(&did);

    let (registered, agent_class, trust_score, capabilities) = match record {
        Some(r) => (
            true,
            Some(r.agent_class.clone()),
            Some(r.trust_score),
            r.capabilities.clone(),
        ),
        None => (false, None, None, Vec::new()),
    };

    // Step 3: Extract delegation depth from parsed DID if available.
    let delegation_depth = parsed_did.as_ref().and_then(|d| {
        match d.agent_class {
            trustdid_core::AgentClass::Delegated => Some(1u8), // default assumption
            trustdid_core::AgentClass::Autonomous => Some(0u8),
            _ => None,
        }
    });

    // Step 4: Determine overall status.
    let overall_status = if !did_valid {
        "invalid_did".to_string()
    } else if !registered {
        "unregistered".to_string()
    } else if trust_score.unwrap_or(0) == 0 {
        "untrusted".to_string()
    } else {
        "verified".to_string()
    };

    let report = VerificationReport {
        did: did.clone(),
        did_valid,
        did_parse_error,
        registered,
        agent_class,
        trust_score,
        delegation_depth,
        capabilities,
        verified_at: now,
        overall_status,
    };

    (StatusCode::OK, Json(json!(report)))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let registry: AgentRegistry = Arc::new(RwLock::new(HashMap::new()));

    let app = Router::new()
        .route("/health", get(health))
        .route("/agents/register", post(register_agent))
        .route("/agents", get(search_agents))
        .route("/agents/{did}", get(get_agent))
        .route("/agents/{did}/capabilities", get(get_agent_capabilities))
        .route("/agents/{did}/verify", post(verify_agent))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(registry);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3004").await.unwrap();
    tracing::info!("TrustDID Discovery listening on port 3004");
    axum::serve(listener, app).await.unwrap();
}
