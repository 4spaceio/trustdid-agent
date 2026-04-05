use axum::{
    Json, Router,
    extract::{Path, State},
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
use uuid::Uuid;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

/// Per-recipient mailbox: a list of DIDComm envelopes (raw JSON values).
type MessageStore = Arc<RwLock<HashMap<String, Vec<StoredMessage>>>>;

/// A stored message awaiting pickup.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredMessage {
    /// Server-assigned message ID.
    id: String,
    /// The full DIDComm envelope as received.
    envelope: Value,
    /// When the message was accepted by the mediator.
    received_at: chrono::DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct AcceptedResponse {
    status: &'static str,
    message_id: String,
    received_at: chrono::DateTime<Utc>,
}

#[derive(Serialize)]
struct PickupResponse {
    recipient: String,
    messages: Vec<StoredMessage>,
    count: usize,
}

#[derive(Serialize)]
struct MediatorStatus {
    service: &'static str,
    version: &'static str,
    pending_messages: usize,
    connected_agents: usize,
    timestamp: chrono::DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /health` -- basic liveness probe.
async fn health() -> Json<Value> {
    Json(json!({
        "status": "ok",
        "service": "trustdid-mediator",
        "version": "0.1.0"
    }))
}

/// `POST /didcomm` -- accept a DIDComm envelope and store for recipient.
async fn accept_didcomm(
    State(store): State<MessageStore>,
    Json(body): Json<Value>,
) -> impl IntoResponse {
    // Try to extract recipient DID from the envelope.
    let recipient_did = extract_recipient(&body);

    let recipient_did = match recipient_did {
        Some(did) => did,
        None => {
            let err = json!({
                "error": "badRequest",
                "message": "Cannot determine recipient DID: envelope must contain 'to' (array) or 'recipient' (string)"
            });
            return (StatusCode::BAD_REQUEST, Json(err));
        }
    };

    let now = Utc::now();
    let message_id = Uuid::new_v4().to_string();

    let stored = StoredMessage {
        id: message_id.clone(),
        envelope: body,
        received_at: now,
    };

    {
        let mut s = store.write().await;
        s.entry(recipient_did.clone())
            .or_default()
            .push(stored);
    }

    tracing::info!(
        recipient = %recipient_did,
        message_id = %message_id,
        "DIDComm envelope accepted"
    );

    let resp = AcceptedResponse {
        status: "accepted",
        message_id,
        received_at: now,
    };
    (StatusCode::ACCEPTED, Json(json!(resp)))
}

/// `GET /pickup/{recipient_did}` -- retrieve and drain pending messages.
async fn pickup_messages(
    State(store): State<MessageStore>,
    Path(recipient_did): Path<String>,
) -> Json<Value> {
    let messages = {
        let mut s = store.write().await;
        s.remove(&recipient_did).unwrap_or_default()
    };

    let count = messages.len();
    tracing::info!(
        recipient = %recipient_did,
        count = count,
        "Messages picked up"
    );

    let resp = PickupResponse {
        recipient: recipient_did,
        messages,
        count,
    };
    Json(json!(resp))
}

/// `GET /status` -- mediator operational status.
async fn status(State(store): State<MessageStore>) -> Json<Value> {
    let s = store.read().await;
    let connected_agents = s.len();
    let pending_messages: usize = s.values().map(|v| v.len()).sum();

    let resp = MediatorStatus {
        service: "trustdid-mediator",
        version: "0.1.0",
        pending_messages,
        connected_agents,
        timestamp: Utc::now(),
    };
    Json(json!(resp))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract recipient DID from a DIDComm envelope.
///
/// Looks for `to[0]` first, then `recipient`.
fn extract_recipient(envelope: &Value) -> Option<String> {
    // DIDComm v2: "to" is an array of DIDs.
    if let Some(to_array) = envelope.get("to").and_then(|v| v.as_array()) {
        if let Some(first) = to_array.first().and_then(|v| v.as_str()) {
            return Some(first.to_string());
        }
    }
    // Fallback: "recipient" as a single string.
    if let Some(recipient) = envelope.get("recipient").and_then(|v| v.as_str()) {
        return Some(recipient.to_string());
    }
    None
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let store: MessageStore = Arc::new(RwLock::new(HashMap::new()));

    let app = Router::new()
        .route("/health", get(health))
        .route("/didcomm", post(accept_didcomm))
        .route("/pickup/{recipient_did}", get(pickup_messages))
        .route("/status", get(status))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(store);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3002").await.unwrap();
    tracing::info!("TrustDID Mediator listening on port 3002");
    axum::serve(listener, app).await.unwrap();
}
