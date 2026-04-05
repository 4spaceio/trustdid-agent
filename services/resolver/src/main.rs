use axum::{Router, Json, extract::Path, routing::get};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::RwLock;
use trustdid_core::*;

type Store = Arc<RwLock<std::collections::HashMap<String, DIDDocument>>>;

async fn health() -> Json<Value> {
    Json(json!({"status": "ok", "service": "trustdid-resolver", "version": "0.1.0"}))
}

async fn resolve_did(Path(did_str): Path<String>, store: axum::extract::State<Store>) -> Json<Value> {
    match DID::parse(&did_str) {
        Ok(did) => {
            let s = store.read().await;
            match s.get(&did.to_uri()) {
                Some(doc) => Json(json!({
                    "didDocument": doc,
                    "didResolutionMetadata": {"contentType": "application/did+ld+json"},
                    "didDocumentMetadata": {}
                })),
                None => Json(json!({"error": "notFound", "message": format!("DID not found: {}", did.to_uri())})),
            }
        }
        Err(e) => Json(json!({"error": "invalidDid", "message": e.to_string()})),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let store: Store = Arc::new(RwLock::new(std::collections::HashMap::new()));

    let app = Router::new()
        .route("/health", get(health))
        .route("/1.0/identifiers/{did}", get(resolve_did))
        .with_state(store);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    tracing::info!("TrustDID Resolver listening on port 3000");
    axum::serve(listener, app).await.unwrap();
}
