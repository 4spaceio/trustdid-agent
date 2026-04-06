//! Axum HTTP handlers for the payment service.

use std::sync::Arc;

use axum::{
    Json,
    body::Bytes,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::db::Database;
use crate::models::{Plan, Subscription, SubscriptionStatus, ValidationResult};
use crate::stripe::{CreateCheckoutRequest, CreatePortalRequest, StripeClient};
use crate::webhook;

/// Shared application state.
pub struct AppState {
    pub db: Database,
    pub stripe: StripeClient,
    pub webhook_secret: String,
    /// Map plan_id -> stripe_price_id (set from env).
    pub price_map: std::collections::HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Common types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
}

#[derive(Deserialize)]
pub struct ValidateQuery {
    pub action: Option<String>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// GET /health
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        service: "trustdid-payment",
    })
}

/// GET /billing/plans
pub async fn list_plans(State(state): State<Arc<AppState>>) -> Json<Vec<Plan>> {
    Json(state.db.list_plans())
}

/// GET /billing/plans/:id
pub async fn get_plan(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state.db.get_plan(&id) {
        Some(plan) => (StatusCode::OK, Json(serde_json::to_value(plan).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ErrorResponse {
                error: format!("Plan '{id}' not found"),
            }).unwrap()),
        ),
    }
}

/// POST /billing/checkout-session
pub async fn create_checkout_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCheckoutRequest>,
) -> impl IntoResponse {
    // Look up the Stripe price ID for this plan.
    let price_id = match state.price_map.get(&req.plan_id) {
        Some(pid) => pid.clone(),
        None => {
            // For free tier, no Stripe checkout needed.
            if req.plan_id == "developer" {
                // Auto-create a free subscription.
                let now = Utc::now();
                let sub = Subscription {
                    id: Uuid::new_v4().to_string(),
                    customer_did: req.customer_did.clone(),
                    customer_email: req.customer_email.clone(),
                    plan_id: "developer".into(),
                    stripe_customer_id: format!("free_{}", Uuid::new_v4()),
                    stripe_subscription_id: None,
                    status: SubscriptionStatus::Active,
                    current_period_start: now,
                    current_period_end: now + Duration::days(36500), // ~100 years
                    created_at: now,
                    updated_at: now,
                };
                state.db.create_subscription(&sub);
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "plan": "developer",
                        "status": "active",
                        "message": "Free tier activated. No payment required."
                    })),
                );
            }
            // Enterprise = contact sales
            if req.plan_id == "enterprise" {
                return (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "plan": "enterprise",
                        "message": "Contact sales@trustdid.org for enterprise pricing."
                    })),
                );
            }
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!(ErrorResponse {
                    error: format!("No Stripe price configured for plan '{}'", req.plan_id),
                })),
            );
        }
    };

    // Create Stripe Checkout Session.
    match state
        .stripe
        .create_checkout_session(
            &price_id,
            &req.customer_email,
            &req.customer_did,
            &req.success_url,
            &req.cancel_url,
        )
        .await
    {
        Ok(session) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "checkout_url": session.url,
                "session_id": session.id,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::to_value(ErrorResponse { error: e }).unwrap()),
        ),
    }
}

/// GET /billing/subscription/:did
pub async fn get_subscription(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    match state.db.get_subscription_by_did(&did) {
        Some(sub) => (StatusCode::OK, Json(serde_json::to_value(sub).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ErrorResponse {
                error: format!("No subscription found for DID '{did}'"),
            }).unwrap()),
        ),
    }
}

/// GET /billing/usage/:did
pub async fn get_usage(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    let sub = match state.db.get_subscription_by_did(&did) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::to_value(ErrorResponse {
                    error: format!("No subscription for DID '{did}'"),
                }).unwrap()),
            );
        }
    };

    match state.db.get_usage(&sub.id) {
        Some(usage) => (StatusCode::OK, Json(serde_json::to_value(usage).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::to_value(ErrorResponse {
                error: "No usage record found".into(),
            }).unwrap()),
        ),
    }
}

/// POST /billing/portal-session
pub async fn create_portal_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreatePortalRequest>,
) -> impl IntoResponse {
    let sub = match state.db.get_subscription_by_did(&req.customer_did) {
        Some(s) => s,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::to_value(ErrorResponse {
                    error: "No subscription found".into(),
                }).unwrap()),
            );
        }
    };

    match state
        .stripe
        .create_portal_session(&sub.stripe_customer_id, &req.return_url)
        .await
    {
        Ok(session) => (
            StatusCode::OK,
            Json(serde_json::json!({ "portal_url": session.url })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::to_value(ErrorResponse { error: e }).unwrap()),
        ),
    }
}

/// GET /billing/validate/:did?action=create
pub async fn validate(
    State(state): State<Arc<AppState>>,
    Path(did): Path<String>,
    Query(query): Query<ValidateQuery>,
) -> Json<ValidationResult> {
    let action = query.action.as_deref().unwrap_or("create");
    Json(state.db.validate(&did, action))
}

/// POST /webhooks/stripe
pub async fn stripe_webhook(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let payload = match std::str::from_utf8(&body) {
        Ok(p) => p,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "Invalid UTF-8 body");
        }
    };

    // Extract Stripe-Signature header.
    let sig = match headers.get("stripe-signature").and_then(|v| v.to_str().ok()) {
        Some(s) => s,
        None => {
            return (StatusCode::BAD_REQUEST, "Missing Stripe-Signature header");
        }
    };

    // Verify signature.
    if let Err(e) = webhook::verify_signature(payload, sig, &state.webhook_secret) {
        error!("Webhook signature verification failed: {e}");
        return (StatusCode::UNAUTHORIZED, "Invalid signature");
    }

    // Parse and dispatch event.
    let event = match webhook::parse_event(payload) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to parse webhook event: {e}");
            return (StatusCode::BAD_REQUEST, "Invalid event payload");
        }
    };

    let action = webhook::dispatch_event(&event);
    handle_webhook_action(&state, action);

    (StatusCode::OK, "ok")
}

/// Process a webhook action by updating the database.
fn handle_webhook_action(state: &AppState, action: webhook::EventAction) {
    match action {
        webhook::EventAction::CheckoutCompleted {
            customer_id,
            subscription_id,
            customer_email,
            customer_did,
        } => {
            if customer_did.is_empty() {
                warn!("Checkout completed but no customer_did in metadata");
                return;
            }
            info!("Creating subscription for DID: {customer_did}");

            // Determine plan from Stripe price (default to startup).
            let plan_id = determine_plan_from_subscription(&state.price_map, &subscription_id);

            let now = Utc::now();
            let sub = Subscription {
                id: Uuid::new_v4().to_string(),
                customer_did,
                customer_email,
                plan_id,
                stripe_customer_id: customer_id,
                stripe_subscription_id: Some(subscription_id),
                status: SubscriptionStatus::Active,
                current_period_start: now,
                current_period_end: now + Duration::days(30),
                created_at: now,
                updated_at: now,
            };
            state.db.create_subscription(&sub);
        }
        webhook::EventAction::SubscriptionUpdated {
            subscription_id,
            status,
        } => {
            let st = crate::models::SubscriptionStatus::from_str(&status);
            state
                .db
                .update_subscription_status(&subscription_id, &st, None);
        }
        webhook::EventAction::SubscriptionDeleted { subscription_id } => {
            state.db.update_subscription_status(
                &subscription_id,
                &SubscriptionStatus::Canceled,
                Some("developer"), // Downgrade to free
            );
        }
        webhook::EventAction::PaymentFailed { subscription_id } => {
            state.db.update_subscription_status(
                &subscription_id,
                &SubscriptionStatus::PastDue,
                None,
            );
        }
        webhook::EventAction::InvoicePaid { subscription_id } => {
            state.db.update_subscription_status(
                &subscription_id,
                &SubscriptionStatus::Active,
                None,
            );
        }
        webhook::EventAction::Ignored => {}
    }
}

/// Determine plan ID from price map (reverse lookup).
fn determine_plan_from_subscription(
    price_map: &std::collections::HashMap<String, String>,
    _subscription_id: &str,
) -> String {
    // In a real implementation we'd look up the subscription in Stripe
    // to get the price ID, then reverse-lookup the plan. For MVP, default
    // to "startup" since that's the most common paid plan.
    // The webhook metadata approach (set on checkout) is more reliable.
    "startup".into()
}
