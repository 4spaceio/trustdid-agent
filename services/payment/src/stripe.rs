//! Stripe API client -- direct HTTP calls to `api.stripe.com/v1/`.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

/// Minimal Stripe API client.
#[derive(Clone)]
pub struct StripeClient {
    http: Client,
    secret_key: String,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CheckoutSession {
    pub id: String,
    pub url: Option<String>,
    pub customer: Option<String>,
    pub subscription: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct PortalSession {
    pub id: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub status: String,
    pub customer: String,
    pub metadata: Option<serde_json::Value>,
    pub items: Option<SubscriptionItems>,
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionItems {
    pub data: Vec<SubscriptionItem>,
}

#[derive(Debug, Deserialize)]
pub struct SubscriptionItem {
    pub price: Option<PriceInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PriceInfo {
    pub id: String,
}

/// Stripe event from webhooks.
#[derive(Debug, Deserialize)]
pub struct StripeEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: EventData,
}

#[derive(Debug, Deserialize)]
pub struct EventData {
    pub object: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateCheckoutRequest {
    pub plan_id: String,
    pub customer_email: String,
    pub customer_did: String,
    pub success_url: String,
    pub cancel_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePortalRequest {
    pub customer_did: String,
    pub return_url: String,
}

// ---------------------------------------------------------------------------
// Client implementation
// ---------------------------------------------------------------------------

impl StripeClient {
    pub fn new(secret_key: String) -> Self {
        Self {
            http: Client::new(),
            secret_key,
        }
    }

    /// Create a Stripe Checkout Session for a subscription.
    pub async fn create_checkout_session(
        &self,
        price_id: &str,
        customer_email: &str,
        customer_did: &str,
        success_url: &str,
        cancel_url: &str,
    ) -> Result<CheckoutSession, String> {
        let params = [
            ("mode", "subscription"),
            ("payment_method_types[0]", "card"),
            ("line_items[0][price]", price_id),
            ("line_items[0][quantity]", "1"),
            ("customer_email", customer_email),
            ("success_url", success_url),
            ("cancel_url", cancel_url),
            ("metadata[customer_did]", customer_did),
        ];

        let resp = self
            .http
            .post("https://api.stripe.com/v1/checkout/sessions")
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Stripe request failed: {e}"))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            error!("Stripe checkout session error ({status}): {body}");
            return Err(format!("Stripe error ({status}): {body}"));
        }

        info!("Stripe checkout session created");
        serde_json::from_str(&body).map_err(|e| format!("Failed to parse Stripe response: {e}"))
    }

    /// Create a Stripe Customer Portal session for plan management.
    pub async fn create_portal_session(
        &self,
        stripe_customer_id: &str,
        return_url: &str,
    ) -> Result<PortalSession, String> {
        let params = [
            ("customer", stripe_customer_id),
            ("return_url", return_url),
        ];

        let resp = self
            .http
            .post("https://api.stripe.com/v1/billing_portal/sessions")
            .basic_auth(&self.secret_key, None::<&str>)
            .form(&params)
            .send()
            .await
            .map_err(|e| format!("Stripe request failed: {e}"))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            error!("Stripe portal session error ({status}): {body}");
            return Err(format!("Stripe error ({status}): {body}"));
        }

        serde_json::from_str(&body).map_err(|e| format!("Failed to parse Stripe response: {e}"))
    }

    /// Retrieve a Stripe Subscription.
    pub async fn get_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<StripeSubscription, String> {
        let resp = self
            .http
            .get(format!(
                "https://api.stripe.com/v1/subscriptions/{subscription_id}"
            ))
            .basic_auth(&self.secret_key, None::<&str>)
            .send()
            .await
            .map_err(|e| format!("Stripe request failed: {e}"))?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();

        if !status.is_success() {
            return Err(format!("Stripe error ({status}): {body}"));
        }

        serde_json::from_str(&body).map_err(|e| format!("Failed to parse: {e}"))
    }
}
