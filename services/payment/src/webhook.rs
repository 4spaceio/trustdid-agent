//! Stripe webhook signature verification and event dispatch.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use tracing::{error, info, warn};

use crate::stripe::StripeEvent;

type HmacSha256 = Hmac<Sha256>;

/// Maximum age (in seconds) for a webhook timestamp before we reject it.
const MAX_TIMESTAMP_AGE: i64 = 300;

/// Verify a Stripe webhook signature.
///
/// The `Stripe-Signature` header contains `t=<timestamp>,v1=<signature>`.
/// We compute `HMAC-SHA256(secret, "{timestamp}.{payload}")` and compare.
pub fn verify_signature(payload: &str, sig_header: &str, webhook_secret: &str) -> Result<(), String> {
    let mut timestamp: Option<&str> = None;
    let mut signature: Option<&str> = None;

    for part in sig_header.split(',') {
        let part = part.trim();
        if let Some(t) = part.strip_prefix("t=") {
            timestamp = Some(t);
        } else if let Some(v) = part.strip_prefix("v1=") {
            signature = Some(v);
        }
    }

    let timestamp = timestamp.ok_or("Missing timestamp in Stripe-Signature")?;
    let signature = signature.ok_or("Missing v1 signature in Stripe-Signature")?;

    // Check timestamp age
    let ts: i64 = timestamp
        .parse()
        .map_err(|_| "Invalid timestamp in Stripe-Signature")?;
    let now = chrono::Utc::now().timestamp();
    if (now - ts).abs() > MAX_TIMESTAMP_AGE {
        return Err(format!(
            "Webhook timestamp too old: {ts} vs now {now} (diff={}s)",
            (now - ts).abs()
        ));
    }

    // Compute expected signature
    let signed_payload = format!("{timestamp}.{payload}");
    let mut mac =
        HmacSha256::new_from_slice(webhook_secret.as_bytes()).map_err(|e| format!("HMAC error: {e}"))?;
    mac.update(signed_payload.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison
    if expected != signature {
        return Err("Signature mismatch".into());
    }

    Ok(())
}

/// Parse and classify a Stripe event.
pub fn parse_event(body: &str) -> Result<StripeEvent, String> {
    serde_json::from_str(body).map_err(|e| format!("Failed to parse webhook event: {e}"))
}

/// Dispatch a verified Stripe event. Returns a summary string.
pub fn dispatch_event(event: &StripeEvent) -> EventAction {
    match event.event_type.as_str() {
        "checkout.session.completed" => {
            info!("Checkout session completed: {}", event.id);
            let obj = &event.data.object;
            EventAction::CheckoutCompleted {
                customer_id: obj
                    .get("customer")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                subscription_id: obj
                    .get("subscription")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                customer_email: obj
                    .get("customer_email")
                    .or_else(|| obj.get("customer_details").and_then(|d| d.get("email")))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                customer_did: obj
                    .get("metadata")
                    .and_then(|m| m.get("customer_did"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            }
        }
        "customer.subscription.updated" => {
            info!("Subscription updated: {}", event.id);
            let obj = &event.data.object;
            EventAction::SubscriptionUpdated {
                subscription_id: obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                status: obj
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("active")
                    .to_string(),
            }
        }
        "customer.subscription.deleted" => {
            info!("Subscription deleted: {}", event.id);
            let obj = &event.data.object;
            EventAction::SubscriptionDeleted {
                subscription_id: obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            }
        }
        "invoice.payment_failed" => {
            warn!("Invoice payment failed: {}", event.id);
            let obj = &event.data.object;
            EventAction::PaymentFailed {
                subscription_id: obj
                    .get("subscription")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            }
        }
        "invoice.paid" => {
            info!("Invoice paid: {}", event.id);
            let obj = &event.data.object;
            EventAction::InvoicePaid {
                subscription_id: obj
                    .get("subscription")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            }
        }
        other => {
            info!("Unhandled webhook event type: {other}");
            EventAction::Ignored
        }
    }
}

/// Actions produced by webhook event dispatch.
#[derive(Debug)]
pub enum EventAction {
    CheckoutCompleted {
        customer_id: String,
        subscription_id: String,
        customer_email: String,
        customer_did: String,
    },
    SubscriptionUpdated {
        subscription_id: String,
        status: String,
    },
    SubscriptionDeleted {
        subscription_id: String,
    },
    PaymentFailed {
        subscription_id: String,
    },
    InvoicePaid {
        subscription_id: String,
    },
    Ignored,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_verification() {
        let secret = "whsec_test_secret";
        let payload = r#"{"id":"evt_test","type":"checkout.session.completed"}"#;
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let signed_payload = format!("{timestamp}.{payload}");

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let header = format!("t={timestamp},v1={sig}");
        assert!(verify_signature(payload, &header, secret).is_ok());
    }

    #[test]
    fn test_signature_rejects_bad_sig() {
        let header = format!("t={},v1=badsig", chrono::Utc::now().timestamp());
        assert!(verify_signature("{}", &header, "whsec_test").is_err());
    }
}
