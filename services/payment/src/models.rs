//! Data models for the payment service.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

/// A pricing plan/tier with limits that map to TrustDID capability constraints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub price_cents: u32,
    pub price_label: String,
    pub stripe_price_id: Option<String>,
    pub did_limit: Option<u32>,
    pub delegation_depth_limit: u8,
    pub api_rate_limit: u32,
    pub didcomm_daily_limit: Option<u32>,
    pub allowed_networks: Vec<String>,
    pub allowed_agent_classes: Vec<String>,
    pub features: Vec<String>,
}

impl Plan {
    /// Developer (Free) tier.
    pub fn developer() -> Self {
        Self {
            id: "developer".into(),
            name: "Developer".into(),
            price_cents: 0,
            price_label: "Free".into(),
            stripe_price_id: None,
            did_limit: Some(5),
            delegation_depth_limit: 2,
            api_rate_limit: 60,
            didcomm_daily_limit: Some(100),
            allowed_networks: vec!["keri".into()],
            allowed_agent_classes: vec!["ephemeral".into(), "delegated".into()],
            features: vec![
                "5 active Agent DIDs".into(),
                "Delegation depth: 2".into(),
                "KERI network only".into(),
                "Issue credentials".into(),
                "100 DIDComm msgs/day".into(),
                "60 API calls/min".into(),
                "Community support".into(),
            ],
        }
    }

    /// Startup ($49/mo) tier.
    pub fn startup() -> Self {
        Self {
            id: "startup".into(),
            name: "Startup".into(),
            price_cents: 4900,
            price_label: "$49".into(),
            stripe_price_id: None, // Set via env
            did_limit: Some(100),
            delegation_depth_limit: 5,
            api_rate_limit: 600,
            didcomm_daily_limit: Some(10_000),
            allowed_networks: vec!["keri".into(), "web".into()],
            allowed_agent_classes: vec![
                "autonomous".into(),
                "delegated".into(),
                "ephemeral".into(),
                "org".into(),
                "human".into(),
            ],
            features: vec![
                "100 active Agent DIDs".into(),
                "Delegation depth: 5".into(),
                "KERI + Web networks".into(),
                "SD-JWT selective disclosure".into(),
                "10,000 DIDComm msgs/day".into(),
                "600 API calls/min".into(),
                "Email support (48h)".into(),
            ],
        }
    }

    /// Scale ($199/mo) tier.
    pub fn scale() -> Self {
        Self {
            id: "scale".into(),
            name: "Scale".into(),
            price_cents: 19900,
            price_label: "$199".into(),
            stripe_price_id: None, // Set via env
            did_limit: None, // unlimited
            delegation_depth_limit: 10,
            api_rate_limit: 6000,
            didcomm_daily_limit: Some(100_000),
            allowed_networks: vec!["keri".into(), "web".into(), "evm".into()],
            allowed_agent_classes: vec![
                "autonomous".into(),
                "delegated".into(),
                "ephemeral".into(),
                "org".into(),
                "human".into(),
            ],
            features: vec![
                "Unlimited Agent DIDs".into(),
                "Delegation depth: 10".into(),
                "All networks (KERI+Web+EVM)".into(),
                "SD-JWT + OID4VC flows".into(),
                "100,000 DIDComm msgs/day".into(),
                "6,000 API calls/min".into(),
                "Priority support (4h)".into(),
            ],
        }
    }

    /// Enterprise (custom) tier.
    pub fn enterprise() -> Self {
        Self {
            id: "enterprise".into(),
            name: "Enterprise".into(),
            price_cents: 0,
            price_label: "Custom".into(),
            stripe_price_id: None,
            did_limit: None,
            delegation_depth_limit: 10,
            api_rate_limit: 60000,
            didcomm_daily_limit: None,
            allowed_networks: vec!["keri".into(), "web".into(), "evm".into()],
            allowed_agent_classes: vec![
                "autonomous".into(),
                "delegated".into(),
                "ephemeral".into(),
                "org".into(),
                "human".into(),
            ],
            features: vec![
                "Unlimited Agent DIDs".into(),
                "Configurable delegation depth".into(),
                "All networks + custom".into(),
                "Full credential stack".into(),
                "Unlimited DIDComm msgs".into(),
                "Custom API rate limits".into(),
                "Dedicated support".into(),
            ],
        }
    }

    /// All default plans.
    pub fn all_plans() -> Vec<Self> {
        vec![
            Self::developer(),
            Self::startup(),
            Self::scale(),
            Self::enterprise(),
        ]
    }
}

// ---------------------------------------------------------------------------
// Subscription
// ---------------------------------------------------------------------------

/// Subscription status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    PastDue,
    Canceled,
    Trialing,
    Unpaid,
}

impl SubscriptionStatus {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Active => "active",
            Self::PastDue => "past_due",
            Self::Canceled => "canceled",
            Self::Trialing => "trialing",
            Self::Unpaid => "unpaid",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "active" => Self::Active,
            "past_due" => Self::PastDue,
            "canceled" => Self::Canceled,
            "trialing" => Self::Trialing,
            "unpaid" => Self::Unpaid,
            _ => Self::Active,
        }
    }
}

/// A customer subscription linking a DID to a pricing plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub customer_did: String,
    pub customer_email: String,
    pub plan_id: String,
    pub stripe_customer_id: String,
    pub stripe_subscription_id: Option<String>,
    pub status: SubscriptionStatus,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

/// Usage tracking for a subscription within the current billing period.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageRecord {
    pub subscription_id: String,
    pub dids_created: u32,
    pub api_calls_today: u32,
    pub didcomm_messages_today: u32,
    pub period_start: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Result of checking whether a DID can perform an action under their plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub allowed: bool,
    pub plan: String,
    pub reason: Option<String>,
    pub remaining_dids: Option<u32>,
}
