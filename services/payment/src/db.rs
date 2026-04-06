//! SQLite database layer for the payment service.

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use std::sync::Mutex;

use crate::models::{Plan, Subscription, SubscriptionStatus, UsageRecord, ValidationResult};

/// Database handle wrapping a SQLite connection.
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (or create) the database at `path` and initialize the schema.
    pub fn open(path: &str) -> Self {
        let conn = if path == ":memory:" {
            Connection::open_in_memory().expect("failed to open in-memory db")
        } else {
            Connection::open(path).expect("failed to open database")
        };

        let db = Self {
            conn: Mutex::new(conn),
        };
        db.init_schema();
        db
    }

    /// Create tables if they don't exist.
    fn init_schema(&self) {
        let conn = self.conn.lock().unwrap();

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS plans (
                id              TEXT PRIMARY KEY,
                name            TEXT NOT NULL,
                price_cents     INTEGER NOT NULL,
                price_label     TEXT NOT NULL,
                stripe_price_id TEXT,
                did_limit       INTEGER,
                delegation_depth_limit INTEGER NOT NULL,
                api_rate_limit  INTEGER NOT NULL,
                didcomm_daily_limit INTEGER,
                allowed_networks    TEXT NOT NULL,
                allowed_agent_classes TEXT NOT NULL,
                features        TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS subscriptions (
                id                      TEXT PRIMARY KEY,
                customer_did            TEXT NOT NULL,
                customer_email          TEXT NOT NULL,
                plan_id                 TEXT NOT NULL,
                stripe_customer_id      TEXT NOT NULL,
                stripe_subscription_id  TEXT,
                status                  TEXT NOT NULL DEFAULT 'active',
                current_period_start    TEXT NOT NULL,
                current_period_end      TEXT NOT NULL,
                created_at              TEXT NOT NULL,
                updated_at              TEXT NOT NULL,
                FOREIGN KEY (plan_id) REFERENCES plans(id)
            );

            CREATE INDEX IF NOT EXISTS idx_sub_did ON subscriptions(customer_did);
            CREATE INDEX IF NOT EXISTS idx_sub_stripe ON subscriptions(stripe_subscription_id);

            CREATE TABLE IF NOT EXISTS usage_records (
                subscription_id     TEXT PRIMARY KEY,
                dids_created        INTEGER NOT NULL DEFAULT 0,
                api_calls_today     INTEGER NOT NULL DEFAULT 0,
                didcomm_messages_today INTEGER NOT NULL DEFAULT 0,
                period_start        TEXT NOT NULL,
                FOREIGN KEY (subscription_id) REFERENCES subscriptions(id)
            );
            ",
        )
        .expect("failed to init schema");
    }

    // -----------------------------------------------------------------------
    // Plans
    // -----------------------------------------------------------------------

    /// Seed the plans table (upsert).
    pub fn seed_plans(&self, plans: &[Plan]) {
        let conn = self.conn.lock().unwrap();
        for plan in plans {
            conn.execute(
                "INSERT OR REPLACE INTO plans
                 (id, name, price_cents, price_label, stripe_price_id,
                  did_limit, delegation_depth_limit, api_rate_limit,
                  didcomm_daily_limit, allowed_networks, allowed_agent_classes, features)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
                params![
                    plan.id,
                    plan.name,
                    plan.price_cents,
                    plan.price_label,
                    plan.stripe_price_id,
                    plan.did_limit,
                    plan.delegation_depth_limit,
                    plan.api_rate_limit,
                    plan.didcomm_daily_limit,
                    serde_json::to_string(&plan.allowed_networks).unwrap(),
                    serde_json::to_string(&plan.allowed_agent_classes).unwrap(),
                    serde_json::to_string(&plan.features).unwrap(),
                ],
            )
            .expect("failed to seed plan");
        }
    }

    /// Get all plans.
    pub fn list_plans(&self) -> Vec<Plan> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT * FROM plans ORDER BY price_cents ASC")
            .unwrap();
        stmt.query_map([], |row| {
            Ok(Plan {
                id: row.get(0)?,
                name: row.get(1)?,
                price_cents: row.get(2)?,
                price_label: row.get(3)?,
                stripe_price_id: row.get(4)?,
                did_limit: row.get(5)?,
                delegation_depth_limit: row.get(6)?,
                api_rate_limit: row.get(7)?,
                didcomm_daily_limit: row.get(8)?,
                allowed_networks: serde_json::from_str(&row.get::<_, String>(9)?).unwrap(),
                allowed_agent_classes: serde_json::from_str(&row.get::<_, String>(10)?).unwrap(),
                features: serde_json::from_str(&row.get::<_, String>(11)?).unwrap(),
            })
        })
        .unwrap()
        .filter_map(|r| r.ok())
        .collect()
    }

    /// Get one plan by ID.
    pub fn get_plan(&self, id: &str) -> Option<Plan> {
        self.list_plans().into_iter().find(|p| p.id == id)
    }

    // -----------------------------------------------------------------------
    // Subscriptions
    // -----------------------------------------------------------------------

    /// Create a new subscription.
    pub fn create_subscription(&self, sub: &Subscription) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO subscriptions
             (id, customer_did, customer_email, plan_id, stripe_customer_id,
              stripe_subscription_id, status, current_period_start,
              current_period_end, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                sub.id,
                sub.customer_did,
                sub.customer_email,
                sub.plan_id,
                sub.stripe_customer_id,
                sub.stripe_subscription_id,
                sub.status.as_str(),
                sub.current_period_start.to_rfc3339(),
                sub.current_period_end.to_rfc3339(),
                sub.created_at.to_rfc3339(),
                sub.updated_at.to_rfc3339(),
            ],
        )
        .expect("failed to create subscription");

        // Also create a usage record.
        conn.execute(
            "INSERT OR IGNORE INTO usage_records
             (subscription_id, dids_created, api_calls_today, didcomm_messages_today, period_start)
             VALUES (?1, 0, 0, 0, ?2)",
            params![sub.id, sub.current_period_start.to_rfc3339()],
        )
        .expect("failed to create usage record");
    }

    /// Find subscription by customer DID.
    pub fn get_subscription_by_did(&self, did: &str) -> Option<Subscription> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM subscriptions WHERE customer_did = ?1 ORDER BY created_at DESC LIMIT 1",
            params![did],
            |row| {
                Ok(Subscription {
                    id: row.get(0)?,
                    customer_did: row.get(1)?,
                    customer_email: row.get(2)?,
                    plan_id: row.get(3)?,
                    stripe_customer_id: row.get(4)?,
                    stripe_subscription_id: row.get(5)?,
                    status: SubscriptionStatus::from_str(&row.get::<_, String>(6)?),
                    current_period_start: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    current_period_end: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            },
        )
        .ok()
    }

    /// Find subscription by Stripe subscription ID.
    pub fn get_subscription_by_stripe_id(&self, stripe_sub_id: &str) -> Option<Subscription> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM subscriptions WHERE stripe_subscription_id = ?1",
            params![stripe_sub_id],
            |row| {
                Ok(Subscription {
                    id: row.get(0)?,
                    customer_did: row.get(1)?,
                    customer_email: row.get(2)?,
                    plan_id: row.get(3)?,
                    stripe_customer_id: row.get(4)?,
                    stripe_subscription_id: row.get(5)?,
                    status: SubscriptionStatus::from_str(&row.get::<_, String>(6)?),
                    current_period_start: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    current_period_end: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(9)?)
                        .unwrap()
                        .with_timezone(&Utc),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(10)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            },
        )
        .ok()
    }

    /// Update subscription status and plan.
    pub fn update_subscription_status(
        &self,
        stripe_sub_id: &str,
        status: &SubscriptionStatus,
        plan_id: Option<&str>,
    ) {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        if let Some(plan) = plan_id {
            conn.execute(
                "UPDATE subscriptions SET status = ?1, plan_id = ?2, updated_at = ?3
                 WHERE stripe_subscription_id = ?4",
                params![status.as_str(), plan, now, stripe_sub_id],
            )
            .ok();
        } else {
            conn.execute(
                "UPDATE subscriptions SET status = ?1, updated_at = ?2
                 WHERE stripe_subscription_id = ?3",
                params![status.as_str(), now, stripe_sub_id],
            )
            .ok();
        }
    }

    // -----------------------------------------------------------------------
    // Usage
    // -----------------------------------------------------------------------

    /// Get usage for a subscription.
    pub fn get_usage(&self, subscription_id: &str) -> Option<UsageRecord> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM usage_records WHERE subscription_id = ?1",
            params![subscription_id],
            |row| {
                Ok(UsageRecord {
                    subscription_id: row.get(0)?,
                    dids_created: row.get(1)?,
                    api_calls_today: row.get(2)?,
                    didcomm_messages_today: row.get(3)?,
                    period_start: DateTime::parse_from_rfc3339(&row.get::<_, String>(4)?)
                        .unwrap()
                        .with_timezone(&Utc),
                })
            },
        )
        .ok()
    }

    /// Increment DID creation count.
    pub fn increment_dids(&self, subscription_id: &str) {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "UPDATE usage_records SET dids_created = dids_created + 1
             WHERE subscription_id = ?1",
            params![subscription_id],
        )
        .ok();
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /// Validate whether a DID holder can perform a given action.
    pub fn validate(&self, did: &str, action: &str) -> ValidationResult {
        let sub = match self.get_subscription_by_did(did) {
            Some(s) => s,
            None => {
                // No subscription -- allow on free tier by default
                return ValidationResult {
                    allowed: true,
                    plan: "developer".into(),
                    reason: Some("No subscription found, using free tier".into()),
                    remaining_dids: Some(5),
                };
            }
        };

        if sub.status != SubscriptionStatus::Active {
            return ValidationResult {
                allowed: false,
                plan: sub.plan_id.clone(),
                reason: Some(format!("Subscription status: {}", sub.status.as_str())),
                remaining_dids: None,
            };
        }

        let plan = match self.get_plan(&sub.plan_id) {
            Some(p) => p,
            None => {
                return ValidationResult {
                    allowed: false,
                    plan: sub.plan_id,
                    reason: Some("Plan not found".into()),
                    remaining_dids: None,
                };
            }
        };

        match action {
            "create" => {
                if let Some(limit) = plan.did_limit {
                    let usage = self.get_usage(&sub.id);
                    let created = usage.map(|u| u.dids_created).unwrap_or(0);
                    if created >= limit {
                        return ValidationResult {
                            allowed: false,
                            plan: sub.plan_id,
                            reason: Some(format!(
                                "DID limit reached ({created}/{limit}). Upgrade your plan."
                            )),
                            remaining_dids: Some(0),
                        };
                    }
                    ValidationResult {
                        allowed: true,
                        plan: sub.plan_id,
                        reason: None,
                        remaining_dids: Some(limit - created),
                    }
                } else {
                    // Unlimited
                    ValidationResult {
                        allowed: true,
                        plan: sub.plan_id,
                        reason: None,
                        remaining_dids: None,
                    }
                }
            }
            "delegate" => ValidationResult {
                allowed: true,
                plan: sub.plan_id,
                reason: None,
                remaining_dids: None,
            },
            _ => ValidationResult {
                allowed: true,
                plan: sub.plan_id,
                reason: None,
                remaining_dids: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_and_list_plans() {
        let db = Database::open(":memory:");
        db.seed_plans(&Plan::all_plans());
        let plans = db.list_plans();
        assert_eq!(plans.len(), 4);
        assert_eq!(plans[0].id, "developer");
    }

    #[test]
    fn test_subscription_and_validation() {
        let db = Database::open(":memory:");
        db.seed_plans(&Plan::all_plans());

        let now = Utc::now();
        let sub = Subscription {
            id: "sub_test".into(),
            customer_did: "did:trustagent:keri:autonomous:z6MkTest".into(),
            customer_email: "test@example.com".into(),
            plan_id: "developer".into(),
            stripe_customer_id: "cus_test".into(),
            stripe_subscription_id: None,
            status: SubscriptionStatus::Active,
            current_period_start: now,
            current_period_end: now + chrono::Duration::days(30),
            created_at: now,
            updated_at: now,
        };
        db.create_subscription(&sub);

        // Should be allowed (0/5 DIDs)
        let result = db.validate(&sub.customer_did, "create");
        assert!(result.allowed);
        assert_eq!(result.remaining_dids, Some(5));

        // Simulate 5 DID creations
        for _ in 0..5 {
            db.increment_dids("sub_test");
        }

        // Should be blocked (5/5 DIDs)
        let result = db.validate(&sub.customer_did, "create");
        assert!(!result.allowed);
        assert_eq!(result.remaining_dids, Some(0));
    }
}
