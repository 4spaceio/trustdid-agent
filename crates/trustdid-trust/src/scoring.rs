//! Trust Scoring Engine.
//!
//! Computes a trust score (in basis points, 0-10 000) for any DID based on:
//!
//! * **Delegation depth** -- closer to a trust root scores higher.
//! * **Endorsement count** -- more endorsements from reputable DIDs boost the
//!   score.
//! * **Identity age** -- longer-lived identities receive a maturity bonus.
//! * **Behaviour score** -- an externally supplied reputation signal.
//!
//! Endorsements are stored in-memory and feed into `calculate_score`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum score in basis points (100.00 %).
const MAX_SCORE: u16 = 10_000;

/// Maximum weight an endorsement can carry (basis points).
const MAX_ENDORSEMENT_WEIGHT: u16 = 10_000;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum ScoringError {
    #[error("self-endorsement is not allowed")]
    SelfEndorsement,

    #[error("endorsement weight must be 1..={MAX_ENDORSEMENT_WEIGHT}")]
    InvalidWeight,

    #[error("duplicate endorsement from {endorser} to {target}")]
    DuplicateEndorsement { endorser: String, target: String },
}

pub type Result<T> = std::result::Result<T, ScoringError>;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// A trust score for a DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustScore {
    /// Score in basis points (0 = untrusted, 10 000 = fully trusted).
    pub score: u16,
    /// Number of endorsements received.
    pub endorsements: u32,
    /// When the score was last evaluated.
    pub last_evaluated: DateTime<Utc>,
}

/// An endorsement from one DID to another.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Endorsement {
    /// DID of the endorser.
    pub endorser_did: String,
    /// DID of the entity being endorsed.
    pub target_did: String,
    /// Weight of the endorsement in basis points (1..=10 000).
    pub weight: u16,
    /// When the endorsement was created.
    pub created_at: DateTime<Utc>,
}

/// Externally supplied input factors for score calculation.
#[derive(Debug, Clone)]
pub struct ScoreFactors {
    /// Delegation depth: 0 = trust root, higher = further from root.
    pub delegation_depth: u8,
    /// Age of the identity in days.
    pub identity_age_days: u32,
    /// Externally assigned behaviour score (0..=10 000 basis points).
    pub behavior_score: u16,
}

impl Default for ScoreFactors {
    fn default() -> Self {
        Self {
            delegation_depth: 0,
            identity_age_days: 0,
            behavior_score: 5_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal storage
// ---------------------------------------------------------------------------

/// Per-DID data stored in the scorer.
#[derive(Debug, Clone)]
struct DidEntry {
    factors: ScoreFactors,
    endorsements_received: Vec<Endorsement>,
}

// ---------------------------------------------------------------------------
// TrustScorer
// ---------------------------------------------------------------------------

/// In-memory trust scoring engine.
#[derive(Debug, Clone)]
pub struct TrustScorer {
    store: Arc<RwLock<HashMap<String, DidEntry>>>,
}

impl TrustScorer {
    /// Create a new, empty scorer.
    pub fn new() -> Self {
        Self {
            store: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Set (or overwrite) the external scoring factors for a DID.
    pub async fn set_factors(&self, did: impl Into<String>, factors: ScoreFactors) {
        let did = did.into();
        let mut store = self.store.write().await;
        let entry = store.entry(did).or_insert_with(|| DidEntry {
            factors: ScoreFactors::default(),
            endorsements_received: Vec::new(),
        });
        entry.factors = factors;
    }

    /// Record an endorsement from `endorser_did` to `target_did`.
    pub async fn endorse(
        &self,
        endorser_did: impl Into<String>,
        target_did: impl Into<String>,
        weight: u16,
    ) -> Result<()> {
        let endorser_did = endorser_did.into();
        let target_did = target_did.into();

        if endorser_did == target_did {
            return Err(ScoringError::SelfEndorsement);
        }
        if weight == 0 || weight > MAX_ENDORSEMENT_WEIGHT {
            return Err(ScoringError::InvalidWeight);
        }

        let mut store = self.store.write().await;
        let entry = store.entry(target_did.clone()).or_insert_with(|| DidEntry {
            factors: ScoreFactors::default(),
            endorsements_received: Vec::new(),
        });

        // Prevent duplicate endorsement from the same endorser.
        if entry
            .endorsements_received
            .iter()
            .any(|e| e.endorser_did == endorser_did)
        {
            return Err(ScoringError::DuplicateEndorsement {
                endorser: endorser_did,
                target: target_did,
            });
        }

        entry.endorsements_received.push(Endorsement {
            endorser_did,
            target_did,
            weight,
            created_at: Utc::now(),
        });

        Ok(())
    }

    /// Calculate the trust score for a DID.
    ///
    /// Scoring formula (all weights add up to 10 000 basis points):
    ///
    /// | Component        | Max bps | Description                             |
    /// |------------------|---------|-----------------------------------------|
    /// | delegation_depth | 3 000   | `3000 * (1 - depth / 10)`, cap at 10   |
    /// | endorsements     | 3 000   | `3000 * min(count, 20) / 20`            |
    /// | identity_age     | 1 500   | `1500 * min(days, 365) / 365`           |
    /// | behavior         | 2 500   | `2500 * behavior_score / 10000`         |
    pub async fn calculate_score(&self, did: &str) -> TrustScore {
        let store = self.store.read().await;
        let entry = store.get(did);

        let (factors, endorsement_count) = match entry {
            Some(e) => (&e.factors, e.endorsements_received.len() as u32),
            None => {
                return TrustScore {
                    score: 0,
                    endorsements: 0,
                    last_evaluated: Utc::now(),
                };
            }
        };

        let depth_score = {
            let capped_depth = factors.delegation_depth.min(10) as u32;
            (3_000u32 * (10 - capped_depth) / 10) as u16
        };

        let endorsement_score = {
            let capped = endorsement_count.min(20);
            (3_000u32 * capped / 20) as u16
        };

        let age_score = {
            let capped_days = factors.identity_age_days.min(365);
            (1_500u32 * capped_days / 365) as u16
        };

        let behavior_score = {
            let capped = factors.behavior_score.min(MAX_SCORE) as u32;
            (2_500u32 * capped / MAX_SCORE as u32) as u16
        };

        let total = (depth_score + endorsement_score + age_score + behavior_score).min(MAX_SCORE);

        TrustScore {
            score: total,
            endorsements: endorsement_count,
            last_evaluated: Utc::now(),
        }
    }

    /// Retrieve the cached score for a DID (re-calculates on the fly).
    pub async fn get_score(&self, did: &str) -> Option<TrustScore> {
        let store = self.store.read().await;
        if store.contains_key(did) {
            drop(store); // Release read lock before calling calculate.
            Some(self.calculate_score(did).await)
        } else {
            None
        }
    }

    /// Return all endorsements that a DID has received.
    pub async fn get_endorsements(&self, did: &str) -> Vec<Endorsement> {
        let store = self.store.read().await;
        store
            .get(did)
            .map(|e| e.endorsements_received.clone())
            .unwrap_or_default()
    }

    /// Returns `true` if the DID's score meets the given minimum threshold.
    pub async fn meets_threshold(&self, did: &str, min_score: u16) -> bool {
        let score = self.calculate_score(did).await;
        score.score >= min_score
    }
}

impl Default for TrustScorer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn test_unknown_did_scores_zero() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let score = scorer.calculate_score("did:unknown:abc").await;
            assert_eq!(score.score, 0);
            assert_eq!(score.endorsements, 0);
        });
    }

    #[test]
    fn test_trust_root_max_depth_score() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let did = "did:trustagent:keri:autonomous:z6MkRoot";
            scorer
                .set_factors(
                    did,
                    ScoreFactors {
                        delegation_depth: 0, // trust root
                        identity_age_days: 0,
                        behavior_score: 0,
                    },
                )
                .await;

            let score = scorer.calculate_score(did).await;
            // depth component alone: 3000 * (10-0)/10 = 3000
            assert_eq!(score.score, 3_000);
        });
    }

    #[test]
    fn test_delegation_depth_reduces_score() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let did = "did:trustagent:keri:delegated:z6MkDeep";
            scorer
                .set_factors(
                    did,
                    ScoreFactors {
                        delegation_depth: 5,
                        identity_age_days: 0,
                        behavior_score: 0,
                    },
                )
                .await;

            let score = scorer.calculate_score(did).await;
            // 3000 * (10-5)/10 = 1500
            assert_eq!(score.score, 1_500);
        });
    }

    #[test]
    fn test_max_depth_gives_zero_depth_component() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let did = "did:trustagent:keri:delegated:z6MkMaxDepth";
            scorer
                .set_factors(
                    did,
                    ScoreFactors {
                        delegation_depth: 10,
                        identity_age_days: 0,
                        behavior_score: 0,
                    },
                )
                .await;

            let score = scorer.calculate_score(did).await;
            assert_eq!(score.score, 0);
        });
    }

    #[test]
    fn test_endorsements_increase_score() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let target = "did:trustagent:keri:autonomous:z6MkTarget";
            scorer
                .set_factors(
                    target,
                    ScoreFactors {
                        delegation_depth: 10, // zero depth component
                        identity_age_days: 0,
                        behavior_score: 0,
                    },
                )
                .await;

            // Add 10 endorsements.
            for i in 0..10 {
                let endorser = format!("did:trustagent:keri:autonomous:z6MkE{i}");
                scorer.endorse(&endorser, target, 5_000).await.unwrap();
            }

            let score = scorer.calculate_score(target).await;
            // 3000 * 10/20 = 1500
            assert_eq!(score.score, 1_500);
            assert_eq!(score.endorsements, 10);
        });
    }

    #[test]
    fn test_endorsements_cap_at_20() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let target = "did:trustagent:keri:autonomous:z6MkCap";
            scorer
                .set_factors(
                    target,
                    ScoreFactors {
                        delegation_depth: 10,
                        identity_age_days: 0,
                        behavior_score: 0,
                    },
                )
                .await;

            for i in 0..25 {
                let endorser = format!("did:trustagent:keri:autonomous:z6MkCE{i}");
                scorer.endorse(&endorser, target, 5_000).await.unwrap();
            }

            let score = scorer.calculate_score(target).await;
            // capped at 20: 3000 * 20/20 = 3000
            assert_eq!(score.score, 3_000);
            assert_eq!(score.endorsements, 25); // raw count not capped
        });
    }

    #[test]
    fn test_identity_age_component() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let did = "did:trustagent:keri:autonomous:z6MkAge";
            scorer
                .set_factors(
                    did,
                    ScoreFactors {
                        delegation_depth: 10,
                        identity_age_days: 365,
                        behavior_score: 0,
                    },
                )
                .await;

            let score = scorer.calculate_score(did).await;
            // 1500 * 365/365 = 1500
            assert_eq!(score.score, 1_500);
        });
    }

    #[test]
    fn test_behavior_component() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let did = "did:trustagent:keri:autonomous:z6MkBehav";
            scorer
                .set_factors(
                    did,
                    ScoreFactors {
                        delegation_depth: 10,
                        identity_age_days: 0,
                        behavior_score: 10_000, // max
                    },
                )
                .await;

            let score = scorer.calculate_score(did).await;
            // 2500 * 10000/10000 = 2500
            assert_eq!(score.score, 2_500);
        });
    }

    #[test]
    fn test_full_perfect_score() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let target = "did:trustagent:keri:autonomous:z6MkPerfect";
            scorer
                .set_factors(
                    target,
                    ScoreFactors {
                        delegation_depth: 0,    // 3000
                        identity_age_days: 365, // 1500
                        behavior_score: 10_000, // 2500
                    },
                )
                .await;

            for i in 0..20 {
                let endorser = format!("did:trustagent:keri:autonomous:z6MkPE{i}");
                scorer.endorse(&endorser, target, 5_000).await.unwrap();
            }

            let score = scorer.calculate_score(target).await;
            // 3000 + 3000 + 1500 + 2500 = 10000
            assert_eq!(score.score, 10_000);
        });
    }

    #[test]
    fn test_self_endorsement_rejected() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let did = "did:trustagent:keri:autonomous:z6MkSelf";
            let res = scorer.endorse(did, did, 5_000).await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_duplicate_endorsement_rejected() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let endorser = "did:trustagent:keri:autonomous:z6MkE1";
            let target = "did:trustagent:keri:autonomous:z6MkT1";

            scorer.endorse(endorser, target, 5_000).await.unwrap();
            let res = scorer.endorse(endorser, target, 5_000).await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_invalid_weight_zero() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let res = scorer
                .endorse(
                    "did:trustagent:keri:autonomous:z6MkA",
                    "did:trustagent:keri:autonomous:z6MkB",
                    0,
                )
                .await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_invalid_weight_too_high() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let res = scorer
                .endorse(
                    "did:trustagent:keri:autonomous:z6MkA",
                    "did:trustagent:keri:autonomous:z6MkB",
                    10_001,
                )
                .await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_get_endorsements() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let target = "did:trustagent:keri:autonomous:z6MkGetEnd";
            let endorser1 = "did:trustagent:keri:autonomous:z6MkGE1";
            let endorser2 = "did:trustagent:keri:autonomous:z6MkGE2";

            scorer.endorse(endorser1, target, 8_000).await.unwrap();
            scorer.endorse(endorser2, target, 3_000).await.unwrap();

            let endorsements = scorer.get_endorsements(target).await;
            assert_eq!(endorsements.len(), 2);
            assert_eq!(endorsements[0].endorser_did, endorser1);
            assert_eq!(endorsements[0].weight, 8_000);
            assert_eq!(endorsements[1].endorser_did, endorser2);
            assert_eq!(endorsements[1].weight, 3_000);
        });
    }

    #[test]
    fn test_get_endorsements_empty() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let endorsements = scorer
                .get_endorsements("did:trustagent:keri:autonomous:z6MkNone")
                .await;
            assert!(endorsements.is_empty());
        });
    }

    #[test]
    fn test_meets_threshold() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let did = "did:trustagent:keri:autonomous:z6MkThresh";
            scorer
                .set_factors(
                    did,
                    ScoreFactors {
                        delegation_depth: 0,    // 3000
                        identity_age_days: 365, // 1500
                        behavior_score: 10_000, // 2500
                    },
                )
                .await;

            // Score = 7000 (no endorsements)
            assert!(scorer.meets_threshold(did, 7_000).await);
            assert!(scorer.meets_threshold(did, 5_000).await);
            assert!(!scorer.meets_threshold(did, 7_001).await);
        });
    }

    #[test]
    fn test_unknown_did_fails_threshold() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            assert!(!scorer.meets_threshold("did:unknown:xyz", 1).await);
        });
    }

    #[test]
    fn test_get_score_existing() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let did = "did:trustagent:keri:autonomous:z6MkGetS";
            scorer
                .set_factors(did, ScoreFactors::default())
                .await;

            let score = scorer.get_score(did).await;
            assert!(score.is_some());
        });
    }

    #[test]
    fn test_get_score_nonexistent() {
        runtime().block_on(async {
            let scorer = TrustScorer::new();
            let score = scorer
                .get_score("did:trustagent:keri:autonomous:z6MkNoExist")
                .await;
            assert!(score.is_none());
        });
    }

    #[test]
    fn test_score_serialization() {
        let ts = TrustScore {
            score: 7_500,
            endorsements: 12,
            last_evaluated: Utc::now(),
        };
        let json = serde_json::to_string(&ts).unwrap();
        let parsed: TrustScore = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.score, 7_500);
        assert_eq!(parsed.endorsements, 12);
    }

    #[test]
    fn test_endorsement_serialization() {
        let e = Endorsement {
            endorser_did: "did:trustagent:keri:autonomous:z6MkA".to_string(),
            target_did: "did:trustagent:keri:autonomous:z6MkB".to_string(),
            weight: 5_000,
            created_at: Utc::now(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let parsed: Endorsement = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.endorser_did, e.endorser_did);
        assert_eq!(parsed.weight, 5_000);
    }
}
