//! Credential schema definitions for TrustDID Agent credentials.

use serde::{Deserialize, Serialize};
use serde_json::json;

/// Pre-defined schema types for agent credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentCredentialType {
    Delegation,
    Capability,
    TrustScore,
    Identity,
}

impl AgentCredentialType {
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Delegation => "AgentDelegationCredential",
            Self::Capability => "AgentCapabilityCredential",
            Self::TrustScore => "AgentTrustScoreCredential",
            Self::Identity => "AgentIdentityCredential",
        }
    }

    pub fn schema(&self) -> serde_json::Value {
        match self {
            Self::Delegation => json!({
                "$id": "https://trustdid.org/schemas/delegation/v1",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["capabilities", "delegationDepth", "maxDepth"],
                "properties": {
                    "capabilities": { "type": "array", "items": { "type": "string" } },
                    "delegationDepth": { "type": "integer", "minimum": 0 },
                    "maxDepth": { "type": "integer", "minimum": 1, "maximum": 10 },
                    "delegationType": { "type": "string", "enum": ["capability", "identity", "full"] }
                }
            }),
            Self::Capability => json!({
                "$id": "https://trustdid.org/schemas/capability/v1",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["capabilities"],
                "properties": {
                    "capabilities": { "type": "array", "items": { "type": "string" } },
                    "grantedAt": { "type": "string", "format": "date-time" },
                    "expiresAt": { "type": "string", "format": "date-time" }
                }
            }),
            Self::TrustScore => json!({
                "$id": "https://trustdid.org/schemas/trust-score/v1",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["trustScore", "endorsements"],
                "properties": {
                    "trustScore": { "type": "integer", "minimum": 0, "maximum": 10000 },
                    "endorsements": { "type": "integer", "minimum": 0 },
                    "behaviorHash": { "type": "string" },
                    "evaluatedAt": { "type": "string", "format": "date-time" }
                }
            }),
            Self::Identity => json!({
                "$id": "https://trustdid.org/schemas/identity/v1",
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["agentClass", "lifecycle"],
                "properties": {
                    "agentClass": { "type": "string", "enum": ["autonomous", "delegated", "ephemeral", "org", "human"] },
                    "lifecycle": { "type": "string" },
                    "parentDID": { "type": "string" },
                    "model": { "type": "string" },
                    "version": { "type": "string" }
                }
            }),
        }
    }
}

/// Schema registry for looking up credential schemas.
#[derive(Debug, Default)]
pub struct SchemaRegistry {
    custom: std::collections::HashMap<String, serde_json::Value>,
}

impl SchemaRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, schema_id: impl Into<String>, schema: serde_json::Value) {
        self.custom.insert(schema_id.into(), schema);
    }

    pub fn get(&self, schema_id: &str) -> Option<serde_json::Value> {
        // Check built-in schemas first
        for t in [
            AgentCredentialType::Delegation,
            AgentCredentialType::Capability,
            AgentCredentialType::TrustScore,
            AgentCredentialType::Identity,
        ] {
            let schema = t.schema();
            if schema.get("$id").and_then(|v| v.as_str()) == Some(schema_id) {
                return Some(schema);
            }
        }
        self.custom.get(schema_id).cloned()
    }
}
