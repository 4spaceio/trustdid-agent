//! Capability engine for TrustDID agents.
//!
//! Handles capability parsing, subset checking, attenuation (intersection),
//! and constraint evaluation. Capabilities follow a compact format:
//! `resource:action:constraint=value,constraint=value`.

use std::collections::HashMap;
use trustdid_core::{Capability, Constraint, Result, TrustDIDError};

/// Engine for evaluating and manipulating agent capabilities.
pub struct CapabilityEngine;

impl CapabilityEngine {
    /// Check whether `child_caps` is a subset of `parent_caps`.
    ///
    /// Every capability in `child_caps` must match at least one capability in
    /// `parent_caps` with the same resource and action, and all child constraints
    /// must be present in the matching parent capability.
    pub fn is_subset(child_caps: &[Capability], parent_caps: &[Capability]) -> bool {
        child_caps.iter().all(|child| {
            parent_caps.iter().any(|parent| {
                Self::capability_matches(child, parent)
            })
        })
    }

    /// Attenuate parent capabilities to the intersection with the requested set.
    ///
    /// For each requested capability, if the parent has a matching capability
    /// (same resource and action), the result includes the capability with the
    /// union of both constraint sets (more restrictive).
    pub fn attenuate(
        parent_caps: &[Capability],
        requested_caps: &[Capability],
    ) -> Vec<Capability> {
        requested_caps
            .iter()
            .filter_map(|requested| {
                parent_caps.iter().find_map(|parent| {
                    if parent.resource == requested.resource && parent.action == requested.action {
                        Some(Self::merge_constraints(parent, requested))
                    } else {
                        None
                    }
                })
            })
            .collect()
    }

    /// Parse a capability from compact string format.
    ///
    /// Format: `resource:action` or `resource:action:key=value,key=value`
    pub fn parse_capability(compact: &str) -> Result<Capability> {
        let parts: Vec<&str> = compact.splitn(3, ':').collect();
        if parts.len() < 2 {
            return Err(TrustDIDError::CapabilityNotGranted(format!(
                "invalid capability format: '{compact}', expected 'resource:action[:constraints]'"
            )));
        }

        let resource = parts[0].to_string();
        let action = parts[1].to_string();

        if resource.is_empty() || action.is_empty() {
            return Err(TrustDIDError::CapabilityNotGranted(
                "resource and action must not be empty".to_string(),
            ));
        }

        let mut constraints = Vec::new();
        if parts.len() == 3 && !parts[2].is_empty() {
            for segment in parts[2].split(',') {
                let kv: Vec<&str> = segment.splitn(2, '=').collect();
                if kv.len() != 2 || kv[0].is_empty() || kv[1].is_empty() {
                    return Err(TrustDIDError::CapabilityNotGranted(format!(
                        "invalid constraint format: '{segment}', expected 'key=value'"
                    )));
                }
                constraints.push(Constraint::new(kv[0], kv[1]));
            }
        }

        Ok(Capability {
            resource,
            action,
            constraints,
        })
    }

    /// Check if a capability satisfies a given set of context constraints.
    ///
    /// Each constraint key in the capability must have a matching entry in the
    /// context with a value that satisfies the constraint. Currently supports
    /// exact match and numeric upper-bound comparison.
    pub fn check_constraint(cap: &Capability, context: &HashMap<String, String>) -> bool {
        cap.constraints.iter().all(|constraint| {
            match context.get(&constraint.key) {
                None => false,
                Some(ctx_value) => {
                    // Try numeric comparison first (constraint is an upper bound)
                    if let (Ok(limit), Ok(actual)) = (
                        constraint.value.parse::<f64>(),
                        ctx_value.parse::<f64>(),
                    ) {
                        actual <= limit
                    } else {
                        // Fall back to exact string match
                        ctx_value == &constraint.value
                    }
                }
            }
        })
    }

    // --- private helpers ---

    /// Check whether a child capability is covered by a parent capability.
    ///
    /// The parent must have the same resource and action, and every constraint
    /// on the child must also appear on the parent (the child may be *more*
    /// constrained, but not less).
    fn capability_matches(child: &Capability, parent: &Capability) -> bool {
        if child.resource != parent.resource || child.action != parent.action {
            return false;
        }

        // A wildcard action on the parent covers any child action
        // (already handled above since we compare exact strings).

        // Every constraint on the child must be present on the parent
        // (parent may have fewer constraints, meaning it's broader).
        // But the child must not be LESS restrictive than the parent.
        // So we check that every parent constraint appears on the child.
        parent.constraints.iter().all(|pc| {
            child.constraints.iter().any(|cc| {
                cc.key == pc.key && Self::constraint_at_most(pc, cc)
            })
        })
    }

    /// Check that `child_constraint` is at most as permissive as `parent_constraint`.
    ///
    /// For numeric values, the child's value must be <= parent's value.
    /// For non-numeric values, they must be identical.
    fn constraint_at_most(parent: &Constraint, child: &Constraint) -> bool {
        if let (Ok(p_val), Ok(c_val)) = (
            parent.value.parse::<f64>(),
            child.value.parse::<f64>(),
        ) {
            c_val <= p_val
        } else {
            child.value == parent.value
        }
    }

    /// Merge constraints from parent and requested capabilities.
    ///
    /// Takes the stricter (lower numeric / matching string) constraint when
    /// both sides specify the same key; otherwise includes all constraints
    /// from both sides.
    fn merge_constraints(parent: &Capability, requested: &Capability) -> Capability {
        let mut merged: HashMap<String, Constraint> = HashMap::new();

        // Start with parent constraints
        for c in &parent.constraints {
            merged.insert(c.key.clone(), c.clone());
        }

        // Merge requested constraints (take stricter value)
        for c in &requested.constraints {
            match merged.get(&c.key) {
                Some(existing) => {
                    if let (Ok(e_val), Ok(r_val)) = (
                        existing.value.parse::<f64>(),
                        c.value.parse::<f64>(),
                    ) {
                        // Take the lower (more restrictive) numeric limit
                        if r_val < e_val {
                            merged.insert(c.key.clone(), c.clone());
                        }
                    }
                    // For non-numeric, keep parent's constraint (stricter by default)
                }
                None => {
                    // Additional constraint from child = more restrictive
                    merged.insert(c.key.clone(), c.clone());
                }
            }
        }

        let mut constraints: Vec<Constraint> = merged.into_values().collect();
        constraints.sort_by(|a, b| a.key.cmp(&b.key));

        Capability {
            resource: parent.resource.clone(),
            action: parent.action.clone(),
            constraints,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn cap(resource: &str, action: &str) -> Capability {
        Capability::new(resource, action)
    }

    fn cap_with(resource: &str, action: &str, key: &str, value: &str) -> Capability {
        Capability::new(resource, action).with_constraint(Constraint::new(key, value))
    }

    // ---- parse_capability tests ----

    #[test]
    fn test_parse_simple_capability() {
        let c = CapabilityEngine::parse_capability("credential:issue").unwrap();
        assert_eq!(c.resource, "credential");
        assert_eq!(c.action, "issue");
        assert!(c.constraints.is_empty());
    }

    #[test]
    fn test_parse_capability_with_constraint() {
        let c = CapabilityEngine::parse_capability("payment:authorize:limit=1000").unwrap();
        assert_eq!(c.resource, "payment");
        assert_eq!(c.action, "authorize");
        assert_eq!(c.constraints.len(), 1);
        assert_eq!(c.constraints[0].key, "limit");
        assert_eq!(c.constraints[0].value, "1000");
    }

    #[test]
    fn test_parse_capability_with_multiple_constraints() {
        let c = CapabilityEngine::parse_capability("api:call:rate=100,region=us").unwrap();
        assert_eq!(c.constraints.len(), 2);
        assert_eq!(c.constraints[0].key, "rate");
        assert_eq!(c.constraints[0].value, "100");
        assert_eq!(c.constraints[1].key, "region");
        assert_eq!(c.constraints[1].value, "us");
    }

    #[test]
    fn test_parse_capability_invalid_format() {
        assert!(CapabilityEngine::parse_capability("onlyone").is_err());
    }

    #[test]
    fn test_parse_capability_empty_resource() {
        assert!(CapabilityEngine::parse_capability(":action").is_err());
    }

    #[test]
    fn test_parse_capability_empty_action() {
        assert!(CapabilityEngine::parse_capability("resource:").is_err());
    }

    #[test]
    fn test_parse_capability_bad_constraint() {
        assert!(CapabilityEngine::parse_capability("r:a:noequals").is_err());
    }

    #[test]
    fn test_parse_roundtrip() {
        let original = cap_with("payment", "authorize", "limit", "5000");
        let compact = original.to_compact();
        let parsed = CapabilityEngine::parse_capability(&compact).unwrap();
        assert_eq!(parsed.resource, original.resource);
        assert_eq!(parsed.action, original.action);
        assert_eq!(parsed.constraints, original.constraints);
    }

    // ---- is_subset tests ----

    #[test]
    fn test_subset_simple_match() {
        let parent = vec![cap("credential", "issue"), cap("payment", "authorize")];
        let child = vec![cap("credential", "issue")];
        assert!(CapabilityEngine::is_subset(&child, &parent));
    }

    #[test]
    fn test_subset_exact_match() {
        let caps = vec![cap("credential", "issue"), cap("payment", "authorize")];
        assert!(CapabilityEngine::is_subset(&caps, &caps));
    }

    #[test]
    fn test_subset_not_subset() {
        let parent = vec![cap("credential", "issue")];
        let child = vec![cap("credential", "issue"), cap("payment", "authorize")];
        assert!(!CapabilityEngine::is_subset(&child, &parent));
    }

    #[test]
    fn test_subset_empty_child() {
        let parent = vec![cap("credential", "issue")];
        assert!(CapabilityEngine::is_subset(&[], &parent));
    }

    #[test]
    fn test_subset_empty_parent() {
        let child = vec![cap("credential", "issue")];
        assert!(!CapabilityEngine::is_subset(&child, &[]));
    }

    #[test]
    fn test_subset_with_stricter_constraint() {
        let parent = vec![cap_with("payment", "authorize", "limit", "1000")];
        let child = vec![cap_with("payment", "authorize", "limit", "500")];
        assert!(CapabilityEngine::is_subset(&child, &parent));
    }

    #[test]
    fn test_subset_with_looser_constraint_fails() {
        let parent = vec![cap_with("payment", "authorize", "limit", "500")];
        let child = vec![cap_with("payment", "authorize", "limit", "1000")];
        assert!(!CapabilityEngine::is_subset(&child, &parent));
    }

    #[test]
    fn test_subset_child_with_extra_constraint() {
        // Child has an additional constraint the parent doesn't -> child is more restrictive -> OK
        let parent = vec![cap("credential", "issue")];
        let child = vec![cap_with("credential", "issue", "schema", "diploma")];
        assert!(CapabilityEngine::is_subset(&child, &parent));
    }

    // ---- attenuate tests ----

    #[test]
    fn test_attenuate_basic() {
        let parent = vec![cap("credential", "issue"), cap("payment", "authorize")];
        let requested = vec![cap("credential", "issue")];
        let result = CapabilityEngine::attenuate(&parent, &requested);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].resource, "credential");
    }

    #[test]
    fn test_attenuate_no_match() {
        let parent = vec![cap("credential", "issue")];
        let requested = vec![cap("payment", "authorize")];
        let result = CapabilityEngine::attenuate(&parent, &requested);
        assert!(result.is_empty());
    }

    #[test]
    fn test_attenuate_merges_constraints() {
        let parent = vec![cap_with("payment", "authorize", "limit", "1000")];
        let requested = vec![cap_with("payment", "authorize", "limit", "500")];
        let result = CapabilityEngine::attenuate(&parent, &requested);
        assert_eq!(result.len(), 1);
        // Should take the stricter (lower) limit
        assert_eq!(result[0].constraints[0].value, "500");
    }

    #[test]
    fn test_attenuate_adds_child_constraint() {
        let parent = vec![cap("credential", "issue")];
        let requested = vec![cap_with("credential", "issue", "schema", "diploma")];
        let result = CapabilityEngine::attenuate(&parent, &requested);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].constraints.len(), 1);
        assert_eq!(result[0].constraints[0].key, "schema");
    }

    // ---- check_constraint tests ----

    #[test]
    fn test_check_constraint_numeric_within_limit() {
        let c = cap_with("payment", "authorize", "limit", "1000");
        let mut ctx = HashMap::new();
        ctx.insert("limit".to_string(), "500".to_string());
        assert!(CapabilityEngine::check_constraint(&c, &ctx));
    }

    #[test]
    fn test_check_constraint_numeric_at_limit() {
        let c = cap_with("payment", "authorize", "limit", "1000");
        let mut ctx = HashMap::new();
        ctx.insert("limit".to_string(), "1000".to_string());
        assert!(CapabilityEngine::check_constraint(&c, &ctx));
    }

    #[test]
    fn test_check_constraint_numeric_exceeds_limit() {
        let c = cap_with("payment", "authorize", "limit", "1000");
        let mut ctx = HashMap::new();
        ctx.insert("limit".to_string(), "1500".to_string());
        assert!(!CapabilityEngine::check_constraint(&c, &ctx));
    }

    #[test]
    fn test_check_constraint_string_match() {
        let c = cap_with("credential", "issue", "schema", "diploma");
        let mut ctx = HashMap::new();
        ctx.insert("schema".to_string(), "diploma".to_string());
        assert!(CapabilityEngine::check_constraint(&c, &ctx));
    }

    #[test]
    fn test_check_constraint_string_mismatch() {
        let c = cap_with("credential", "issue", "schema", "diploma");
        let mut ctx = HashMap::new();
        ctx.insert("schema".to_string(), "certificate".to_string());
        assert!(!CapabilityEngine::check_constraint(&c, &ctx));
    }

    #[test]
    fn test_check_constraint_missing_context_key() {
        let c = cap_with("payment", "authorize", "limit", "1000");
        let ctx = HashMap::new();
        assert!(!CapabilityEngine::check_constraint(&c, &ctx));
    }

    #[test]
    fn test_check_constraint_no_constraints() {
        let c = cap("credential", "issue");
        let ctx = HashMap::new();
        assert!(CapabilityEngine::check_constraint(&c, &ctx));
    }

    #[test]
    fn test_check_constraint_multiple() {
        let c = Capability::new("api", "call")
            .with_constraint(Constraint::new("rate", "100"))
            .with_constraint(Constraint::new("region", "us"));
        let mut ctx = HashMap::new();
        ctx.insert("rate".to_string(), "50".to_string());
        ctx.insert("region".to_string(), "us".to_string());
        assert!(CapabilityEngine::check_constraint(&c, &ctx));
    }

    #[test]
    fn test_check_constraint_multiple_one_fails() {
        let c = Capability::new("api", "call")
            .with_constraint(Constraint::new("rate", "100"))
            .with_constraint(Constraint::new("region", "us"));
        let mut ctx = HashMap::new();
        ctx.insert("rate".to_string(), "50".to_string());
        ctx.insert("region".to_string(), "eu".to_string());
        assert!(!CapabilityEngine::check_constraint(&c, &ctx));
    }
}
