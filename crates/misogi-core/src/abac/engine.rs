//! ABAC policy evaluation engine — core orchestration layer.
//!
//! Provides [`AbacEngine`], the central component that ties together attribute
//! resolution, condition evaluation, and decision production.
//!
//! # Evaluation Algorithm
//!
//! 1. Check decision cache → return if hit (within TTL)
//! 2. Sort enabled rules by priority **descending**
//! 3. For each rule: evaluate ALL conditions (**AND** logic)
//!    - Deny match → **RETURN Deny immediately** (short-circuit)
//!    - Permit match → record obligation, continue scanning
//! 4. Finalize: any Deny → Deny; else if Permit → Permit (+ obligation); else → `default_effect`
//! 5. Cache decision and return
//!
//! # Safety Properties
//!
//! - **Deny precedence**: Matching Deny overrides all matched Permits.
//! - **Fail-closed**: Evaluation errors cause conditions to fail → rule does not match.
//! - **Immutable during evaluation**: Rules are read-only during `evaluate()`.

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;
use std::time::{Duration, Instant};

use super::attribute::AbacValue;
use super::config::AbacConfig;
use super::decision::AbacDecision;
use super::evaluator::ConditionEvaluator;
use super::policy::{AbacPolicyRule, Obligation, PolicyEffect};

// ===========================================================================
// AbacEngine
// ===========================================================================

/// Core ABAC policy evaluation engine.
///
/// Orchestrates the complete access control decision pipeline: receives resolved
/// attributes, evaluates rules in priority order, produces structured decisions,
/// and caches results for performance.
///
/// Concurrency: uses `RwLock` for internal state; concurrent reads allowed without blocking.
pub struct AbacEngine {
    /// Policy rules (sorted at eval time by priority DESC).
    rules: Vec<AbacPolicyRule>,
    /// Default effect when no rule matches.
    default_effect: PolicyEffect,
    /// Stateless condition evaluator.
    #[allow(dead_code)]
    evaluator: ConditionEvaluator,
    /// Decision cache: hash → (decision, insertion_time).
    cache: RwLock<HashMap<u64, (AbacDecision, Instant)>>,
    /// Cache TTL. Zero disables caching.
    cache_ttl: Duration,
}

impl AbacEngine {
    /// Constructs a new engine with explicit parameters.
    pub fn new(
        rules: Vec<AbacPolicyRule>,
        default_effect: PolicyEffect,
        cache_ttl_secs: u64,
    ) -> Self {
        Self {
            rules,
            default_effect,
            evaluator: ConditionEvaluator,
            cache: RwLock::new(HashMap::new()),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
        }
    }

    /// Constructs an engine from an [`AbacConfig`] configuration object.
    ///
    /// Extracts `rules`, `default_effect`, and `decision_cache_ttl_secs`.
    /// Callers should invoke `config.validate()` beforehand if validation is desired.
    pub fn from_config(config: &AbacConfig) -> Self {
        let effect = if config.default_effect == "permit" {
            PolicyEffect::Permit
        } else {
            PolicyEffect::Deny
        };
        Self::new(config.rules.clone(), effect, config.decision_cache_ttl_secs)
    }

    // -------------------------------------------------------------------
    // Main Evaluation Entry Point
    // -------------------------------------------------------------------

    /// Evaluates the attribute set against all enabled rules.
    ///
    /// See module-level documentation for the full algorithm description.
    pub async fn evaluate(&self, attributes: &HashMap<String, AbacValue>) -> AbacDecision {
        // --- Step 1: Cache lookup ---
        let attr_hash = Self::hash_attributes(attributes);
        if let Some(cached) = self.get_cached_decision(attr_hash) {
            return cached;
        }

        // --- Step 2: Sort enabled rules by priority DESC ---
        let mut sorted: Vec<&AbacPolicyRule> = self.rules.iter().filter(|r| r.enabled).collect();
        sorted.sort_by_key(|b| std::cmp::Reverse(b.priority));

        // --- Step 3-4: Evaluate ---
        let mut matched_permit_id: Option<String> = None;
        let mut matched_obligation: Option<Obligation> = None;
        let mut evaluated_count: u32 = 0;

        for rule in &sorted {
            evaluated_count += 1;
            if !Self::match_rule(rule, attributes) {
                continue;
            }
            match rule.effect {
                PolicyEffect::Deny => {
                    let d = AbacDecision {
                        effect: PolicyEffect::Deny,
                        matched_rule_id: Some(rule.rule_id.clone()),
                        obligation: None,
                        evaluated_rules: evaluated_count,
                        cache_hit: false,
                    };
                    self.cache_decision(attr_hash, d.clone());
                    return d;
                }
                PolicyEffect::Permit => {
                    if matched_permit_id.is_none() {
                        matched_permit_id = Some(rule.rule_id.clone());
                        matched_obligation = Self::apply_obligation(rule.obligation.as_ref());
                    }
                }
            }
        }

        // --- Step 5: Finalize ---
        let decision = match &matched_permit_id {
            Some(pid) => AbacDecision {
                effect: PolicyEffect::Permit,
                matched_rule_id: Some(pid.clone()),
                obligation: matched_obligation,
                evaluated_rules: evaluated_count,
                cache_hit: false,
            },
            None => AbacDecision {
                effect: self.default_effect,
                matched_rule_id: None,
                obligation: None,
                evaluated_rules: evaluated_count,
                cache_hit: false,
            },
        };

        self.cache_decision(attr_hash, decision.clone());
        decision
    }

    // -------------------------------------------------------------------
    // Rule Matching
    // -------------------------------------------------------------------

    /// Checks whether ALL conditions of a rule match (AND logic).
    /// Fail-closed: missing attrs / type mismatches → condition fails → rule does not match.
    fn match_rule(rule: &AbacPolicyRule, attribute_map: &HashMap<String, AbacValue>) -> bool {
        rule.matches_conditions(attribute_map)
    }

    // -------------------------------------------------------------------
    // Obligation Processing
    // -------------------------------------------------------------------

    /// Passthrough for matched permit rule obligations.
    fn apply_obligation(obligation: Option<&Obligation>) -> Option<Obligation> {
        obligation.cloned()
    }

    // -------------------------------------------------------------------
    // Decision Caching
    // -------------------------------------------------------------------

    fn cache_decision(&self, hash: u64, decision: AbacDecision) {
        if self.cache_ttl.is_zero() {
            return;
        }
        if let Ok(mut c) = self.cache.write() {
            c.insert(hash, (decision, Instant::now()));
        }
    }

    fn get_cached_decision(&self, hash: u64) -> Option<AbacDecision> {
        if self.cache_ttl.is_zero() {
            return None;
        }
        let c = self.cache.read().ok()?;
        let (d, t) = c.get(&hash)?;
        if t.elapsed() < self.cache_ttl {
            let mut result = d.clone();
            result.cache_hit = true;
            Some(result)
        } else {
            None
        }
    }

    /// Removes all entries from the decision cache.
    pub fn invalidate_cache(&self) {
        if let Ok(mut c) = self.cache.write() {
            c.clear();
        }
    }

    // -------------------------------------------------------------------
    // Rule Management
    // -------------------------------------------------------------------

    /// Appends a new rule. Call [`invalidate_cache`] afterward to prevent stale hits.
    pub fn add_rule(&mut self, rule: AbacPolicyRule) {
        self.rules.push(rule);
    }

    /// Removes a rule by ID. Returns `true` if found and removed.
    pub fn remove_rule(&mut self, rule_id: &str) -> bool {
        let n = self.rules.len();
        self.rules.retain(|r| r.rule_id != rule_id);
        self.rules.len() < n
    }

    /// Replaces all rules and invalidates the cache atomically.
    pub fn reload_rules(&mut self, rules: Vec<AbacPolicyRule>) {
        self.rules = rules;
        self.invalidate_cache();
    }

    // -------------------------------------------------------------------
    // Private Helpers
    // -------------------------------------------------------------------

    /// Computes a deterministic FNV-1a-style hash of sorted attribute map.
    /// Uses BTreeMap for order-independent hashing.
    fn hash_attributes(attributes: &HashMap<String, AbacValue>) -> u64 {
        let sorted: BTreeMap<&String, &AbacValue> = attributes.iter().collect();
        let mut h = 0u64;
        for (key, val) in &sorted {
            for b in key.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
            let s = format!("{:?}", val);
            for b in s.as_bytes() {
                h ^= *b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
        }
        h
    }
}
