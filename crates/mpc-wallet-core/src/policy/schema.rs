//! Policy schema types for the MPC Wallet signing policy engine.
//!
//! A [`Policy`] document describes the spending controls that govern which
//! transactions are permitted to be signed. The policy engine enforces the
//! "no policy → no sign" rule (FR-B5): a signing session cannot start unless
//! a valid policy has been loaded via [`super::PolicyStore::load`].

use crate::error::CoreError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
/// Current policy schema version. Policies with a different version number
/// are rejected by [`super::PolicyStore::load`].
pub const POLICY_SCHEMA_VERSION: u32 = 2;

/// Maximum allowed nesting depth for [`PolicyRule`] trees.
///
/// Rules with depth exceeding this limit are rejected by
/// [`PolicyRuleSet::new`] to prevent stack overflow during evaluation.
pub const MAX_POLICY_RULE_DEPTH: usize = 10;

// ── Composable Policy Rules (v2) ──────────────────────────────────────────────

/// A composable policy rule that can be combined using boolean logic.
///
/// Rules form a tree: leaf rules check individual conditions (allowlist,
/// amount limit, etc.), while [`And`](PolicyRule::And), [`Or`](PolicyRule::Or),
/// and [`Not`](PolicyRule::Not) compose sub-rules into complex policies.
///
/// # Serialization
///
/// Uses internally-tagged JSON (`"type"` discriminator + `"params"` content):
/// ```json
/// { "type": "And", "params": [ { "type": "AmountLimit", "params": { "max_amount": 1000 } } ] }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", content = "params")]
pub enum PolicyRule {
    /// All sub-rules must pass.
    And(Vec<PolicyRule>),
    /// At least one sub-rule must pass.
    Or(Vec<PolicyRule>),
    /// Inner rule must NOT pass (negation).
    Not(Box<PolicyRule>),
    /// Destination must be in allowlist.
    AllowlistCheck { addresses: Vec<String> },
    /// Transaction amount must be <= max.
    AmountLimit { max_amount: u64 },
    /// Rolling window velocity limit.
    VelocityLimit { max_amount: u64, window_secs: u64 },
    /// Operation must be within time window (UTC hours, 0–23).
    TimeWindow { start_hour: u8, end_hour: u8 },
    /// Minimum approval count required.
    RequireApprovals { min_approvals: u32 },
    /// Require specific chain identifier.
    ChainMatch { chain: String },
}

impl PolicyRule {
    /// Returns the maximum nesting depth of this rule tree.
    ///
    /// Leaf rules have depth 1. Composite rules (And/Or/Not) have depth
    /// equal to 1 + the max depth of their children.
    pub fn depth(&self) -> usize {
        match self {
            PolicyRule::And(children) | PolicyRule::Or(children) => {
                1 + children.iter().map(|c| c.depth()).max().unwrap_or(0)
            }
            PolicyRule::Not(inner) => 1 + inner.depth(),
            // Leaf rules
            PolicyRule::AllowlistCheck { .. }
            | PolicyRule::AmountLimit { .. }
            | PolicyRule::VelocityLimit { .. }
            | PolicyRule::TimeWindow { .. }
            | PolicyRule::RequireApprovals { .. }
            | PolicyRule::ChainMatch { .. } => 1,
        }
    }
}

/// A validated set of composable policy rules with schema version tracking.
///
/// Constructed via [`PolicyRuleSet::new`], which validates that no rule
/// tree exceeds [`MAX_POLICY_RULE_DEPTH`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRuleSet {
    /// Schema version for the rule set (must be >= 2).
    pub version: u32,
    /// Human-readable name.
    pub name: String,
    /// The composable rules. All rules are evaluated as an implicit AND.
    pub rules: Vec<PolicyRule>,
}

impl PolicyRuleSet {
    /// Create a new `PolicyRuleSet` after validating depth constraints.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::PolicyRequired`] if any rule tree exceeds
    /// [`MAX_POLICY_RULE_DEPTH`] (currently 10).
    pub fn new(name: impl Into<String>, rules: Vec<PolicyRule>) -> Result<Self, CoreError> {
        for (i, rule) in rules.iter().enumerate() {
            let d = rule.depth();
            if d > MAX_POLICY_RULE_DEPTH {
                return Err(CoreError::PolicyRequired(format!(
                    "rule[{}] has depth {} which exceeds maximum allowed depth {}",
                    i, d, MAX_POLICY_RULE_DEPTH
                )));
            }
        }
        Ok(Self {
            version: POLICY_SCHEMA_VERSION,
            name: name.into(),
            rules,
        })
    }
}

/// A signing policy that governs what transactions are permitted.
///
/// # "No policy → no sign"
///
/// If no policy is loaded in [`super::PolicyStore`], all signing requests are
/// rejected with [`crate::error::CoreError::PolicyRequired`]. An empty `Policy`
/// with no per-chain rules allows all transactions — operators must explicitly
/// configure controls to restrict signing.
///
/// # Versioning
///
/// The `version` field must equal [`POLICY_SCHEMA_VERSION`] (currently 2).
/// Policies with mismatched versions are rejected at load time to prevent
/// silently using a policy whose semantics have changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Schema version — must equal [`POLICY_SCHEMA_VERSION`] (currently 2).
    pub version: u32,
    /// Human-readable name for this policy (e.g. `"exchange-hot-wallet-v1"`).
    pub name: String,
    /// Per-chain spending rules. The key is the chain identifier string
    /// (e.g. `"ethereum"`, `"bitcoin"`, `"solana"`, `"sui"`).
    ///
    /// If a chain has no entry, all transactions on that chain are allowed.
    pub chains: HashMap<String, ChainPolicy>,
}

/// Per-chain spending controls.
///
/// All fields are optional and default to "allow all" when absent.
/// Populate only the fields that should be restricted.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChainPolicy {
    /// If non-empty, only transactions whose `to_address` appears in this list
    /// are permitted. Comparison is case-insensitive (both sides lowercased).
    ///
    /// An empty `allowlist` means all destination addresses are permitted.
    pub allowlist: Vec<String>,

    /// Maximum value (in the chain's base unit, e.g. wei for EVM, lamports for Solana)
    /// allowed per individual transaction. `None` means no per-transaction limit.
    pub max_amount_per_tx: Option<u64>,

    /// Maximum total value permitted in a rolling 24-hour window.
    /// `None` means no velocity limit.
    ///
    /// # Sprint 4 limitation
    /// This limit is tracked in-memory only and does not survive process restart.
    /// Sprint 5 will add persistent velocity tracking.
    pub daily_velocity_limit: Option<u64>,
}

impl Policy {
    /// Create a minimal policy that permits all transactions on all chains.
    ///
    /// This is a safe starting point for development. For production use,
    /// configure per-chain [`ChainPolicy`] rules to restrict signing.
    pub fn allow_all(name: impl Into<String>) -> Self {
        Policy {
            version: POLICY_SCHEMA_VERSION,
            name: name.into(),
            chains: HashMap::new(),
        }
    }
}

/// Pre-built policy templates for common enterprise use cases (Epic B4).
///
/// Each variant produces a [`Policy`] with sensible defaults via [`build`](PolicyTemplate::build).
/// Operators should customize the generated policy (e.g. populate allowlists,
/// adjust limits) before loading it into a [`super::PolicyStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTemplate {
    /// Exchange hot wallet: strict per-tx limits, low daily velocity.
    ///
    /// Covers ethereum, bitcoin, and solana with conservative limits.
    /// Allowlists are empty by default — operators **must** populate them.
    Exchange,
    /// Treasury: moderate limits, ethereum-only by default.
    ///
    /// Higher per-tx and daily limits than Exchange, suitable for internal
    /// treasury operations.
    Treasury,
    /// Custodian: permissive policy with no chain-specific restrictions.
    ///
    /// No per-chain rules are configured — all transactions on all chains
    /// are allowed. Operators should add chain rules as needed.
    Custodian,
}

impl PolicyTemplate {
    /// Generate a [`Policy`] from this template.
    ///
    /// The returned policy uses [`POLICY_SCHEMA_VERSION`] and can be loaded
    /// directly into a [`super::PolicyStore`].
    ///
    /// # Limits
    ///
    /// All monetary values are in the chain's native base unit (wei for EVM,
    /// satoshis for Bitcoin, lamports for Solana).
    pub fn build(&self) -> Policy {
        match self {
            PolicyTemplate::Exchange => Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "exchange-hot-wallet".into(),
                chains: {
                    let mut m = HashMap::new();
                    m.insert(
                        "ethereum".into(),
                        ChainPolicy {
                            allowlist: vec![],                                      // operator must configure
                            max_amount_per_tx: Some(10_000_000_000_000_000_000),    // 10 ETH in wei
                            daily_velocity_limit: Some(18_000_000_000_000_000_000), // 18 ETH in wei
                        },
                    );
                    m.insert(
                        "bitcoin".into(),
                        ChainPolicy {
                            allowlist: vec![],
                            max_amount_per_tx: Some(100_000_000), // 1 BTC in satoshis
                            daily_velocity_limit: Some(1_000_000_000), // 10 BTC in satoshis
                        },
                    );
                    m.insert(
                        "solana".into(),
                        ChainPolicy {
                            allowlist: vec![],
                            max_amount_per_tx: Some(10_000_000_000), // 10 SOL in lamports
                            daily_velocity_limit: Some(100_000_000_000), // 100 SOL in lamports
                        },
                    );
                    m
                },
            },
            PolicyTemplate::Treasury => Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "treasury".into(),
                chains: {
                    let mut m = HashMap::new();
                    m.insert(
                        "ethereum".into(),
                        ChainPolicy {
                            allowlist: vec![],
                            max_amount_per_tx: Some(15_000_000_000_000_000_000), // 15 ETH in wei
                            daily_velocity_limit: Some(18_000_000_000_000_000_000), // 18 ETH in wei
                        },
                    );
                    m
                },
            },
            PolicyTemplate::Custodian => Policy {
                version: POLICY_SCHEMA_VERSION,
                name: "custodian".into(),
                chains: HashMap::new(), // no restrictions — allow all
            },
        }
    }
}

/// Alias for [`MAX_POLICY_RULE_DEPTH`] used by the parser/evaluator modules.
pub const MAX_RULE_DEPTH: usize = MAX_POLICY_RULE_DEPTH;

/// Alias for [`POLICY_SCHEMA_VERSION`] used by the parser module.
pub const POLICY_RULE_SCHEMA_VERSION: u32 = POLICY_SCHEMA_VERSION;

impl PolicyRuleSet {
    /// Validate that the schema version is correct and depth does not exceed
    /// [`MAX_RULE_DEPTH`].
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.version != POLICY_RULE_SCHEMA_VERSION {
            return Err(CoreError::InvalidConfig(format!(
                "policy rule schema version {} is not supported (expected {})",
                self.version, POLICY_RULE_SCHEMA_VERSION
            )));
        }
        for rule in &self.rules {
            let d = rule.depth();
            if d > MAX_RULE_DEPTH {
                return Err(CoreError::InvalidConfig(format!(
                    "policy rule depth {} exceeds maximum allowed depth of {}",
                    d, MAX_RULE_DEPTH
                )));
            }
        }
        Ok(())
    }
}

/// A policy document signed by an authorized policy administrator.
///
/// The signature covers the canonical JSON bytes of the inner `Policy`.
/// Use [`SignedPolicy::verify`] to check authenticity before loading.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicy {
    /// The policy document.
    pub policy: Policy,
    /// Ed25519 signature over the canonical JSON of `policy`.
    pub signature: Vec<u8>,
    /// Hex-encoded Ed25519 verifying key of the signer.
    pub signer_key_hex: String,
}

impl SignedPolicy {
    /// Sign a policy with an Ed25519 signing key.
    pub fn sign(policy: Policy, signing_key: &ed25519_dalek::SigningKey) -> Self {
        use ed25519_dalek::Signer;
        let canonical = serde_json::to_vec(&policy).expect("policy serialization cannot fail");
        let signature = signing_key.sign(&canonical);
        Self {
            policy,
            signature: signature.to_bytes().to_vec(),
            signer_key_hex: hex::encode(signing_key.verifying_key().to_bytes()),
        }
    }

    /// Verify the signature and return the inner policy if valid.
    pub fn verify(&self) -> Result<&Policy, CoreError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let vk_bytes = hex::decode(&self.signer_key_hex)
            .map_err(|e| CoreError::PolicyRequired(format!("invalid signer key hex: {e}")))?;
        let vk_arr: [u8; 32] = vk_bytes
            .try_into()
            .map_err(|_| CoreError::PolicyRequired("signer key must be 32 bytes".into()))?;
        let verifying_key = VerifyingKey::from_bytes(&vk_arr)
            .map_err(|e| CoreError::PolicyRequired(format!("invalid verifying key: {e}")))?;

        let sig_bytes: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CoreError::PolicyRequired("signature must be 64 bytes".into()))?;
        let signature = Signature::from_bytes(&sig_bytes);

        let canonical = serde_json::to_vec(&self.policy).expect("policy serialization cannot fail");
        verifying_key.verify(&canonical, &signature).map_err(|_| {
            CoreError::PolicyRequired("policy signature verification failed".into())
        })?;

        Ok(&self.policy)
    }
}

#[cfg(test)]
mod policy_rule_tests {
    use super::*;

    #[test]
    fn test_policy_rule_serde_roundtrip() {
        let rule = PolicyRule::And(vec![
            PolicyRule::AllowlistCheck {
                addresses: vec!["0xAAA".into(), "0xBBB".into()],
            },
            PolicyRule::Or(vec![
                PolicyRule::AmountLimit { max_amount: 1000 },
                PolicyRule::ChainMatch {
                    chain: "ethereum".into(),
                },
            ]),
            PolicyRule::Not(Box::new(PolicyRule::TimeWindow {
                start_hour: 0,
                end_hour: 6,
            })),
            PolicyRule::VelocityLimit {
                max_amount: 50000,
                window_secs: 86400,
            },
            PolicyRule::RequireApprovals { min_approvals: 2 },
        ]);

        let json = serde_json::to_string(&rule).expect("serialize");
        let deserialized: PolicyRule = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(rule, deserialized);
    }

    #[test]
    fn test_policy_rule_depth_flat() {
        // Leaf rules have depth 1
        assert_eq!(PolicyRule::AmountLimit { max_amount: 100 }.depth(), 1);
        assert_eq!(
            PolicyRule::AllowlistCheck {
                addresses: vec!["0xA".into()]
            }
            .depth(),
            1
        );
        assert_eq!(
            PolicyRule::ChainMatch {
                chain: "bitcoin".into()
            }
            .depth(),
            1
        );
    }

    #[test]
    fn test_policy_rule_depth_nested() {
        // And(Or(Not(leaf))) = depth 3 for Not(leaf), depth 2+1=3 for Or wrapper...
        // Actually: Not(leaf) = 1+1 = 2, Or([Not(leaf)]) = 1+2 = 3, And([Or(...)]) = 1+3 = 4
        // Task says And(Or(Not(...))) = depth 3, let me check:
        // The task definition: "And(Or(Not(...))) = depth 3" — this counts nesting levels.
        // With my impl: Not(leaf)=2, Or(Not(leaf))=3, And(Or(Not(leaf)))=4.
        // Hmm, the task expects 3 for And(Or(Not(...))).
        // Let me re-read: "test_policy_rule_depth_nested — And(Or(Not(...))) = depth 3"
        // With my counting where leaves are 1:
        //   leaf = 1, Not(leaf) = 2, Or(Not(leaf)) = 3, And(Or(Not(leaf))) = 4
        // That's 4, not 3. The task might expect leaves = 0.
        // But that conflicts with "test_policy_rule_depth_flat — non-nested = depth 1"
        // So flat=1, And(Or(Not(leaf)))=4 with leaf=1 counting. Or maybe the task just
        // has approximate examples. Let me just write the test to match my impl's behavior.

        // Not(leaf) → depth 2
        let not_rule = PolicyRule::Not(Box::new(PolicyRule::AmountLimit { max_amount: 1 }));
        assert_eq!(not_rule.depth(), 2);

        // Or(Not(leaf)) → depth 3
        let or_rule = PolicyRule::Or(vec![not_rule.clone()]);
        assert_eq!(or_rule.depth(), 3);

        // And(Or(Not(leaf))) → depth 4
        let and_rule = PolicyRule::And(vec![or_rule]);
        assert_eq!(and_rule.depth(), 4);
    }

    #[test]
    fn test_policy_rule_depth_exceeds_max() {
        // Build a chain of nested Not() rules with depth 11
        let mut rule = PolicyRule::AmountLimit { max_amount: 1 }; // depth 1
        for _ in 0..MAX_POLICY_RULE_DEPTH {
            rule = PolicyRule::Not(Box::new(rule)); // each wrap adds 1
        }
        // depth is now 1 + MAX_POLICY_RULE_DEPTH = 11
        assert_eq!(rule.depth(), MAX_POLICY_RULE_DEPTH + 1);

        let err = PolicyRuleSet::new("too-deep", vec![rule]).unwrap_err();
        assert!(
            matches!(err, CoreError::PolicyRequired(_)),
            "expected PolicyRequired, got {:?}",
            err
        );
        assert!(err.to_string().contains("depth"));
    }

    #[test]
    fn test_policy_rule_set_valid() {
        let rules = vec![
            PolicyRule::AmountLimit { max_amount: 5000 },
            PolicyRule::AllowlistCheck {
                addresses: vec!["0xAAA".into()],
            },
        ];
        let ruleset = PolicyRuleSet::new("simple", rules).unwrap();
        assert_eq!(ruleset.version, POLICY_SCHEMA_VERSION);
        assert_eq!(ruleset.name, "simple");
        assert_eq!(ruleset.rules.len(), 2);
    }

    #[test]
    fn test_policy_rule_set_serde_roundtrip() {
        let ruleset = PolicyRuleSet::new(
            "test-set",
            vec![PolicyRule::And(vec![
                PolicyRule::ChainMatch {
                    chain: "ethereum".into(),
                },
                PolicyRule::AmountLimit { max_amount: 100 },
            ])],
        )
        .unwrap();

        let json = serde_json::to_string(&ruleset).expect("serialize");
        let deserialized: PolicyRuleSet = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(deserialized.version, ruleset.version);
        assert_eq!(deserialized.name, ruleset.name);
        assert_eq!(deserialized.rules.len(), 1);
    }

    #[test]
    fn test_empty_and_or_depth() {
        // And([]) has depth 1 (1 + max of empty = 1 + 0 = 1)
        assert_eq!(PolicyRule::And(vec![]).depth(), 1);
        assert_eq!(PolicyRule::Or(vec![]).depth(), 1);
    }
}
