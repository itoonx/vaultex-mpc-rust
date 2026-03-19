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
pub const POLICY_SCHEMA_VERSION: u32 = 1;

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
/// The `version` field must equal [`POLICY_SCHEMA_VERSION`] (currently 1).
/// Policies with mismatched versions are rejected at load time to prevent
/// silently using a policy whose semantics have changed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Schema version — must equal [`POLICY_SCHEMA_VERSION`] (currently 1).
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

/// Maximum allowed nesting depth for recursive policy rules.
pub const MAX_RULE_DEPTH: usize = 10;

/// Current policy rule schema version for [`PolicyRuleSet`].
pub const POLICY_RULE_SCHEMA_VERSION: u32 = 2;

/// A recursive policy rule for the v2 Policy DSL.
///
/// Rules can be composed using `And`, `Or`, and `Not` combinators to build
/// arbitrarily complex (up to [`MAX_RULE_DEPTH`]) policy expressions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum PolicyRule {
    /// All sub-rules must evaluate to `true`.
    And { rules: Vec<PolicyRule> },
    /// At least one sub-rule must evaluate to `true`.
    Or { rules: Vec<PolicyRule> },
    /// The inner rule must evaluate to `false`.
    Not { rule: Box<PolicyRule> },
    /// Destination address must be in the allowlist (case-insensitive).
    AllowlistCheck { addresses: Vec<String> },
    /// Transaction amount must be at most `max_amount`.
    AmountLimit { max_amount: u64 },
    /// Cumulative spend (existing + proposed) must not exceed `max_amount`.
    VelocityLimit { max_amount: u64 },
    /// Current UTC hour must fall within `[start_hour, end_hour)`.
    TimeWindow { start_hour: u8, end_hour: u8 },
    /// Approval count must be at least `min_approvals`.
    RequireApprovals { min_approvals: u32 },
    /// Chain identifier must match exactly.
    ChainMatch { chain: String },
}

impl PolicyRule {
    /// Compute the nesting depth of this rule tree.
    ///
    /// Leaf rules have depth 1. `And`/`Or`/`Not` add 1 to the max child depth.
    pub fn depth(&self) -> usize {
        match self {
            PolicyRule::And { rules } | PolicyRule::Or { rules } => {
                1 + rules.iter().map(|r| r.depth()).max().unwrap_or(0)
            }
            PolicyRule::Not { rule } => 1 + rule.depth(),
            _ => 1,
        }
    }
}

/// A versioned set of policy rules with depth validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyRuleSet {
    /// Schema version — must equal [`POLICY_RULE_SCHEMA_VERSION`].
    pub version: u32,
    /// The list of rules (evaluated as implicit AND).
    pub rules: Vec<PolicyRule>,
}

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
