//! Policy evaluation logic.
//!
//! The [`evaluate`] function checks a single proposed transaction against a
//! loaded [`Policy`], returning [`EvalResult::Allow`] or [`EvalResult::Deny`].
//!
//! The [`evaluate_rule`] and [`evaluate_ruleset`] functions provide recursive
//! evaluation of the v2 Policy DSL [`PolicyRule`] trees against an
//! [`EvaluationContext`].

use crate::error::CoreError;
use crate::policy::schema::{Policy, PolicyRule, PolicyRuleSet};

/// The result of evaluating a transaction against a policy.
#[derive(Debug, PartialEq, Eq)]
pub enum EvalResult {
    /// The transaction is permitted by the policy.
    Allow,
    /// The transaction is denied. The inner string explains which rule was violated.
    Deny(String),
}

/// Evaluate a proposed transaction against a [`Policy`].
///
/// # Arguments
/// - `policy` — the loaded policy to evaluate against.
/// - `chain` — chain identifier string, must match the keys used in
///   `policy.chains` (e.g. `"ethereum"`, `"bitcoin"`).
/// - `to_address` — destination address as a string. Compared case-insensitively
///   against allowlist entries.
/// - `amount` — transaction value in the chain's smallest unit (e.g. wei for EVM).
///
/// # Returns
/// [`EvalResult::Allow`] if the transaction passes all rules for the given chain,
/// [`EvalResult::Deny`] with a human-readable reason if any rule rejects it.
///
/// If the policy has no rules for `chain`, the transaction is allowed by default.
pub fn evaluate(policy: &Policy, chain: &str, to_address: &str, amount: u64) -> EvalResult {
    let chain_policy = match policy.chains.get(chain) {
        Some(cp) => cp,
        // No rules for this chain → allow by default
        None => return EvalResult::Allow,
    };

    // ── Allowlist check ───────────────────────────────────────────────────────
    if !chain_policy.allowlist.is_empty() {
        let addr_lower = to_address.to_lowercase();
        let allowed = chain_policy
            .allowlist
            .iter()
            .any(|a| a.to_lowercase() == addr_lower);
        if !allowed {
            return EvalResult::Deny(format!(
                "destination address '{}' is not in the allowlist for chain '{}'",
                to_address, chain
            ));
        }
    }

    // ── Per-transaction amount limit ──────────────────────────────────────────
    if let Some(max) = chain_policy.max_amount_per_tx {
        if amount > max {
            return EvalResult::Deny(format!(
                "amount {} exceeds the per-transaction limit of {} on chain '{}'",
                amount, max, chain
            ));
        }
    }

    // ── Daily velocity limit ────────────────────────────────────────────────────
    // Velocity enforcement is handled by `PolicyStore::check()` which maintains
    // a rolling 24-hour window of signed amounts per chain. The pure evaluator
    // does not track state; it only checks stateless per-transaction rules.

    EvalResult::Allow
}

/// Context for evaluating v2 Policy DSL rules against a proposed transaction.
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    /// Chain identifier (e.g. `"ethereum"`, `"bitcoin"`).
    pub chain: String,
    /// Transaction amount in the chain's base unit.
    pub amount: u64,
    /// Destination address.
    pub destination: String,
    /// Current hour in UTC (0..23).
    pub current_hour_utc: u8,
    /// Number of approvals collected for this transaction.
    pub approval_count: u32,
    /// Amount already spent in the current velocity window.
    pub velocity_used: u64,
}

/// Recursively evaluate a single [`PolicyRule`] against the given context.
///
/// # Returns
/// - `Ok(true)` if the rule passes.
/// - `Ok(false)` if the rule fails.
/// - `Err(CoreError)` if evaluation encounters an error.
pub fn evaluate_rule(rule: &PolicyRule, ctx: &EvaluationContext) -> Result<bool, CoreError> {
    match rule {
        PolicyRule::And { rules } => {
            for r in rules {
                if !evaluate_rule(r, ctx)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        PolicyRule::Or { rules } => {
            for r in rules {
                if evaluate_rule(r, ctx)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        PolicyRule::Not { rule: inner } => Ok(!evaluate_rule(inner, ctx)?),
        PolicyRule::AllowlistCheck { addresses } => {
            let dest_lower = ctx.destination.to_lowercase();
            Ok(addresses.iter().any(|a| a.to_lowercase() == dest_lower))
        }
        PolicyRule::AmountLimit { max_amount } => Ok(ctx.amount <= *max_amount),
        PolicyRule::VelocityLimit { max_amount } => {
            Ok(ctx.velocity_used.saturating_add(ctx.amount) <= *max_amount)
        }
        PolicyRule::TimeWindow {
            start_hour,
            end_hour,
        } => Ok(ctx.current_hour_utc >= *start_hour && ctx.current_hour_utc < *end_hour),
        PolicyRule::RequireApprovals { min_approvals } => Ok(ctx.approval_count >= *min_approvals),
        PolicyRule::ChainMatch { chain } => Ok(ctx.chain == *chain),
    }
}

/// Evaluate all rules in a [`PolicyRuleSet`] against the given context.
///
/// All rules must pass (implicit AND). Returns `Ok(true)` if all pass,
/// `Ok(false)` if any rule fails.
pub fn evaluate_ruleset(
    ruleset: &PolicyRuleSet,
    ctx: &EvaluationContext,
) -> Result<bool, CoreError> {
    for rule in &ruleset.rules {
        if !evaluate_rule(rule, ctx)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::schema::{ChainPolicy, Policy, POLICY_SCHEMA_VERSION};
    use std::collections::HashMap;

    fn make_policy(chain: &str, cp: ChainPolicy) -> Policy {
        let mut chains = HashMap::new();
        chains.insert(chain.to_string(), cp);
        Policy {
            version: POLICY_SCHEMA_VERSION,
            name: "test".into(),
            chains,
        }
    }

    #[test]
    fn test_no_chain_rules_allows_all() {
        let policy = Policy::allow_all("test");
        assert_eq!(
            evaluate(&policy, "ethereum", "0xabc", 9999),
            EvalResult::Allow
        );
    }

    #[test]
    fn test_empty_allowlist_allows_all_addresses() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: None,
                daily_velocity_limit: None,
            },
        );
        assert_eq!(
            evaluate(&policy, "ethereum", "0xdeadbeef", 1),
            EvalResult::Allow
        );
    }

    #[test]
    fn test_allowlist_permits_known_address() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec!["0xAAA".to_string()],
                max_amount_per_tx: None,
                daily_velocity_limit: None,
            },
        );
        // Case-insensitive match
        assert_eq!(evaluate(&policy, "ethereum", "0xaaa", 1), EvalResult::Allow);
        assert_eq!(evaluate(&policy, "ethereum", "0xAAA", 1), EvalResult::Allow);
    }

    #[test]
    fn test_allowlist_blocks_unknown_address() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec!["0xAAA".to_string()],
                max_amount_per_tx: None,
                daily_velocity_limit: None,
            },
        );
        let result = evaluate(&policy, "ethereum", "0xBBB", 1);
        assert!(matches!(result, EvalResult::Deny(_)));
    }

    #[test]
    fn test_amount_limit_permits_at_limit() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: Some(1000),
                daily_velocity_limit: None,
            },
        );
        assert_eq!(
            evaluate(&policy, "ethereum", "0xabc", 1000),
            EvalResult::Allow
        );
    }

    #[test]
    fn test_amount_limit_blocks_over_limit() {
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec![],
                max_amount_per_tx: Some(1000),
                daily_velocity_limit: None,
            },
        );
        let result = evaluate(&policy, "ethereum", "0xabc", 1001);
        assert!(matches!(result, EvalResult::Deny(_)));
    }

    #[test]
    fn test_unknown_chain_allows() {
        // Policy has rules only for "ethereum"; "bitcoin" is unconstrained
        let policy = make_policy(
            "ethereum",
            ChainPolicy {
                allowlist: vec!["0xAAA".to_string()],
                max_amount_per_tx: Some(500),
                daily_velocity_limit: None,
            },
        );
        assert_eq!(
            evaluate(&policy, "bitcoin", "bc1anything", 99999),
            EvalResult::Allow
        );
    }
}

#[cfg(test)]
mod rule_evaluator_tests {
    use super::*;

    fn base_ctx() -> EvaluationContext {
        EvaluationContext {
            chain: "ethereum".into(),
            amount: 500,
            destination: "0xAAA".into(),
            current_hour_utc: 10,
            approval_count: 3,
            velocity_used: 1000,
        }
    }

    #[test]
    fn test_eval_allowlist_pass() {
        let rule = PolicyRule::AllowlistCheck {
            addresses: vec!["0xAAA".into(), "0xBBB".into()],
        };
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_allowlist_fail() {
        let rule = PolicyRule::AllowlistCheck {
            addresses: vec!["0xCCC".into()],
        };
        assert!(!evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_amount_limit_pass() {
        let rule = PolicyRule::AmountLimit { max_amount: 500 };
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_amount_limit_fail() {
        let rule = PolicyRule::AmountLimit { max_amount: 499 };
        assert!(!evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_and_all_pass() {
        let rule = PolicyRule::And {
            rules: vec![
                PolicyRule::AmountLimit { max_amount: 1000 },
                PolicyRule::ChainMatch {
                    chain: "ethereum".into(),
                },
            ],
        };
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_and_one_fails() {
        let rule = PolicyRule::And {
            rules: vec![
                PolicyRule::AmountLimit { max_amount: 1000 },
                PolicyRule::ChainMatch {
                    chain: "bitcoin".into(),
                },
            ],
        };
        assert!(!evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_or_one_passes() {
        let rule = PolicyRule::Or {
            rules: vec![
                PolicyRule::ChainMatch {
                    chain: "bitcoin".into(),
                },
                PolicyRule::AmountLimit { max_amount: 1000 },
            ],
        };
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_or_all_fail() {
        let rule = PolicyRule::Or {
            rules: vec![
                PolicyRule::ChainMatch {
                    chain: "bitcoin".into(),
                },
                PolicyRule::AmountLimit { max_amount: 100 },
            ],
        };
        assert!(!evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_not_inverts() {
        // ChainMatch("bitcoin") is false for our ctx, so Not should be true
        let rule = PolicyRule::Not {
            rule: Box::new(PolicyRule::ChainMatch {
                chain: "bitcoin".into(),
            }),
        };
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());

        // ChainMatch("ethereum") is true, so Not should be false
        let rule2 = PolicyRule::Not {
            rule: Box::new(PolicyRule::ChainMatch {
                chain: "ethereum".into(),
            }),
        };
        assert!(!evaluate_rule(&rule2, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_time_window_inside() {
        let rule = PolicyRule::TimeWindow {
            start_hour: 9,
            end_hour: 17,
        };
        // ctx.current_hour_utc = 10, which is in [9, 17)
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_time_window_outside() {
        let rule = PolicyRule::TimeWindow {
            start_hour: 14,
            end_hour: 20,
        };
        // ctx.current_hour_utc = 10, which is NOT in [14, 20)
        assert!(!evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_velocity_under_limit() {
        // velocity_used=1000, amount=500 => total 1500 <= 2000
        let rule = PolicyRule::VelocityLimit { max_amount: 2000 };
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_velocity_over_limit() {
        // velocity_used=1000, amount=500 => total 1500 > 1400
        let rule = PolicyRule::VelocityLimit { max_amount: 1400 };
        assert!(!evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_require_approvals_pass() {
        let rule = PolicyRule::RequireApprovals { min_approvals: 2 };
        // ctx.approval_count = 3 >= 2
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_require_approvals_fail() {
        let rule = PolicyRule::RequireApprovals { min_approvals: 5 };
        // ctx.approval_count = 3 < 5
        assert!(!evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_complex_nested() {
        // And(AmountLimit(1000), Or(AllowlistCheck(["0xAAA"]), RequireApprovals(5)))
        let rule = PolicyRule::And {
            rules: vec![
                PolicyRule::AmountLimit { max_amount: 1000 },
                PolicyRule::Or {
                    rules: vec![
                        PolicyRule::AllowlistCheck {
                            addresses: vec!["0xAAA".into()],
                        },
                        PolicyRule::RequireApprovals { min_approvals: 5 },
                    ],
                },
            ],
        };
        // AmountLimit(1000): 500 <= 1000 => true
        // AllowlistCheck(["0xAAA"]): "0xAAA" in list => true (short-circuit)
        // And(true, Or(true, _)) => true
        assert!(evaluate_rule(&rule, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_ruleset_all_pass() {
        let ruleset = PolicyRuleSet {
            version: 2,
            rules: vec![
                PolicyRule::AmountLimit { max_amount: 1000 },
                PolicyRule::ChainMatch {
                    chain: "ethereum".into(),
                },
            ],
        };
        assert!(evaluate_ruleset(&ruleset, &base_ctx()).unwrap());
    }

    #[test]
    fn test_eval_ruleset_one_fails() {
        let ruleset = PolicyRuleSet {
            version: 2,
            rules: vec![
                PolicyRule::AmountLimit { max_amount: 1000 },
                PolicyRule::ChainMatch {
                    chain: "bitcoin".into(),
                },
            ],
        };
        assert!(!evaluate_ruleset(&ruleset, &base_ctx()).unwrap());
    }
}
