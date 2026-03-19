//! JSON parser and validator for Policy DSL v2 rules.
//!
//! Provides [`parse_policy_rules`] to deserialize a JSON string into a validated
//! [`PolicyRuleSet`], and [`validate_rule`] to recursively check individual rule
//! constraints (e.g. valid hour ranges, non-empty sub-rule lists).

use crate::error::CoreError;
use crate::policy::schema::{PolicyRule, PolicyRuleSet};

/// Parse a JSON string into a validated [`PolicyRuleSet`].
///
/// This function:
/// 1. Deserializes the JSON into a `PolicyRuleSet`.
/// 2. Validates schema version == 2.
/// 3. Validates max depth <= 10.
/// 4. Recursively validates each rule via [`validate_rule`].
///
/// # Errors
///
/// Returns [`CoreError::Serialization`] for malformed JSON, or
/// [`CoreError::InvalidConfig`] for schema/depth/rule constraint violations.
pub fn parse_policy_rules(json: &str) -> Result<PolicyRuleSet, CoreError> {
    let ruleset: PolicyRuleSet = serde_json::from_str(json)
        .map_err(|e| CoreError::Serialization(format!("invalid policy rules JSON: {e}")))?;
    ruleset.validate()?;
    for rule in &ruleset.rules {
        validate_rule(rule)?;
    }
    Ok(ruleset)
}

/// Recursively validate a single [`PolicyRule`].
///
/// Checks:
/// - `TimeWindow`: `start_hour < 24` and `end_hour < 24`
/// - `AmountLimit`: `max_amount > 0`
/// - `VelocityLimit`: `max_amount > 0`
/// - `RequireApprovals`: `min_approvals > 0`
/// - `AllowlistCheck`: `addresses` is not empty
/// - `And`/`Or`: at least 1 sub-rule, and each sub-rule is recursively valid
/// - `Not`: inner rule is recursively valid
/// - `ChainMatch`: no extra constraints
pub fn validate_rule(rule: &PolicyRule) -> Result<(), CoreError> {
    match rule {
        PolicyRule::And(rules) => {
            if rules.is_empty() {
                return Err(CoreError::InvalidConfig(
                    "And rule must have at least 1 sub-rule".into(),
                ));
            }
            for r in rules {
                validate_rule(r)?;
            }
        }
        PolicyRule::Or(rules) => {
            if rules.is_empty() {
                return Err(CoreError::InvalidConfig(
                    "Or rule must have at least 1 sub-rule".into(),
                ));
            }
            for r in rules {
                validate_rule(r)?;
            }
        }
        PolicyRule::Not(inner) => {
            validate_rule(inner)?;
        }
        PolicyRule::AllowlistCheck { addresses } => {
            if addresses.is_empty() {
                return Err(CoreError::InvalidConfig(
                    "AllowlistCheck must have at least 1 address".into(),
                ));
            }
        }
        PolicyRule::AmountLimit { max_amount } => {
            if *max_amount == 0 {
                return Err(CoreError::InvalidConfig(
                    "AmountLimit max_amount must be greater than 0".into(),
                ));
            }
        }
        PolicyRule::VelocityLimit { max_amount, .. } => {
            if *max_amount == 0 {
                return Err(CoreError::InvalidConfig(
                    "VelocityLimit max_amount must be greater than 0".into(),
                ));
            }
        }
        PolicyRule::TimeWindow {
            start_hour,
            end_hour,
        } => {
            if *start_hour >= 24 {
                return Err(CoreError::InvalidConfig(format!(
                    "TimeWindow start_hour {} must be < 24",
                    start_hour
                )));
            }
            if *end_hour >= 24 {
                return Err(CoreError::InvalidConfig(format!(
                    "TimeWindow end_hour {} must be < 24",
                    end_hour
                )));
            }
        }
        PolicyRule::RequireApprovals { min_approvals } => {
            if *min_approvals == 0 {
                return Err(CoreError::InvalidConfig(
                    "RequireApprovals min_approvals must be greater than 0".into(),
                ));
            }
        }
        PolicyRule::ChainMatch { .. } => {
            // No additional constraints
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_allowlist() {
        let json = r#"{
            "version": 2,
            "name": "test",
            "rules": [
                {"type": "AllowlistCheck", "params": {"addresses": ["0xAAA", "0xBBB"]}}
            ]
        }"#;
        let ruleset = parse_policy_rules(json).unwrap();
        assert_eq!(ruleset.rules.len(), 1);
        match &ruleset.rules[0] {
            PolicyRule::AllowlistCheck { addresses } => {
                assert_eq!(addresses.len(), 2);
            }
            other => panic!("expected AllowlistCheck, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_nested_and_or() {
        let json = r#"{
            "version": 2,
            "name": "test",
            "rules": [
                {
                    "type": "And",
                    "params": [
                        {"type": "AmountLimit", "params": {"max_amount": 1000}},
                        {
                            "type": "Or",
                            "params": [
                                {"type": "AllowlistCheck", "params": {"addresses": ["0xAAA"]}},
                                {"type": "ChainMatch", "params": {"chain": "ethereum"}}
                            ]
                        }
                    ]
                }
            ]
        }"#;
        let ruleset = parse_policy_rules(json).unwrap();
        assert_eq!(ruleset.rules.len(), 1);
        assert!(matches!(&ruleset.rules[0], PolicyRule::And(..)));
    }

    #[test]
    fn test_parse_invalid_json() {
        let json = "not valid json {{{";
        let err = parse_policy_rules(json).unwrap_err();
        assert!(matches!(err, CoreError::Serialization(_)));
    }

    #[test]
    fn test_parse_exceeds_max_depth() {
        // Build depth-11 nested Not rules
        let mut inner = r#"{"type": "ChainMatch", "params": {"chain": "eth"}}"#.to_string();
        for _ in 0..11 {
            inner = format!(r#"{{"type": "Not", "params": {}}}"#, inner);
        }
        let json = format!(r#"{{"version": 2, "name": "test", "rules": [{}]}}"#, inner);
        let err = parse_policy_rules(&json).unwrap_err();
        assert!(matches!(err, CoreError::InvalidConfig(_)));
        assert!(err.to_string().contains("depth"));
    }

    #[test]
    fn test_parse_invalid_time_window() {
        let json = r#"{
            "version": 2,
            "name": "test",
            "rules": [
                {"type": "TimeWindow", "params": {"start_hour": 25, "end_hour": 10}}
            ]
        }"#;
        let err = parse_policy_rules(json).unwrap_err();
        assert!(matches!(err, CoreError::InvalidConfig(_)));
        assert!(err.to_string().contains("start_hour"));
    }

    #[test]
    fn test_parse_empty_and() {
        let json = r#"{
            "version": 2,
            "name": "test",
            "rules": [
                {"type": "And", "params": []}
            ]
        }"#;
        let err = parse_policy_rules(json).unwrap_err();
        assert!(matches!(err, CoreError::InvalidConfig(_)));
        assert!(err.to_string().contains("And rule"));
    }

    #[test]
    fn test_validate_amount_zero() {
        let json = r#"{
            "version": 2,
            "name": "test",
            "rules": [
                {"type": "AmountLimit", "params": {"max_amount": 0}}
            ]
        }"#;
        let err = parse_policy_rules(json).unwrap_err();
        assert!(matches!(err, CoreError::InvalidConfig(_)));
        assert!(err.to_string().contains("max_amount"));
    }

    #[test]
    fn test_parse_wrong_version() {
        let json = r#"{
            "version": 1,
            "name": "test",
            "rules": [
                {"type": "ChainMatch", "params": {"chain": "ethereum"}}
            ]
        }"#;
        let err = parse_policy_rules(json).unwrap_err();
        assert!(matches!(err, CoreError::InvalidConfig(_)));
        assert!(err.to_string().contains("version"));
    }

    #[test]
    fn test_validate_empty_allowlist() {
        let json = r#"{
            "version": 2,
            "name": "test",
            "rules": [
                {"type": "AllowlistCheck", "params": {"addresses": []}}
            ]
        }"#;
        let err = parse_policy_rules(json).unwrap_err();
        assert!(matches!(err, CoreError::InvalidConfig(_)));
        assert!(err.to_string().contains("AllowlistCheck"));
    }

    #[test]
    fn test_validate_require_approvals_zero() {
        let json = r#"{
            "version": 2,
            "name": "test",
            "rules": [
                {"type": "RequireApprovals", "params": {"min_approvals": 0}}
            ]
        }"#;
        let err = parse_policy_rules(json).unwrap_err();
        assert!(matches!(err, CoreError::InvalidConfig(_)));
        assert!(err.to_string().contains("min_approvals"));
    }

    #[test]
    fn test_parse_all_rule_types() {
        let json = r#"{
            "version": 2,
            "name": "test",
            "rules": [
                {"type": "AllowlistCheck", "params": {"addresses": ["0xAAA"]}},
                {"type": "AmountLimit", "params": {"max_amount": 1000}},
                {"type": "VelocityLimit", "params": {"max_amount": 5000, "window_secs": 86400}},
                {"type": "TimeWindow", "params": {"start_hour": 9, "end_hour": 17}},
                {"type": "RequireApprovals", "params": {"min_approvals": 2}},
                {"type": "ChainMatch", "params": {"chain": "ethereum"}}
            ]
        }"#;
        let ruleset = parse_policy_rules(json).unwrap();
        assert_eq!(ruleset.rules.len(), 6);
    }
}
