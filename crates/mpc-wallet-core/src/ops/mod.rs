//! Multi-cloud operations: node distribution constraints and health monitoring (Epic I).

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::error::CoreError;
use crate::types::PartyId;

/// Cloud provider identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CloudProvider(pub String);

/// Geographic region identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Region(pub String);

/// Node location metadata for distribution constraint enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeLocation {
    pub party_id: PartyId,
    pub provider: CloudProvider,
    pub region: Region,
}

/// Distribution constraint policy (Epic I1).
#[derive(Debug, Clone)]
pub struct DistributionPolicy {
    /// Minimum number of distinct cloud providers required.
    pub min_providers: usize,
    /// Minimum number of distinct regions required.
    pub min_regions: usize,
    /// Maximum parties allowed on a single provider.
    pub max_per_provider: usize,
}

impl Default for DistributionPolicy {
    fn default() -> Self {
        Self {
            min_providers: 2,
            min_regions: 2,
            max_per_provider: 2,
        }
    }
}

/// Validate that node locations satisfy the distribution policy.
pub fn validate_distribution(
    nodes: &[NodeLocation],
    policy: &DistributionPolicy,
) -> Result<(), CoreError> {
    if nodes.is_empty() {
        return Err(CoreError::InvalidConfig("no nodes provided".into()));
    }

    // Count distinct providers
    let providers: HashSet<_> = nodes.iter().map(|n| &n.provider).collect();
    if providers.len() < policy.min_providers {
        return Err(CoreError::InvalidConfig(format!(
            "insufficient cloud providers: {} (minimum {})",
            providers.len(),
            policy.min_providers
        )));
    }

    // Count distinct regions
    let regions: HashSet<_> = nodes.iter().map(|n| &n.region).collect();
    if regions.len() < policy.min_regions {
        return Err(CoreError::InvalidConfig(format!(
            "insufficient regions: {} (minimum {})",
            regions.len(),
            policy.min_regions
        )));
    }

    // Check per-provider concentration
    let mut per_provider: HashMap<&CloudProvider, usize> = HashMap::new();
    for node in nodes {
        *per_provider.entry(&node.provider).or_default() += 1;
    }
    for (provider, count) in &per_provider {
        if *count > policy.max_per_provider {
            return Err(CoreError::InvalidConfig(format!(
                "too many nodes on provider '{}': {} (max {})",
                provider.0, count, policy.max_per_provider
            )));
        }
    }

    Ok(())
}

/// Node health status (Epic I2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Degraded(String),
    Unreachable,
}

/// Health report for a single node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHealth {
    pub party_id: PartyId,
    pub status: HealthStatus,
    pub last_heartbeat: u64,
    pub location: NodeLocation,
}

/// Quorum risk assessment based on node health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumRisk {
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub threshold: u16,
    /// Can we still form a signing quorum?
    pub quorum_available: bool,
    /// Risk level: 0=safe, 1=degraded, 2=critical
    pub risk_level: u8,
}

/// Assess quorum risk from health reports.
pub fn assess_quorum_risk(reports: &[NodeHealth], threshold: u16) -> QuorumRisk {
    let total = reports.len();
    let healthy = reports
        .iter()
        .filter(|r| r.status == HealthStatus::Healthy)
        .count();
    let quorum_available = healthy >= threshold as usize;
    let risk_level = if healthy >= total {
        0
    } else if quorum_available {
        1
    } else {
        2
    };

    QuorumRisk {
        total_nodes: total,
        healthy_nodes: healthy,
        threshold,
        quorum_available,
        risk_level,
    }
}

// ─── RPC Failover (Epic I3) ──────────────────────────────────────────────────

/// RPC endpoint with priority for failover ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEndpoint {
    pub url: String,
    pub provider: String,
    pub priority: u8,
    pub healthy: bool,
}

/// RPC failover pool — tries endpoints in priority order.
pub struct RpcFailoverPool {
    endpoints: Vec<RpcEndpoint>,
}

impl RpcFailoverPool {
    pub fn new(mut endpoints: Vec<RpcEndpoint>) -> Self {
        endpoints.sort_by_key(|e| e.priority);
        Self { endpoints }
    }

    /// Get the next healthy endpoint. Returns None if all are unhealthy.
    pub fn next_healthy(&self) -> Option<&RpcEndpoint> {
        self.endpoints.iter().find(|e| e.healthy)
    }

    /// Mark an endpoint as unhealthy (after failure).
    pub fn mark_unhealthy(&mut self, url: &str) {
        if let Some(ep) = self.endpoints.iter_mut().find(|e| e.url == url) {
            ep.healthy = false;
        }
    }

    /// Mark an endpoint as healthy (after recovery).
    pub fn mark_healthy(&mut self, url: &str) {
        if let Some(ep) = self.endpoints.iter_mut().find(|e| e.url == url) {
            ep.healthy = true;
        }
    }

    /// Get all endpoints.
    pub fn endpoints(&self) -> &[RpcEndpoint] {
        &self.endpoints
    }

    /// Count healthy endpoints.
    pub fn healthy_count(&self) -> usize {
        self.endpoints.iter().filter(|e| e.healthy).count()
    }
}

// ─── Chaos Test Framework (Epic I4) ──────────────────────────────────────────

/// Chaos scenario for testing resilience.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChaosScenario {
    /// Kill a specific party (simulate crash).
    KillParty(PartyId),
    /// Partition network: these parties cannot communicate with each other.
    NetworkPartition(Vec<PartyId>, Vec<PartyId>),
    /// Delay messages from a party by N milliseconds.
    DelayMessages { party: PartyId, delay_ms: u64 },
    /// Corrupt messages from a party (flip random bytes).
    CorruptMessages(PartyId),
}

/// Result of running a chaos scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChaosResult {
    pub scenario: String,
    pub protocol_completed: bool,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Evaluate whether the system can tolerate a set of party failures.
pub fn can_tolerate_failures(threshold: u16, total_parties: u16, failed_parties: u16) -> bool {
    let healthy = total_parties.saturating_sub(failed_parties);
    healthy >= threshold
}

// ─── Disaster Recovery (Epic H4) ─────────────────────────────────────────────

/// Disaster recovery plan for key group restoration.
///
/// Encapsulates the information needed to assess whether a key group can be
/// recovered and the procedural steps to do so.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryPlan {
    /// Key group identifier.
    pub group_id: String,
    /// Minimum shares needed to recover (threshold).
    pub threshold: u16,
    /// Total shares in the group.
    pub total_shares: u16,
    /// Known share locations with backup status.
    pub share_locations: Vec<ShareLocation>,
    /// Recovery procedure steps (human-readable).
    pub steps: Vec<String>,
}

/// Location of a key share for recovery purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareLocation {
    /// Party that holds this share.
    pub party_id: PartyId,
    /// Cloud provider where the share is stored.
    pub provider: CloudProvider,
    /// Geographic region of the share.
    pub region: Region,
    /// Whether the backup has been verified recently.
    pub backup_verified: bool,
    /// Unix timestamp of the last backup verification.
    pub last_backup_timestamp: u64,
}

impl RecoveryPlan {
    /// Create a recovery plan from current node health data.
    ///
    /// Generates procedural steps based on how many nodes are healthy
    /// relative to the threshold requirement.
    pub fn from_health(group_id: &str, threshold: u16, nodes: &[NodeHealth]) -> Self {
        let share_locations: Vec<ShareLocation> = nodes
            .iter()
            .map(|n| ShareLocation {
                party_id: n.party_id,
                provider: n.location.provider.clone(),
                region: n.location.region.clone(),
                backup_verified: n.status == HealthStatus::Healthy,
                last_backup_timestamp: n.last_heartbeat,
            })
            .collect();

        let healthy_count = nodes
            .iter()
            .filter(|n| n.status == HealthStatus::Healthy)
            .count();

        let mut steps = vec![format!(
            "1. Verify {} of {} shares are accessible",
            threshold,
            nodes.len()
        )];

        if healthy_count < threshold as usize {
            steps.push(format!(
                "2. CRITICAL: Only {} healthy nodes, need {}. Initiate emergency share recovery.",
                healthy_count, threshold
            ));
            steps.push("3. Contact backup custodians for offline share restoration.".into());
        } else {
            steps
                .push("2. All required shares accessible. Proceed with normal key refresh.".into());
            steps.push("3. After refresh, verify new shares with test signing.".into());
        }
        steps.push("4. Update backup records and verify all share locations.".into());

        RecoveryPlan {
            group_id: group_id.into(),
            threshold,
            total_shares: nodes.len() as u16,
            share_locations,
            steps,
        }
    }

    /// Check if recovery is possible with current share availability.
    ///
    /// Returns `true` if the number of verified backup locations meets or
    /// exceeds the threshold.
    pub fn is_recoverable(&self) -> bool {
        let available = self
            .share_locations
            .iter()
            .filter(|s| s.backup_verified)
            .count();
        available >= self.threshold as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(id: u16, provider: &str, region: &str) -> NodeLocation {
        NodeLocation {
            party_id: PartyId(id),
            provider: CloudProvider(provider.into()),
            region: Region(region.into()),
        }
    }

    #[test]
    fn test_valid_distribution() {
        let nodes = vec![
            node(1, "aws", "us-east-1"),
            node(2, "gcp", "eu-west-1"),
            node(3, "azure", "ap-southeast-1"),
        ];
        assert!(validate_distribution(&nodes, &DistributionPolicy::default()).is_ok());
    }

    #[test]
    fn test_insufficient_providers() {
        let nodes = vec![
            node(1, "aws", "us-east-1"),
            node(2, "aws", "eu-west-1"),
            node(3, "aws", "ap-southeast-1"),
        ];
        let policy = DistributionPolicy {
            min_providers: 2,
            min_regions: 1,
            max_per_provider: 5,
        };
        assert!(validate_distribution(&nodes, &policy).is_err());
    }

    #[test]
    fn test_insufficient_regions() {
        let nodes = vec![node(1, "aws", "us-east-1"), node(2, "gcp", "us-east-1")];
        let policy = DistributionPolicy {
            min_providers: 2,
            min_regions: 2,
            max_per_provider: 5,
        };
        assert!(validate_distribution(&nodes, &policy).is_err());
    }

    #[test]
    fn test_too_many_per_provider() {
        let nodes = vec![
            node(1, "aws", "us-east-1"),
            node(2, "aws", "eu-west-1"),
            node(3, "aws", "ap-southeast-1"),
            node(4, "gcp", "us-west-1"),
        ];
        let policy = DistributionPolicy {
            min_providers: 2,
            min_regions: 2,
            max_per_provider: 2,
        };
        assert!(validate_distribution(&nodes, &policy).is_err());
    }

    #[test]
    fn test_empty_nodes_rejected() {
        assert!(validate_distribution(&[], &DistributionPolicy::default()).is_err());
    }

    #[test]
    fn test_quorum_risk_all_healthy() {
        let reports = vec![
            NodeHealth {
                party_id: PartyId(1),
                status: HealthStatus::Healthy,
                last_heartbeat: 100,
                location: node(1, "aws", "us-east-1"),
            },
            NodeHealth {
                party_id: PartyId(2),
                status: HealthStatus::Healthy,
                last_heartbeat: 100,
                location: node(2, "gcp", "eu-west-1"),
            },
            NodeHealth {
                party_id: PartyId(3),
                status: HealthStatus::Healthy,
                last_heartbeat: 100,
                location: node(3, "azure", "ap-1"),
            },
        ];
        let risk = assess_quorum_risk(&reports, 2);
        assert!(risk.quorum_available);
        assert_eq!(risk.risk_level, 0);
    }

    #[test]
    fn test_quorum_risk_degraded() {
        let reports = vec![
            NodeHealth {
                party_id: PartyId(1),
                status: HealthStatus::Healthy,
                last_heartbeat: 100,
                location: node(1, "aws", "us-east-1"),
            },
            NodeHealth {
                party_id: PartyId(2),
                status: HealthStatus::Healthy,
                last_heartbeat: 100,
                location: node(2, "gcp", "eu-west-1"),
            },
            NodeHealth {
                party_id: PartyId(3),
                status: HealthStatus::Unreachable,
                last_heartbeat: 50,
                location: node(3, "azure", "ap-1"),
            },
        ];
        let risk = assess_quorum_risk(&reports, 2);
        assert!(risk.quorum_available);
        assert_eq!(risk.risk_level, 1);
    }

    #[test]
    fn test_quorum_risk_critical() {
        let reports = vec![
            NodeHealth {
                party_id: PartyId(1),
                status: HealthStatus::Healthy,
                last_heartbeat: 100,
                location: node(1, "aws", "us-east-1"),
            },
            NodeHealth {
                party_id: PartyId(2),
                status: HealthStatus::Unreachable,
                last_heartbeat: 50,
                location: node(2, "gcp", "eu-west-1"),
            },
            NodeHealth {
                party_id: PartyId(3),
                status: HealthStatus::Unreachable,
                last_heartbeat: 50,
                location: node(3, "azure", "ap-1"),
            },
        ];
        let risk = assess_quorum_risk(&reports, 2);
        assert!(!risk.quorum_available);
        assert_eq!(risk.risk_level, 2);
    }

    // ─── RPC Failover tests ─────────────────────────────────────────────

    #[test]
    fn test_rpc_failover_returns_highest_priority_healthy() {
        let pool = RpcFailoverPool::new(vec![
            RpcEndpoint {
                url: "http://primary".into(),
                provider: "alchemy".into(),
                priority: 1,
                healthy: true,
            },
            RpcEndpoint {
                url: "http://backup".into(),
                provider: "infura".into(),
                priority: 2,
                healthy: true,
            },
        ]);
        assert_eq!(pool.next_healthy().unwrap().url, "http://primary");
    }

    #[test]
    fn test_rpc_failover_skips_unhealthy() {
        let mut pool = RpcFailoverPool::new(vec![
            RpcEndpoint {
                url: "http://primary".into(),
                provider: "alchemy".into(),
                priority: 1,
                healthy: true,
            },
            RpcEndpoint {
                url: "http://backup".into(),
                provider: "infura".into(),
                priority: 2,
                healthy: true,
            },
        ]);
        pool.mark_unhealthy("http://primary");
        assert_eq!(pool.next_healthy().unwrap().url, "http://backup");
    }

    #[test]
    fn test_rpc_failover_all_unhealthy_returns_none() {
        let mut pool = RpcFailoverPool::new(vec![RpcEndpoint {
            url: "http://a".into(),
            provider: "x".into(),
            priority: 1,
            healthy: true,
        }]);
        pool.mark_unhealthy("http://a");
        assert!(pool.next_healthy().is_none());
    }

    #[test]
    fn test_rpc_failover_recovery() {
        let mut pool = RpcFailoverPool::new(vec![RpcEndpoint {
            url: "http://a".into(),
            provider: "x".into(),
            priority: 1,
            healthy: true,
        }]);
        pool.mark_unhealthy("http://a");
        assert!(pool.next_healthy().is_none());
        pool.mark_healthy("http://a");
        assert!(pool.next_healthy().is_some());
    }

    // ─── Chaos tests ────────────────────────────────────────────────────

    #[test]
    fn test_can_tolerate_failures_2_of_3() {
        assert!(can_tolerate_failures(2, 3, 1)); // 1 failure ok
        assert!(!can_tolerate_failures(2, 3, 2)); // 2 failures = no quorum
    }

    #[test]
    fn test_healthy_count() {
        let pool = RpcFailoverPool::new(vec![
            RpcEndpoint {
                url: "a".into(),
                provider: "x".into(),
                priority: 1,
                healthy: true,
            },
            RpcEndpoint {
                url: "b".into(),
                provider: "y".into(),
                priority: 2,
                healthy: false,
            },
            RpcEndpoint {
                url: "c".into(),
                provider: "z".into(),
                priority: 3,
                healthy: true,
            },
        ]);
        assert_eq!(pool.healthy_count(), 2);
    }

    // ── Disaster Recovery (RecoveryPlan) tests ───────────────────────────

    fn health_node(
        id: u16,
        provider: &str,
        region: &str,
        status: HealthStatus,
        hb: u64,
    ) -> NodeHealth {
        NodeHealth {
            party_id: PartyId(id),
            status,
            last_heartbeat: hb,
            location: node(id, provider, region),
        }
    }

    #[test]
    fn test_recovery_plan_recoverable() {
        let nodes = vec![
            health_node(1, "aws", "us-1", HealthStatus::Healthy, 100),
            health_node(2, "gcp", "eu-1", HealthStatus::Healthy, 100),
            health_node(3, "azure", "ap-1", HealthStatus::Unreachable, 50),
        ];
        let plan = RecoveryPlan::from_health("group-1", 2, &nodes);
        assert!(plan.is_recoverable());
        assert_eq!(plan.threshold, 2);
        assert_eq!(plan.total_shares, 3);
        assert_eq!(plan.share_locations.len(), 3);
    }

    #[test]
    fn test_recovery_plan_not_recoverable() {
        let nodes = vec![
            health_node(1, "aws", "us-1", HealthStatus::Healthy, 100),
            health_node(2, "gcp", "eu-1", HealthStatus::Unreachable, 50),
            health_node(3, "azure", "ap-1", HealthStatus::Unreachable, 50),
        ];
        let plan = RecoveryPlan::from_health("group-1", 2, &nodes);
        assert!(!plan.is_recoverable());
    }

    #[test]
    fn test_recovery_plan_critical_steps() {
        let nodes = vec![
            health_node(1, "aws", "us-1", HealthStatus::Healthy, 100),
            health_node(2, "gcp", "eu-1", HealthStatus::Unreachable, 50),
            health_node(3, "azure", "ap-1", HealthStatus::Unreachable, 50),
        ];
        let plan = RecoveryPlan::from_health("group-1", 2, &nodes);
        assert!(plan.steps.iter().any(|s| s.contains("CRITICAL")));
    }

    #[test]
    fn test_recovery_plan_normal_steps_when_healthy() {
        let nodes = vec![
            health_node(1, "aws", "us-1", HealthStatus::Healthy, 100),
            health_node(2, "gcp", "eu-1", HealthStatus::Healthy, 100),
            health_node(3, "azure", "ap-1", HealthStatus::Healthy, 100),
        ];
        let plan = RecoveryPlan::from_health("group-1", 2, &nodes);
        assert!(plan.is_recoverable());
        assert!(!plan.steps.iter().any(|s| s.contains("CRITICAL")));
        assert!(plan.steps.iter().any(|s| s.contains("normal key refresh")));
    }
}
