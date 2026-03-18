//! Real Redis implementations for session, replay, and revocation backends.
//!
//! Requires `REDIS_URL` environment variable (e.g., `redis://localhost:6379`
//! or `rediss://user:pass@host:6379` for TLS).

use async_trait::async_trait;
use redis::AsyncCommands;

use super::session_redis::RedisClient;
use crate::state::{ReplayCacheBackend, RevocationBackend};

/// Real Redis client wrapping `redis::aio::ConnectionManager`.
///
/// `ConnectionManager` automatically reconnects on failure — no manual
/// connection pool management needed.
#[derive(Clone)]
pub struct RealRedisClient {
    pub conn: redis::aio::ConnectionManager,
}

impl RealRedisClient {
    /// Connect to Redis. `url` supports `redis://` and `rediss://` (TLS).
    pub async fn connect(url: &str) -> Result<Self, String> {
        let client = redis::Client::open(url).map_err(|e| format!("Redis client open: {e}"))?;
        let conn = client
            .get_connection_manager()
            .await
            .map_err(|e| format!("Redis connect: {e}"))?;
        tracing::info!("Redis connected");
        Ok(Self { conn })
    }
}

#[async_trait]
impl RedisClient for RealRedisClient {
    async fn set_ex(&self, key: &str, value: &str, ttl_secs: u64) -> Result<bool, String> {
        let mut conn = self.conn.clone();
        conn.set_ex::<_, _, ()>(key, value, ttl_secs)
            .await
            .map_err(|e| format!("Redis SET: {e}"))?;
        Ok(true)
    }

    async fn get(&self, key: &str) -> Result<Option<String>, String> {
        let mut conn = self.conn.clone();
        let val: Option<String> = conn.get(key).await.map_err(|e| format!("Redis GET: {e}"))?;
        Ok(val)
    }

    async fn del(&self, key: &str) -> Result<bool, String> {
        let mut conn = self.conn.clone();
        let count: i64 = conn.del(key).await.map_err(|e| format!("Redis DEL: {e}"))?;
        Ok(count > 0)
    }

    async fn count_keys(&self, pattern: &str) -> Result<usize, String> {
        let mut conn = self.conn.clone();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("Redis KEYS: {e}"))?;
        Ok(keys.len())
    }

    async fn scan_keys(&self, pattern: &str) -> Result<Vec<String>, String> {
        let mut conn = self.conn.clone();
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("Redis KEYS: {e}"))?;
        Ok(keys)
    }
}

// ── Redis Replay Cache Backend ────────────────────────────────────

/// Replay cache backed by Redis. Each nonce is stored with a TTL.
#[derive(Clone)]
pub struct RedisReplayBackend {
    conn: redis::aio::ConnectionManager,
    prefix: String,
}

impl RedisReplayBackend {
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self {
            conn,
            prefix: "replay:".into(),
        }
    }
}

#[async_trait]
impl ReplayCacheBackend for RedisReplayBackend {
    async fn check_and_record(&self, nonce: &str, ttl_secs: u64) -> bool {
        let key = format!("{}{}", self.prefix, nonce);
        let mut conn = self.conn.clone();

        // NX = set only if not exists. Returns true if set (not replay), false if exists (replay).
        let result: Result<bool, _> = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(true) => false, // newly set = not a replay
            Ok(false) => true, // already exists = replay
            Err(e) => {
                tracing::error!(error = %e, "Redis replay check failed");
                false // fail open (rate limiter catches abuse)
            }
        }
    }

    async fn prune(&self) -> usize {
        // Redis handles TTL expiry automatically — no manual prune needed.
        0
    }
}

// ── Redis Revocation Backend ──────────────────────────────────────

/// Revocation store backed by a Redis SET.
#[derive(Clone)]
pub struct RedisRevocationBackend {
    conn: redis::aio::ConnectionManager,
    key: String,
}

impl RedisRevocationBackend {
    pub fn new(conn: redis::aio::ConnectionManager) -> Self {
        Self {
            conn,
            key: "revoked_keys".into(),
        }
    }

    /// Load initial revoked keys into Redis (from config file at startup).
    pub async fn load_initial(&self, keys: &[String]) -> Result<(), String> {
        if keys.is_empty() {
            return Ok(());
        }
        let mut conn = self.conn.clone();
        for key_id in keys {
            let _: () = conn
                .sadd(&self.key, key_id)
                .await
                .map_err(|e| format!("Redis SADD: {e}"))?;
        }
        tracing::info!(count = keys.len(), "loaded revoked keys into Redis");
        Ok(())
    }
}

#[async_trait]
impl RevocationBackend for RedisRevocationBackend {
    async fn is_revoked(&self, key_id: &str) -> bool {
        let mut conn = self.conn.clone();
        let result: Result<bool, _> = conn.sismember(&self.key, key_id).await;
        result.unwrap_or(false)
    }

    async fn revoke(&self, key_id: String) -> bool {
        let mut conn = self.conn.clone();
        let result: Result<i64, _> = conn.sadd(&self.key, &key_id).await;
        result.unwrap_or(0) > 0
    }

    async fn list(&self) -> Vec<String> {
        let mut conn = self.conn.clone();
        let result: Result<Vec<String>, _> = conn.smembers(&self.key).await;
        result.unwrap_or_default()
    }
}
