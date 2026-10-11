//! Chain data sources.
//!
//! A [`Provider`] serves TRON blocks. [`HttpProvider`] speaks the standard java-tron HTTP API
//! (`/wallet/getnowblock`, `/wallet/getblockbynum`) that the public endpoints expose. It is keyless,
//! spaces its own requests, bounds every call with timeouts, and classifies HTTP 429/403 as rate
//! limiting so the caller can back off ([`Backoff`]).

use std::future::Future;
use std::time::{Duration, Instant};

use reqwest::header::RETRY_AFTER;
use reqwest::StatusCode;
use serde::Deserialize;

/// A block as the watcher needs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    pub height: u64,
    /// `blockID`, lowercase hex; its first 8 bytes are the height, big-endian.
    pub id: String,
    pub parent_id: String,
    pub time_ms: i64,
    pub txs: Vec<Tx>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx {
    pub txid: String,
    /// `ret[0].contractRet` (for example `SUCCESS`), when the provider reports it.
    pub result: Option<String>,
    pub contracts: Vec<Contract>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contract {
    /// For example `TransferContract` or `TriggerSmartContract`.
    pub kind: String,
    /// `owner_address`: 21-byte hex with the `41` prefix, lowercase (empty if absent).
    pub owner: String,
    /// `Permission_id`: 0 is the owner permission, 2–9 are active permissions.
    pub permission_id: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// HTTP 429, or 403, which TronGrid also uses when it limits or blocks a client.
    #[error("rate limited (HTTP {status})")]
    RateLimited {
        status: u16,
        retry_after: Option<Duration>,
    },
    /// Network failure, timeout, another HTTP error, a node error, a block that is not available
    /// yet, or a response that fails validation. Always retried; a height is never skipped.
    #[error("unavailable: {0}")]
    Unavailable(String),
}

/// A source of TRON blocks at latest (unsolidified) height.
pub trait Provider: Send + Sync {
    /// Short, file-name-safe name; it keys the provider's cursor and its events.
    fn name(&self) -> &str;
    /// The provider's current head block.
    fn latest(&self) -> impl Future<Output = Result<Block, ProviderError>> + Send;
    /// The block at `height`; an error if the provider does not have it yet.
    fn block(&self, height: u64) -> impl Future<Output = Result<Block, ProviderError>> + Send;
}

/// A java-tron HTTP endpoint, used without an API key.
pub struct HttpProvider {
    name: String,
    base_url: String,
    client: reqwest::Client,
    min_interval: Duration,
    last_request: tokio::sync::Mutex<Option<Instant>>,
}

impl HttpProvider {
    // ponytail: keyless (TASKS T07-2). The `TRON-PRO-API-KEY` header comes later, with the
    // production keys.
    pub fn new(name: &str, base_url: &str, min_interval: Duration) -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            // ponytail: the total timeout also bounds how much a provider can make us read
            // (a mainnet block is ~0.5 MB); no separate body-size cap.
            .timeout(Duration::from_secs(20))
            .user_agent(concat!("vaultex-monitor/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            name: name.to_owned(),
            base_url: base_url.trim_end_matches('/').to_owned(),
            client,
            min_interval,
            last_request: tokio::sync::Mutex::new(None),
        })
    }

    async fn fetch(
        &self,
        path: &str,
        body: serde_json::Value,
        want: Option<u64>,
    ) -> Result<Block, ProviderError> {
        // Client-side spacing, so a catch-up burst does not trip the provider's limiter.
        {
            let mut last = self.last_request.lock().await;
            if let Some(at) = *last {
                tokio::time::sleep_until((at + self.min_interval).into()).await;
            }
            *last = Some(Instant::now());
        }
        let resp = self
            .client
            .post(format!("{}{path}", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Unavailable(e.without_url().to_string()))?;
        let status = resp.status();
        if status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::FORBIDDEN {
            // ponytail: delta-seconds only; an HTTP-date Retry-After falls back to our backoff.
            let retry_after = resp
                .headers()
                .get(RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            return Err(ProviderError::RateLimited {
                status: status.as_u16(),
                retry_after,
            });
        }
        if !status.is_success() {
            return Err(ProviderError::Unavailable(format!("HTTP {status}")));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ProviderError::Unavailable(e.without_url().to_string()))?;
        parse_block(&bytes, want)
    }
}

impl Provider for HttpProvider {
    fn name(&self) -> &str {
        &self.name
    }

    async fn latest(&self) -> Result<Block, ProviderError> {
        self.fetch("/wallet/getnowblock", serde_json::json!({}), None)
            .await
    }

    async fn block(&self, height: u64) -> Result<Block, ProviderError> {
        self.fetch(
            "/wallet/getblockbynum",
            serde_json::json!({ "num": height }),
            Some(height),
        )
        .await
    }
}

// java-tron block JSON, reduced to what the watcher reads. Unknown fields are ignored; numeric
// fields that protobuf JSON omits at their default value default to zero.
#[derive(Deserialize)]
struct RawBlock {
    #[serde(rename = "blockID")]
    block_id: Option<String>,
    #[serde(rename = "Error")]
    error: Option<String>,
    block_header: Option<RawHeader>,
    #[serde(default)]
    transactions: Vec<RawTx>,
}

#[derive(Deserialize)]
struct RawHeader {
    raw_data: RawHeaderData,
}

#[derive(Deserialize)]
struct RawHeaderData {
    #[serde(default)]
    number: u64,
    #[serde(rename = "parentHash", default)]
    parent_hash: String,
    #[serde(default)]
    timestamp: i64,
}

#[derive(Deserialize)]
struct RawTx {
    #[serde(rename = "txID")]
    txid: String,
    #[serde(default)]
    ret: Vec<RawRet>,
    raw_data: RawTxData,
}

#[derive(Deserialize)]
struct RawRet {
    #[serde(rename = "contractRet")]
    contract_ret: Option<String>,
}

#[derive(Deserialize)]
struct RawTxData {
    #[serde(default)]
    contract: Vec<RawContract>,
}

#[derive(Deserialize)]
struct RawContract {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(rename = "Permission_id", default)]
    permission_id: u32,
    parameter: Option<RawParameter>,
}

#[derive(Deserialize)]
struct RawParameter {
    #[serde(default)]
    value: RawValue,
}

#[derive(Deserialize, Default)]
struct RawValue {
    #[serde(default)]
    owner_address: String,
}

/// Parses and validates a block response. `want` is the height that was asked for, if any.
pub fn parse_block(body: &[u8], want: Option<u64>) -> Result<Block, ProviderError> {
    let unavailable = |msg: String| ProviderError::Unavailable(msg);
    let raw: RawBlock = serde_json::from_slice(body)
        .map_err(|e| unavailable(format!("malformed block JSON: {e}")))?;
    let Some(id) = raw.block_id else {
        // java-tron answers `{}` for a height it does not have yet, and `{"Error": …}` on failure.
        return Err(unavailable(match raw.error {
            Some(e) => format!("node error: {}", clip(&e)),
            None => "block not available".to_owned(),
        }));
    };
    let header = raw
        .block_header
        .ok_or_else(|| unavailable("block without header".to_owned()))?
        .raw_data;
    let id = id.to_ascii_lowercase();
    let hex64 = id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit());
    if !hex64 || u64::from_str_radix(&id[..16], 16) != Ok(header.number) {
        return Err(unavailable(format!(
            "block id {} does not encode height {}",
            clip(&id),
            header.number
        )));
    }
    if let Some(want) = want.filter(|&w| w != header.number) {
        return Err(unavailable(format!(
            "asked for block {want}, got {}",
            header.number
        )));
    }
    let txs = raw
        .transactions
        .into_iter()
        .map(|tx| Tx {
            txid: tx.txid.to_ascii_lowercase(),
            result: tx.ret.into_iter().next().and_then(|r| r.contract_ret),
            contracts: tx
                .raw_data
                .contract
                .into_iter()
                .map(|c| Contract {
                    kind: c.kind,
                    owner: c
                        .parameter
                        .map(|p| p.value.owner_address.to_ascii_lowercase())
                        .unwrap_or_default(),
                    permission_id: c.permission_id,
                })
                .collect(),
        })
        .collect();
    Ok(Block {
        height: header.number,
        id,
        parent_id: header.parent_hash.to_ascii_lowercase(),
        time_ms: header.timestamp,
        txs,
    })
}

/// Provider-supplied text is untrusted: keep at most 120 characters of it in our messages.
fn clip(s: &str) -> String {
    s.chars().take(120).collect()
}

/// Longest provider `Retry-After` we honour; beyond it the provider counts as down meanwhile.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(300);

/// Exponential backoff per provider that honours `Retry-After`. Reset after a success.
pub struct Backoff {
    base: Duration,
    cap: Duration,
    next: Duration,
}

impl Backoff {
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            next: base,
        }
    }

    pub fn reset(&mut self) {
        self.next = self.base;
    }

    /// How long to wait before retrying after `err`.
    // ponytail: no jitter; each provider has its own host and backoff, so there is no herd to spread.
    pub fn delay(&mut self, err: &ProviderError) -> Duration {
        let mut wait = self.next;
        if let ProviderError::RateLimited {
            retry_after: Some(after),
            ..
        } = err
        {
            wait = wait.max((*after).min(MAX_RETRY_AFTER));
        }
        self.next = (self.next * 2).min(self.cap);
        wait
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    // Shape of a live Nile block (`nile.trongrid.io/wallet/getnowblock`, height 71,722,664, fetched
    // 2026-10-11; `api.nileex.io` returned the same block id), trimmed to two transactions. The
    // second transaction is synthetic: an active-permission TRC-20 call.
    const NILE_BLOCK: &str = r#"{
      "blockID": "00000000044666a82a3caffc8dd96964d439fd62fd42c5d01542c86e883ac5ec",
      "block_header": {
        "raw_data": {
          "number": 71722664,
          "txTrieRoot": "4a28c1253ad5eaa4debebeda265bc9592111a90de0c2f163f22bd2cf1d1e1926",
          "witness_address": "416c28585d13602ae332c5de6f73f8e50f697a196b",
          "parentHash": "00000000044666a7e1f41254433f216651093535b87b05eacf83a54e85f01bb6",
          "version": 39,
          "timestamp": 1791698463000
        },
        "witness_signature": "00"
      },
      "transactions": [
        {
          "ret": [{"contractRet": "SUCCESS"}],
          "signature": ["00"],
          "txID": "7590ceb49257f1750e2f9227ec94cf49da2b47a43e53bc5b962fea5d99a90895",
          "raw_data": {
            "contract": [{
              "parameter": {
                "value": {
                  "amount": 168200,
                  "owner_address": "41313bd9f0dc4e4b2a787470b8dea27e58be82fc53",
                  "to_address": "415e33cfa37d730a43063e70ff5381acfc7895e086"
                },
                "type_url": "type.googleapis.com/protocol.TransferContract"
              },
              "type": "TransferContract"
            }],
            "ref_block_bytes": "66a6",
            "ref_block_hash": "0000000000000000",
            "expiration": 1791698520000,
            "timestamp": 1791698460000
          }
        },
        {
          "txID": "1111111111111111111111111111111111111111111111111111111111111111",
          "raw_data": {
            "contract": [{
              "parameter": {
                "value": {"owner_address": "41A614F803B6FD780986A42C78EC9C7F77E6DED13C", "data": "a9059cbb"},
                "type_url": "type.googleapis.com/protocol.TriggerSmartContract"
              },
              "type": "TriggerSmartContract",
              "Permission_id": 2
            }]
          }
        }
      ]
    }"#;

    #[test]
    fn parses_a_live_shaped_block() {
        let b = parse_block(NILE_BLOCK.as_bytes(), Some(71_722_664)).unwrap();
        assert_eq!(b.height, 71_722_664);
        assert_eq!(
            b.parent_id,
            "00000000044666a7e1f41254433f216651093535b87b05eacf83a54e85f01bb6"
        );
        assert_eq!(b.time_ms, 1_791_698_463_000);
        assert_eq!(b.txs.len(), 2);
        assert_eq!(b.txs[0].result.as_deref(), Some("SUCCESS"));
        assert_eq!(
            b.txs[0].contracts,
            vec![Contract {
                kind: "TransferContract".into(),
                owner: "41313bd9f0dc4e4b2a787470b8dea27e58be82fc53".into(),
                permission_id: 0,
            }]
        );
        // Hex is normalised to lowercase; a missing `ret` stays None.
        assert_eq!(b.txs[1].result, None);
        assert_eq!(
            b.txs[1].contracts[0].owner,
            "41a614f803b6fd780986a42c78ec9c7f77e6ded13c"
        );
        assert_eq!(b.txs[1].contracts[0].permission_id, 2);
    }

    #[test]
    fn refuses_missing_inconsistent_or_unrequested_blocks() {
        let unavailable = |body: &str, want| {
            matches!(
                parse_block(body.as_bytes(), want),
                Err(ProviderError::Unavailable(_))
            )
        };
        // A height the node does not have yet (VERIFIED: Nile answers `{}`), and a node error.
        assert!(unavailable("{}", Some(5)));
        assert!(unavailable(
            r#"{"Error":"class java.lang.NullPointerException"}"#,
            None
        ));
        assert!(unavailable("<html>busy</html>", None));
        // The block id must encode the header's height.
        let wrong_height = NILE_BLOCK.replace("\"number\": 71722664", "\"number\": 71722665");
        assert!(unavailable(&wrong_height, None));
        // The provider must answer the height that was asked for.
        assert!(unavailable(NILE_BLOCK, Some(71_722_663)));
    }

    /// Serves one canned HTTP response per connection and returns each request (head and body).
    async fn mock_server(responses: Vec<String>) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move {
            let mut requests = Vec::new();
            for response in responses {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read the whole request (head and body) before answering.
                loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).to_string();
                    let complete = text.find("\r\n\r\n").is_some_and(|end| {
                        let len = text[..end]
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .map(|v| v.trim().parse::<usize>().unwrap())
                            })
                            .unwrap_or(0);
                        buf.len() >= end + 4 + len
                    });
                    if complete || n == 0 {
                        requests.push(text);
                        break;
                    }
                }
                sock.write_all(response.as_bytes()).await.unwrap();
                sock.shutdown().await.unwrap();
            }
            requests
        });
        (url, handle)
    }

    fn http(status: &str, extra_headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
            body.len()
        )
    }

    #[tokio::test]
    async fn http_provider_classifies_rate_limits_and_errors() {
        let (url, server) = mock_server(vec![
            http("429 Too Many Requests", "Retry-After: 7\r\n", ""),
            http("403 Forbidden", "", "blocked"),
            http("503 Service Unavailable", "", ""),
            http("200 OK", "Content-Type: application/json\r\n", NILE_BLOCK),
        ])
        .await;
        let p = HttpProvider::new("mock", &format!("{url}/"), Duration::ZERO).unwrap();

        match p.block(71_722_664).await {
            Err(ProviderError::RateLimited {
                status: 429,
                retry_after,
            }) => assert_eq!(retry_after, Some(Duration::from_secs(7))),
            other => panic!("expected 429, got {other:?}"),
        }
        assert!(matches!(
            p.block(71_722_664).await,
            Err(ProviderError::RateLimited {
                status: 403,
                retry_after: None
            })
        ));
        assert!(matches!(
            p.latest().await,
            Err(ProviderError::Unavailable(_))
        ));
        assert_eq!(p.block(71_722_664).await.unwrap().height, 71_722_664);

        let requests = server.await.unwrap();
        assert!(requests[0].starts_with("POST /wallet/getblockbynum "));
        assert!(requests[0].ends_with(r#"{"num":71722664}"#));
        assert!(requests[2].starts_with("POST /wallet/getnowblock "));
        // Keyless: no API-key header is ever sent.
        assert!(requests
            .iter()
            .all(|r| !r.to_ascii_lowercase().contains("tron-pro-api-key")));
    }

    #[tokio::test]
    async fn http_provider_spaces_its_requests() {
        let ok = http("200 OK", "", NILE_BLOCK);
        let (url, server) = mock_server(vec![ok.clone(), ok]).await;
        let p = HttpProvider::new("mock", &url, Duration::from_millis(200)).unwrap();
        let started = Instant::now();
        p.latest().await.unwrap();
        p.latest().await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(200));
        server.await.unwrap();
    }

    #[test]
    fn backoff_doubles_to_its_cap_honours_retry_after_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(4));
        let down = ProviderError::Unavailable("x".into());
        let secs: Vec<u64> = (0..4).map(|_| b.delay(&down).as_secs()).collect();
        assert_eq!(secs, [1, 2, 4, 4]);

        b.reset();
        let limited = |s| ProviderError::RateLimited {
            status: 429,
            retry_after: Some(Duration::from_secs(s)),
        };
        assert_eq!(b.delay(&limited(30)), Duration::from_secs(30));
        // An absurd Retry-After is capped.
        assert_eq!(b.delay(&limited(86_400)), MAX_RETRY_AFTER);
        b.reset();
        assert_eq!(b.delay(&down), Duration::from_secs(1));
    }
}
