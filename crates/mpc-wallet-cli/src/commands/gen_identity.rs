//! `gen-identity` — generate a fresh Ed25519 keypair for node/gateway identity.
//!
//! MPC nodes need a `NODE_SIGNING_KEY` (Ed25519 private seed, hex) and a
//! `GATEWAY_PUBKEY` (Ed25519 public key, hex). The gateway public key must be a
//! valid curve point, so it cannot be produced by `openssl rand`; it has to be
//! derived from a real private key. This subcommand keeps that derivation inside
//! audited Rust (`ed25519-dalek`) rather than hand-rolled shell crypto, and emits
//! both halves so a wrapper script can populate an env-file in one call.
//!
//! Output (JSON):
//! ```json
//! { "signing_key_hex": "<64 hex>", "verifying_key_hex": "<64 hex>" }
//! ```

use clap::Args;
use ed25519_dalek::SigningKey;
use rand::RngCore;

use crate::output::OutputFormat;

#[derive(Args)]
pub struct GenIdentityArgs {
    /// Optional label, echoed in text output only (e.g. "node" or "gateway").
    #[arg(long)]
    pub label: Option<String>,
}

pub async fn run(args: GenIdentityArgs, format: OutputFormat) -> anyhow::Result<()> {
    // Generate a 32-byte seed from the OS CSPRNG and derive the Ed25519 keypair.
    // Using `from_bytes(seed)` (rather than `SigningKey::generate`) keeps this
    // robust across `rand` versions.
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let signing_key_hex = hex::encode(signing_key.to_bytes());
    let verifying_key_hex = hex::encode(signing_key.verifying_key().to_bytes());

    match format {
        OutputFormat::Json => {
            let obj = serde_json::json!({
                "signing_key_hex": signing_key_hex,
                "verifying_key_hex": verifying_key_hex,
            });
            println!("{}", serde_json::to_string_pretty(&obj)?);
        }
        OutputFormat::Text => {
            if let Some(label) = &args.label {
                println!("# identity: {label}");
            }
            println!("signing_key_hex={signing_key_hex}");
            println!("verifying_key_hex={verifying_key_hex}");
        }
    }
    Ok(())
}
