use clap::Args;
use mpc_wallet_chains::provider::Chain;
use mpc_wallet_chains::registry::ChainRegistry;
use mpc_wallet_core::key_store::types::KeyGroupId;
use mpc_wallet_core::protocol::KeyShare;
use mpc_wallet_core::types::PartyId;

use crate::output::{self, CliResult, OutputFormat};

#[derive(Args)]
pub struct ExportAddressArgs {
    /// Key group ID
    #[arg(long)]
    pub key_group: String,

    /// Target blockchain
    #[arg(long, value_parser = parse_chain)]
    pub chain: Chain,

    /// Password for key decryption
    #[arg(long)]
    pub password: Option<String>,
}

fn parse_chain(s: &str) -> Result<Chain, String> {
    s.parse()
}

pub async fn run(args: ExportAddressArgs, format: OutputFormat) -> anyhow::Result<()> {
    let group_id = KeyGroupId::from_string(args.key_group);
    let password = match args.password {
        Some(p) => p,
        None => rpassword::prompt_password("Enter wallet password: ")
            .map_err(|e| anyhow::anyhow!("Failed to read password: {e}"))?,
    };

    let store = mpc_wallet_core::key_store::encrypted::EncryptedFileStore::new(
        crate::config::key_store_dir(),
        &password,
    );

    // Load party 1's key share (any party's share has the same group public key)
    use mpc_wallet_core::key_store::KeyStore;
    let share = store.load(&group_id, PartyId(1)).await?;

    let result = export(args.chain, &group_id, &share)?;
    output::print_result(&result, format);
    Ok(())
}

/// Chain gating: a refusal, not an address, for an unverified chain or for a
/// scheme whose signatures cannot spend from the chain's address.
fn export(chain: Chain, group_id: &KeyGroupId, share: &KeyShare) -> anyhow::Result<CliResult> {
    let address = ChainRegistry::default_mainnet().derive_address(
        chain,
        share.scheme,
        &share.group_public_key,
    )?;
    Ok(CliResult {
        status: "success".into(),
        message: format!("Address for {group_id} on {chain}"),
        data: Some(serde_json::json!({
            "address": address,
            "chain": chain.to_string(),
            "group_id": group_id.to_string(),
        })),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mpc_wallet_core::protocol::GroupPublicKey;
    use mpc_wallet_core::types::{CryptoScheme, ThresholdConfig};

    /// A share with no secret material: export only reads the scheme and group key.
    fn share(scheme: CryptoScheme, group_public_key: GroupPublicKey) -> KeyShare {
        KeyShare {
            scheme,
            party_id: PartyId(1),
            config: ThresholdConfig::new(2, 3).unwrap(),
            group_public_key,
            share_data: Default::default(),
            chain_code: None,
            is_derived: false,
        }
    }

    fn secp256k1_key() -> GroupPublicKey {
        // secp256k1 generator, compressed
        GroupPublicKey::Secp256k1(
            hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
        )
    }

    fn assert_gated(result: anyhow::Result<CliResult>, what: &str) {
        let Err(err) = result else {
            panic!("{what}: expected a chain-gating refusal, got an address");
        };
        assert!(err.to_string().contains("chain gating: "), "{what}: {err}");
    }

    #[test]
    fn export_address_never_shows_frost_tr_a_p2wpkh_address() {
        let group = KeyGroupId::from_string("g".into());
        let frost_tr = share(CryptoScheme::FrostSecp256k1Tr, secp256k1_key());
        for chain in [Chain::BitcoinTestnet, Chain::BitcoinMainnet] {
            assert_gated(export(chain, &group, &frost_tr), &chain.to_string());
        }

        let gg20 = share(CryptoScheme::Gg20Ecdsa, secp256k1_key());
        let ok = export(Chain::BitcoinTestnet, &group, &gg20).unwrap();
        let addr = ok.data.unwrap()["address"].as_str().unwrap().to_owned();
        assert!(addr.starts_with("tb1q"), "{addr}");
    }

    #[test]
    fn export_address_refuses_unverified_chains() {
        let group = KeyGroupId::from_string("g".into());
        let gg20 = share(CryptoScheme::Gg20Ecdsa, secp256k1_key());
        let mut ed = vec![0x66; 32];
        ed[0] = 0x58; // Ed25519 base point, compressed
        let frost_ed = share(CryptoScheme::FrostEd25519, GroupPublicKey::Ed25519(ed));

        for chain in [Chain::Polygon, Chain::Litecoin, Chain::CosmosHub] {
            assert_gated(export(chain, &group, &gg20), &chain.to_string());
        }
        for chain in [Chain::Ton, Chain::Monero, Chain::Movement] {
            assert_gated(export(chain, &group, &frost_ed), &chain.to_string());
        }
        // A scheme whose signatures cannot spend from the chain's address.
        assert_gated(export(Chain::Solana, &group, &gg20), "solana / gg20");
        assert_gated(
            export(Chain::Ethereum, &group, &frost_ed),
            "ethereum / frost-ed25519",
        );

        // Verified chains are still served.
        assert!(export(Chain::Ethereum, &group, &gg20).is_ok());
        assert!(export(Chain::Solana, &group, &frost_ed).is_ok());
    }
}
