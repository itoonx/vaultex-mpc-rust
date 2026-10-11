//! Release freeze (ROADMAP M5 #5).
//!
//! Until the full independent audit (M10-F) closes, the node refuses key
//! generation, raw-digest signing and every legacy scheme; only a debug build
//! may lift those three, with the `dev-unfreeze` feature, for testnet
//! development. Any network other than testnet/devnet is refused in every
//! build, `dev-unfreeze` included.

use std::fmt::Display;

use mpc_wallet_core::types::CryptoScheme;

/// `true` unless this is a debug build with the `dev-unfreeze` feature.
pub const FROZEN: bool = !cfg!(feature = "dev-unfreeze");

#[cfg(all(feature = "dev-unfreeze", not(debug_assertions)))]
compile_error!(
    "`dev-unfreeze` is for debug builds only: release builds stay frozen until M10-F (ROADMAP M5 #5)"
);

fn refused(what: impl Display) -> String {
    format!("release freeze: {what} is refused in this build")
}

/// Refuse `what` when the build is frozen.
pub fn refuse_if_frozen(what: impl Display) -> Result<(), String> {
    if FROZEN {
        return Err(refused(what));
    }
    Ok(())
}

/// Only testnet and devnet are allowed; anything else fails closed in every build.
pub fn check_network(network: &str) -> Result<(), String> {
    if matches!(network, "testnet" | "devnet") {
        return Ok(());
    }
    Err(refused(format_args!("network '{network}'")))
}

/// Refuse every legacy scheme.
pub fn check_scheme(scheme: CryptoScheme) -> Result<(), String> {
    // Exhaustive on purpose: a new scheme does not compile until it is classified here.
    // ponytail: same table as the gateway's wallets.rs; one copy once WS-03 lands shared types.
    let legacy = match scheme {
        CryptoScheme::Gg20Ecdsa
        | CryptoScheme::Cggmp21Secp256k1
        | CryptoScheme::FrostEd25519
        | CryptoScheme::FrostSecp256k1Tr
        | CryptoScheme::Sr25519Threshold
        | CryptoScheme::StarkThreshold
        | CryptoScheme::Bls12_381Threshold => true,
    };
    if legacy {
        return refuse_if_frozen(format_args!("legacy scheme '{scheme}'"));
    }
    Ok(())
}
