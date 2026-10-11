//! `spike-sign`: the Rust k256 half of the Nile spike's 2-of-2 active permission.
//!
//! TESTNET ONLY. The key lives in a hex file outside the repository; this binary
//! never prints it. TRON signs `txid = sha256(raw_data)` as `r ‖ s ‖ (27 + recid)`.
//!
//! ```text
//! spike-sign keygen  <keyfile>          create a new key (mode 0600, never overwrites); prints its address
//! spike-sign address <keyfile>          prints the key's base58 TRON address
//! spike-sign sign    <keyfile> <txid>   prints the 65-byte signature, hex
//! spike-sign recover <txid> <sig>       prints the signer's address (k256 recover_from_prehash)
//! ```

use std::{env, fs, io::Write, os::unix::fs::OpenOptionsExt, process::ExitCode};

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Base58Check of `0x41 ‖ keccak256(pubkey_xy)[12..]`.
fn tron_address(vk: &VerifyingKey) -> String {
    let point = vk.to_encoded_point(false);
    let mut raw = vec![0x41];
    raw.extend_from_slice(&Keccak256::digest(&point.as_bytes()[1..])[12..]);
    let check = Sha256::digest(Sha256::digest(&raw));
    raw.extend_from_slice(&check[..4]);
    bs58::encode(raw).into_string()
}

// ponytail: the hex buffer is not zeroized; spike keys are throwaway testnet keys.
fn read_key(path: &str) -> Result<SigningKey, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    let bytes = hex::decode(text.trim()).map_err(|_| format!("{path}: not hex"))?;
    SigningKey::from_slice(&bytes).map_err(|_| format!("{path}: not a secp256k1 scalar"))
}

fn txid(arg: &str) -> Result<[u8; 32], String> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(arg, &mut out).map_err(|_| "txid must be 64 hex chars".to_string())?;
    Ok(out)
}

fn run(args: &[String]) -> Result<String, String> {
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["keygen", path] => {
            let key = SigningKey::random(&mut OsRng);
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("create {path}: {e}"))?;
            writeln!(f, "{}", hex::encode(key.to_bytes())).map_err(|e| e.to_string())?;
            f.sync_all().map_err(|e| e.to_string())?;
            Ok(tron_address(key.verifying_key()))
        }
        ["address", path] => Ok(tron_address(read_key(path)?.verifying_key())),
        ["sign", path, id] => {
            // k256 normalises to low-S and adjusts the recovery id.
            let (sig, recid) = read_key(path)?
                .sign_prehash_recoverable(&txid(id)?)
                .map_err(|e| e.to_string())?;
            Ok(format!(
                "{}{:02x}",
                hex::encode(sig.to_bytes()),
                27 + recid.to_byte()
            ))
        }
        ["recover", id, sig] => {
            let bytes = hex::decode(sig).map_err(|_| "sig: not hex".to_string())?;
            let [rs @ .., v] = bytes.as_slice() else {
                return Err("sig: empty".into());
            };
            let sig = Signature::from_slice(rs).map_err(|_| "sig: need r ‖ s ‖ v (65 bytes)")?;
            let recid = v
                .checked_sub(27)
                .and_then(RecoveryId::from_byte)
                .ok_or("sig: v must be 27 or 28")?;
            let vk = VerifyingKey::recover_from_prehash(&txid(id)?, &sig, recid)
                .map_err(|e| format!("recover: {e}"))?;
            Ok(tron_address(&vk))
        }
        _ => Err("usage: spike-sign keygen <keyfile> | address <keyfile> | sign <keyfile> <txid> | recover <txid> <sig>".into()),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("spike-sign: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tron_address_matches_known_vector() {
        // Private key 1: its Ethereum address 0x7E5F4552…29395Bdf is widely published;
        // TRON is Base58Check(0x41 ‖ the same 20 bytes). tronweb 6.3.0 agrees.
        let key = SigningKey::from_slice(&[[0u8; 31].as_slice(), &[1]].concat()).unwrap();
        assert_eq!(
            tron_address(key.verifying_key()),
            "TMVQGm1qAQYVdetCeGRRkTWYYrLXuHK2HC"
        );
    }

    #[test]
    fn sign_then_recover_round_trips_with_low_s() {
        let key = SigningKey::random(&mut OsRng);
        let id: [u8; 32] = Sha256::digest(b"nile-spike").into();
        let (sig, recid) = key.sign_prehash_recoverable(&id).unwrap();
        assert!(sig.normalize_s().is_none(), "k256 signs low-S");
        let vk = VerifyingKey::recover_from_prehash(&id, &sig, recid).unwrap();
        assert_eq!(&vk, key.verifying_key());
    }
}
