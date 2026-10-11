//! Vaultex wire contracts, v0 (ROADMAP M5 #11). Working name until ADR-12.
//!
//! These are the types that the verifier kernel (`vaultex-verify`), the Guard, the outflow
//! monitor and the admin CLIs exchange. They carry no behaviour beyond validation, canonical
//! encoding and digests: decoding transactions, evaluating policy and signing receipts belong to
//! the kernel.
//!
//! # Status
//!
//! **Draft.** Layouts may still change while the `INTENT_V1` and `RECEIPT_V1` RFCs are open for
//! comment; vectors are regenerated when they do. They freeze at M6 exit (crate 0.2), and in any
//! case before the first receipt over real chain data. After the freeze, a layout change is a new
//! type with a new tag version.
//!
//! # Contract rules
//!
//! Every type here, and every signed type built on it, follows these rules:
//!
//! 1. **Encoding.** Everything that is signed or hashed is BCS, with field order = declaration
//!    order ([`to_canonical`]). JSON may be offered as a view for humans and REST, and is never
//!    signed or hashed.
//! 2. **Digests are domain-separated.** `tagged_digest(tag, v) = SHA-256(BCS(tag) ‖ BCS(v))`, where
//!    `BCS(tag)` is the length-prefixed ASCII tag `VAULTEX/<NAME>/v<N>` ([`tag`]), so tags are
//!    prefix-free. Tags are protocol constants and do not follow product renames.
//! 3. **Signatures** are Ed25519 over the 32-byte tagged digest.
//! 4. **No ambiguous encodings in signed types:** no maps or sets, floats, `char`, `usize`,
//!    skipped or flattened fields, or untagged enums.
//! 5. **64-byte values** encode as 64 raw bytes ([`Sig64`]), never as a length-prefixed slice.
//! 6. **Strings are ASCII and validated at construction** ([`WalletId`], [`NetworkId`]); signed
//!    types have no free-text fields.
//! 7. **Registries** ([`ChainId`], [`RefusalCode`]) are `u16` codes, append-only and never reused.
//!    An unknown code still decodes, so an older peer can log it.
//! 8. **Data-carrying enums are append-only** (`#[non_exhaustive]`). An unknown variant is a
//!    decode error, which fails closed.
//! 9. **One key, one purpose.** A verifier accepts a signature only under a tag that belongs to
//!    the key's registered purpose.
//! 10. **Strict decoding.** [`from_canonical_strict`] caps the size before decoding, rejects
//!     trailing or non-canonical input, and requires re-encoding to be byte-equal. Decoders in
//!     other languages must apply the same re-encode check.
//! 11. **Size caps** are checked before decode ([`MAX_MESSAGE_BYTES`], [`MAX_RAW_TX_BYTES`],
//!     [`MAX_APPROVALS`]).
//! 12. **No clock, I/O or randomness** in this crate (enforced by its `clippy.toml`). "Now" and
//!     storage are parameters of kernel functions.
//!
//! # Versioning
//!
//! A wire version is carried in the tag (`…/v1`) and, for requests and responses, in a leading
//! `version: u16`. Verifiers accept request versions N and N−1, and keep a decoder for every
//! receipt version ever released, so old evidence verifies forever. Readers upgrade before
//! writers.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod encoding;
mod guard;
mod ids;
mod intent;
mod receipt;
mod refusal;
mod statement;

pub use encoding::{
    from_canonical_strict, tag, tagged_digest, to_canonical, Error, MAX_APPROVALS,
    MAX_MESSAGE_BYTES, MAX_RAW_TX_BYTES,
};
pub use guard::{
    GuardMode, GuardRequestV1, GuardResponseV1, SignatureV1, TxContextV1, VerifyRequestV1,
    GUARD_API_VERSION,
};
pub use ids::{
    Address, ChainId, Ed25519Pub, IntentDigest, NetworkId, ReceiptDigest, RequestId, Sig64, TxHash,
    VerifierVersion, WalletId, U256,
};
pub use intent::{AssetId, EcdsaHash, IntentV1, SignInput};
pub use receipt::{ReceiptBodyV1, ReceiptV1};
pub use refusal::{Decision, Refusal, RefusalCode};
pub use statement::{AdminAction, AdminActionV1, ApprovalStatementV1, Role, SignedStatementV1};
