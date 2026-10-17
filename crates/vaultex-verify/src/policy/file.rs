//! [`PolicyStore`]: the installed policy of one signer, in one file (ADR-11).
//!
//! # Durability
//!
//! - **Offer:** the new state is computed in memory ([`PolicyState::offer`]), written whole to
//!   `<path>.tmp`, synced, renamed over `path`, and the directory entry synced; only then does the
//!   offer answer and the new state apply. After a crash the file holds the old or the new state.
//!   After a failed write the store refuses every offer until it is reopened: the rename may have
//!   happened, so only the file tells which state is installed.
//! - **One process:** `<path>.lock` is locked exclusively while the store is open.
//! - **Open:** no file means nothing is installed (every request refuses `NO_POLICY`). A file is
//!   decoded strictly and re-checked as the [module docs](super#limits) say; a file that fails
//!   refuses to open. It must be restored, not repaired.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use vaultex_types::{from_canonical_strict, to_canonical};

use super::{
    AdminSetV1, Offer, Pending, PolicyRefusal, PolicyState, SignedPolicyBundleV1, VerifiedBundle,
};
use crate::durable::{self, io_err};
use crate::velocity::StoreError;

/// The installed file: BCS of this. `anchor` is the digest of the quorum bundle that started the
/// active bundle's epoch (an earlier bundle when the active one is a step, so it is kept here);
/// `received_at_ms` is this signer's own record of when it received the pending bundle.
#[derive(Serialize, Deserialize)]
struct InstalledV1 {
    active: SignedPolicyBundleV1,
    anchor: [u8; 32],
    pending: Option<(SignedPolicyBundleV1, u64)>,
}

/// The installed policy of one signer: a [`PolicyState`] kept in a file. See the
/// [module docs](super) for the checks and the states.
#[derive(Debug)]
pub struct PolicyStore {
    path: PathBuf,
    genesis: AdminSetV1,
    state: PolicyState,
    failed: bool,
    _lock: File,
}

impl PolicyStore {
    /// Opens the policy installed at `path` (none if the file does not exist yet) and locks it.
    /// `genesis` is the admin set pinned at setup; it judges the first bundle only.
    pub fn open(path: impl AsRef<Path>, genesis: AdminSetV1) -> Result<Self, PolicyRefusal> {
        let path = path.as_ref().to_path_buf();
        let lock = durable::open_locked(&durable::sibling(&path, ".lock"))
            .map_err(PolicyRefusal::Store)?;
        let state = match fs::read(&path) {
            Ok(bytes) => load(&bytes)?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => PolicyState::default(),
            Err(e) => return Err(PolicyRefusal::Store(io_err(e))),
        };
        Ok(Self {
            path,
            genesis,
            state,
            failed: false,
            _lock: lock,
        })
    }

    /// Offers the signed bundle `bytes`, received at `now_ms` (this signer's clock): checks it,
    /// records the new state durably, and only then answers. A refusal changes nothing.
    pub fn offer(&mut self, bytes: &[u8], now_ms: u64) -> Result<Offer, PolicyRefusal> {
        if self.failed {
            return Err(PolicyRefusal::Store(StoreError::Failed));
        }
        let (next, offer) = self.state.offer(&self.genesis, bytes, now_ms)?;
        if let Err(e) = durable::replace(&self.path, &save(&next)?) {
            self.failed = true;
            return Err(PolicyRefusal::Store(io_err(e)));
        }
        self.state = next;
        Ok(offer)
    }

    /// The installed state: what requests go by.
    pub fn state(&self) -> &PolicyState {
        &self.state
    }
}

fn save(state: &PolicyState) -> Result<Vec<u8>, PolicyRefusal> {
    // An offer always leaves an active bundle.
    let active = state.active.as_ref().ok_or(PolicyRefusal::NoPolicy)?;
    let file = InstalledV1 {
        active: active.signed.clone(),
        anchor: state.anchor,
        pending: state
            .pending
            .as_ref()
            .map(|p| (p.bundle.signed.clone(), p.received_at_ms)),
    };
    to_canonical(&file).map_err(|_| PolicyRefusal::Store(StoreError::TooLarge))
}

/// Decodes the installed file: both bundles pass step 2; an active quorum bundle is its own
/// anchor; and the pending one, always a quorum loosening, passes steps 3, 6, 7 and 8 against the
/// active one again: its version is above the active one's (possibly by several epochs, when it
/// replaced earlier pending bundles) and its parent is the anchor.
fn load(bytes: &[u8]) -> Result<PolicyState, PolicyRefusal> {
    let file = from_canonical_strict::<InstalledV1>(bytes).map_err(|_| PolicyRefusal::Malformed)?;
    let active = VerifiedBundle::check(file.active)?;
    if active.body().seq == 0 && file.anchor != active.digest() {
        return Err(PolicyRefusal::ParentMismatch);
    }
    let pending = match file.pending {
        None => None,
        Some((signed, received_at_ms)) => {
            let bundle = VerifiedBundle::check(signed)?;
            if bundle.version() <= active.version() {
                return Err(PolicyRefusal::Rollback);
            }
            if bundle.body().parent != file.anchor {
                return Err(PolicyRefusal::ParentMismatch);
            }
            let admins = &active.body().admins;
            if bundle.signers(admins)? < usize::from(admins.threshold) {
                return Err(PolicyRefusal::Quorum);
            }
            Some(Pending::new(bundle, received_at_ms, &active)?)
        }
    };
    Ok(PolicyState {
        active: Some(active),
        anchor: file.anchor,
        pending,
    })
}
