//! Rolling BLAKE3 root: the only root algorithm in this slice.
//!
//! `R_0 = BLAKE3(domain-separated genesis)` and
//! `R_n = BLAKE3(tag || R_{n-1} || canonical_frame_n)` where the tag binds
//! the algorithm id, frame-codec version, boot/session identity, and
//! sequence. The previous root also rides inside the canonical frame for
//! authenticity, but the fold consumes `R_{n-1}` directly, so there is no
//! second encoding of the root.

use blake3::Hasher;
use spin::{Mutex, MutexGuard};
use zeroize::Zeroize;

use super::types::BootSessionId;

pub(crate) const ROOT_LEN: usize = 32;

pub(crate) const ROOT_ALGORITHM_ID: &[u8] = b"BLAKE3-256";
pub(crate) const ROOT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-root.v1";
pub(crate) const GENESIS_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-genesis.v1";
pub(crate) const CHECKPOINT_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-checkpoint.v1";
pub(crate) const ACK_DOMAIN_TAG: &[u8] = b"astrid.native-kernel.audit-ack.v1";
pub(crate) const VERIFIER_HANDOFF_DOMAIN_TAG: &[u8] =
    b"astrid.native-kernel.audit-verifier-handoff.v1";

/// Reusable unkeyed BLAKE3 state owned by one live audit chain. Construction
/// happens during boot custody provisioning, never on the syscall path.
pub(crate) struct RootHasher(Mutex<Hasher>);

impl RootHasher {
    pub(crate) fn new() -> Self {
        Self(Mutex::new(Hasher::new()))
    }

    fn lock(&self) -> MutexGuard<'_, Hasher> {
        self.0.lock()
    }

    pub(crate) fn genesis(&self, boot: BootSessionId) -> [u8; ROOT_LEN] {
        let mut hasher = self.lock();
        hasher.update(GENESIS_DOMAIN_TAG);
        hasher.update(&boot.bytes());
        hasher.update(&super::CODEC_VERSION.to_le_bytes());
        hasher.finalize().into()
    }

    pub(crate) fn advance(
        &self,
        previous_root: [u8; ROOT_LEN],
        boot: BootSessionId,
        seq: u64,
        frame: &[u8],
    ) -> [u8; ROOT_LEN] {
        let mut hasher = self.lock();
        hasher.reset();
        hasher.update(ROOT_DOMAIN_TAG);
        hasher.update(ROOT_ALGORITHM_ID);
        hasher.update(&super::CODEC_VERSION.to_le_bytes());
        hasher.update(&boot.bytes());
        hasher.update(&seq.to_le_bytes());
        hasher.update(&previous_root);
        hasher.update(frame);
        hasher.finalize().into()
    }
}

impl Drop for RootHasher {
    fn drop(&mut self) {
        self.0.get_mut().zeroize();
    }
}

/// Reusable keyed BLAKE3 state owned by one kernel authentication context.
/// The context is move-only and constructs this before any domain can run.
pub(crate) struct TagHasher {
    boot: BootSessionId,
    hasher: Mutex<Hasher>,
}

impl TagHasher {
    pub(crate) fn new(boot: BootSessionId, verification_key: &[u8; ROOT_LEN]) -> Self {
        Self {
            boot,
            hasher: Mutex::new(Hasher::new_keyed(verification_key)),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Hasher> {
        self.hasher.lock()
    }

    pub(crate) fn reset(&self) {
        self.lock().reset();
    }

    pub(crate) fn erase(&mut self) {
        self.hasher.get_mut().zeroize();
    }

    pub(crate) fn checkpoint_tag(
        &self,
        boot: BootSessionId,
        seq: u64,
        root: [u8; ROOT_LEN],
        relay_generation: u64,
        authority_id: u64,
    ) -> [u8; ROOT_LEN] {
        if boot != self.boot {
            return [0; ROOT_LEN];
        }
        let mut hasher = self.lock();
        hasher.reset();
        hasher.update(CHECKPOINT_DOMAIN_TAG);
        hasher.update(&super::CODEC_VERSION.to_le_bytes());
        hasher.update(&boot.bytes());
        hasher.update(&seq.to_le_bytes());
        hasher.update(&root);
        hasher.update(&relay_generation.to_le_bytes());
        hasher.update(&authority_id.to_le_bytes());
        hasher.finalize().into()
    }

    pub(crate) fn ack_tag(
        &self,
        boot: BootSessionId,
        relay_generation: u64,
        seq: u64,
        source_root: [u8; ROOT_LEN],
        frame: &[u8],
        authority_id: u64,
    ) -> [u8; ROOT_LEN] {
        if boot != self.boot {
            return [0; ROOT_LEN];
        }
        let mut hasher = self.lock();
        hasher.reset();
        hasher.update(ACK_DOMAIN_TAG);
        hasher.update(&super::CODEC_VERSION.to_le_bytes());
        hasher.update(&authority_id.to_le_bytes());
        hasher.update(&boot.bytes());
        hasher.update(&relay_generation.to_le_bytes());
        hasher.update(&seq.to_le_bytes());
        hasher.update(&source_root);
        hasher.update(frame);
        hasher.finalize().into()
    }

    pub(crate) fn verifier_handoff_tag(
        &self,
        boot: BootSessionId,
        authority_id: u64,
    ) -> [u8; ROOT_LEN] {
        if boot != self.boot {
            return [0; ROOT_LEN];
        }
        let mut hasher = self.lock();
        hasher.reset();
        hasher.update(VERIFIER_HANDOFF_DOMAIN_TAG);
        hasher.update(&super::CODEC_VERSION.to_le_bytes());
        hasher.update(&boot.bytes());
        hasher.update(&authority_id.to_le_bytes());
        hasher.finalize().into()
    }
}

impl Drop for TagHasher {
    fn drop(&mut self) {
        self.hasher.get_mut().zeroize();
    }
}
