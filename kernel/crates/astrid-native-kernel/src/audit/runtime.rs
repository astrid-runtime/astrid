//! One boot-scoped custody set: chain signer and native verifier anchor.

use spin::Mutex;

use super::chain::{AuditChain, AuditObservation};
use super::types::{AuditError, AuditEvent, BootSessionId, KernelSecretEntropy};
#[cfg(not(test))]
use crate::entropy::ProvisionedEntropy;
use native_audit_verifier::{AuditVerifier, AuthContext};
use zeroize::Zeroizing;

/// A second install is refused even if the first runtime was thought missing.
/// There is no reset or replacement path in production.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditInstallError {
    AlreadyInstalled,
    CustodyRejected,
}

impl core::fmt::Display for AuditInstallError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::AlreadyInstalled => "audit authority is already installed",
            Self::CustodyRejected => "audit custody provisioning was rejected",
        };
        f.write_str(text)
    }
}

/// Public custody identity only. The authority key and anchor stay inside the
/// two runtime custodians and never implement Copy or Clone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditIdentity {
    boot: BootSessionId,
    authority_id: u64,
}

impl AuditIdentity {
    pub const fn boot(&self) -> BootSessionId {
        self.boot
    }

    pub const fn authority_id(&self) -> u64 {
        self.authority_id
    }
}

struct AuditRuntime {
    chain: AuditChain,
    verifier: AuditVerifier,
}

static RUNTIME: Mutex<Option<AuditRuntime>> = Mutex::new(None);

/// Consumes boot seed material and mints the only two authority custodians.
#[cfg(not(test))]
pub fn install(seed: ProvisionedEntropy) -> Result<AuditIdentity, AuditInstallError> {
    install_custody(seed.boot(), seed.secret())
}

/// The shared custody transition. Tests exercise this exact path; production
/// reaches it only through CPUID-gated RDRAND provisioning.
fn install_custody(
    boot: BootSessionId,
    secret: KernelSecretEntropy,
) -> Result<AuditIdentity, AuditInstallError> {
    let mut runtime = RUNTIME.lock();
    if runtime.is_some() {
        return Err(AuditInstallError::AlreadyInstalled);
    }

    let authority =
        super::AuditAuthority::mint(boot, secret).ok_or(AuditInstallError::CustodyRejected)?;
    let handoff = authority.verifier_handoff();
    let anchor_key = Zeroizing::new(*authority.context().verification_key().bytes());
    let anchor = AuthContext::from_trusted_anchor(
        authority.context().authority_id(),
        authority.boot().bytes(),
        *anchor_key,
    )
    .map_err(|_| AuditInstallError::CustodyRejected)?;
    let chain = AuditChain::genesis_custodied(boot, authority)
        .map_err(|_| AuditInstallError::CustodyRejected)?;
    let verifier = AuditVerifier::genesis(boot.bytes(), anchor, &handoff)
        .map_err(|_| AuditInstallError::CustodyRejected)?;

    *runtime = Some(AuditRuntime { chain, verifier });

    let installed = runtime.as_ref().expect("runtime was just installed");
    Ok(AuditIdentity {
        boot: installed.chain.boot(),
        authority_id: installed.chain.authority().context().authority_id(),
    })
}

#[cfg(test)]
pub(crate) fn install_for_test(
    boot: BootSessionId,
    secret: KernelSecretEntropy,
) -> Result<AuditIdentity, AuditInstallError> {
    install_custody(boot, secret)
}

/// Records one event through the real verifier and retires it before return.
pub(crate) fn record(event: AuditEvent) -> Result<AuditObservation, AuditError> {
    let mut runtime = RUNTIME.lock();
    let Some(runtime) = runtime.as_mut() else {
        return Err(AuditError::MalformedFrame);
    };
    runtime
        .chain
        .append_and_retire(event, &mut runtime.verifier)
}

pub(crate) fn identity() -> Option<AuditIdentity> {
    let runtime = RUNTIME.lock();
    let runtime = runtime.as_ref()?;
    Some(AuditIdentity {
        boot: runtime.chain.boot(),
        authority_id: runtime.chain.authority().context().authority_id(),
    })
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    *RUNTIME.lock() = None;
    let boot = BootSessionId::new([0x17; 16]).expect("test boot identity is nonzero");
    let secret = KernelSecretEntropy::new([0x29; 32]).expect("test secret is nonzero");
    install_for_test(boot, secret).expect("test custody installs exactly once");
}

#[cfg(test)]
pub(crate) fn fill_relay_for_test() -> Result<(), AuditError> {
    let mut runtime = RUNTIME.lock();
    let Some(runtime) = runtime.as_mut() else {
        return Err(AuditError::MalformedFrame);
    };
    for _ in 0..super::relay::AUDIT_RELAY_SLOTS {
        let subject = super::AuditSubject::from_parts(0, core::num::NonZeroU64::new(1).unwrap())
            .expect("test subject fits the landed ceiling");
        let event = AuditEvent::new(super::AuditClass::DomainCreate, subject);
        // Direct appends model prior in-flight evidence; ordinary capacity is
        // exhausted before the reserved terminal headroom can be consumed.
        if runtime.chain.append(event).is_err() {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn state_for_test() -> Option<(u64, [u8; 32])> {
    let runtime = RUNTIME.lock();
    let runtime = runtime.as_ref()?;
    Some((runtime.chain.seq(), *runtime.chain.root()))
}
