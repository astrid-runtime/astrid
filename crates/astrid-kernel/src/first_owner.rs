//! Kernel-side gate for the first-owner ceremony.
//!
//! The storage crate owns the durable state machine. This module keeps the
//! composition-root boundary explicit: only an authenticated boot handoff can
//! produce a context-bound request, and the legacy CLI bootstrap is permitted
//! only after the durable graph is Enrolled.

use astrid_core::{FirstOwnerClaim, FleetIdentity, UserIdentity};
use astrid_storage::{FirstOwnerEnrollment, OwnershipError, OwnershipStore};

/// The provenance of an internal boot-context candidate.
///
/// Fixture and host-path inputs are intentionally represented so tests can
/// prove that they fail closed. They must never be accepted as an authority
/// context by the composition root.
#[allow(
    dead_code,
    reason = "the composition root supplies authenticated provenance in the host wiring"
)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BootContextProvenance {
    /// Context obtained from the authenticated machine/boot handoff.
    AuthenticatedHandoff,
    /// Test-only or synthetic context.
    Fixture,
    /// Context derived from an untrusted host path or environment.
    HostPath,
}

/// Authenticated machine and boot facts bound into a first-owner claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthenticatedBootContext {
    machine_context: [u8; 32],
    boot_context: [u8; 32],
    kernel_identity: [u8; 32],
    system_generation: [u8; 32],
}

/// Kernel-side first-owner failure.
#[allow(
    dead_code,
    reason = "the authenticated handoff entry points are retained for the composition-root wiring"
)]
#[derive(Debug)]
pub(crate) enum FirstOwnerBootError {
    /// No authenticated handoff was supplied by the composition root.
    MissingAuthenticatedContext,
    /// A fixture or host-path context was supplied instead of an attested one.
    UntrustedContext(BootContextProvenance),
    /// The authenticated handoff contained an unusable all-zero component.
    EmptyContext(&'static str),
    /// The claim was signed for a different machine or boot generation.
    ContextMismatch(&'static str),
    /// Durable first-owner storage failed or rejected the transition.
    Storage(OwnershipError),
}

impl std::fmt::Display for FirstOwnerBootError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingAuthenticatedContext => {
                formatter.write_str("first-owner operation requires an authenticated boot context")
            },
            Self::UntrustedContext(provenance) => write!(
                formatter,
                "first-owner context provenance is not authenticated: {provenance:?}"
            ),
            Self::EmptyContext(name) => {
                write!(
                    formatter,
                    "authenticated first-owner boot context contains an empty {name}"
                )
            },
            Self::ContextMismatch(name) => {
                write!(
                    formatter,
                    "first-owner claim does not match authenticated {name}"
                )
            },
            Self::Storage(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for FirstOwnerBootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(error) => Some(error),
            _ => None,
        }
    }
}

impl From<OwnershipError> for FirstOwnerBootError {
    fn from(error: OwnershipError) -> Self {
        Self::Storage(error)
    }
}

impl AuthenticatedBootContext {
    /// Build a context from the composition root's authenticated handoff.
    ///
    /// This constructor deliberately rejects fixture and host-path sources.
    /// It also rejects an empty component so a missing handoff cannot be
    /// represented by an all-zero sentinel.
    #[allow(
        dead_code,
        reason = "called by the authenticated composition root when host wiring is enabled"
    )]
    pub(crate) fn from_provenance(
        provenance: BootContextProvenance,
        machine_context: [u8; 32],
        boot_context: [u8; 32],
        kernel_identity: [u8; 32],
        system_generation: [u8; 32],
    ) -> Result<Self, FirstOwnerBootError> {
        if provenance != BootContextProvenance::AuthenticatedHandoff {
            return Err(FirstOwnerBootError::UntrustedContext(provenance));
        }
        for (name, value) in [
            ("machine context", machine_context),
            ("boot context", boot_context),
            ("kernel identity", kernel_identity),
            ("system generation", system_generation),
        ] {
            if value == [0; 32] {
                return Err(FirstOwnerBootError::EmptyContext(name));
            }
        }
        Ok(Self {
            machine_context,
            boot_context,
            kernel_identity,
            system_generation,
        })
    }

    #[allow(
        dead_code,
        reason = "called by the deferred authenticated composition-root entry point"
    )]
    fn validate_claim(&self, claim: &FirstOwnerClaim) -> Result<(), FirstOwnerBootError> {
        for (name, expected, actual) in [
            (
                "machine context",
                self.machine_context,
                *claim.machine_context(),
            ),
            ("boot context", self.boot_context, *claim.boot_context()),
            (
                "kernel identity",
                self.kernel_identity,
                *claim.kernel_identity(),
            ),
            (
                "system generation",
                self.system_generation,
                *claim.system_generation(),
            ),
        ] {
            if expected != actual {
                return Err(FirstOwnerBootError::ContextMismatch(name));
            }
        }
        Ok(())
    }
}

#[allow(
    dead_code,
    reason = "called by the deferred authenticated composition-root entry points"
)]
fn require_context(
    context: Option<&AuthenticatedBootContext>,
    claim: &FirstOwnerClaim,
) -> Result<(), FirstOwnerBootError> {
    let context = context.ok_or(FirstOwnerBootError::MissingAuthenticatedContext)?;
    context.validate_claim(claim)
}

/// Begin first-owner enrollment after binding the claim to authenticated boot
/// facts.
#[allow(
    dead_code,
    reason = "called when the authenticated composition root receives a claim"
)]
pub(crate) async fn begin_first_owner(
    store: &OwnershipStore,
    context: Option<&AuthenticatedBootContext>,
    claim: &FirstOwnerClaim,
) -> Result<FirstOwnerEnrollment, FirstOwnerBootError> {
    require_context(context, claim)?;
    Ok(store.begin_first_owner(*claim).await?)
}

/// Commit first-owner enrollment and its graph edges after context binding.
#[allow(
    dead_code,
    reason = "called when the authenticated composition root commits a claim"
)]
pub(crate) async fn commit_first_owner(
    store: &OwnershipStore,
    context: Option<&AuthenticatedBootContext>,
    claim: &FirstOwnerClaim,
    user: UserIdentity,
    fleet: FleetIdentity,
) -> Result<FirstOwnerEnrollment, FirstOwnerBootError> {
    require_context(context, claim)?;
    Ok(store.commit_first_owner(*claim, user, fleet).await?)
}

/// Return whether the legacy CLI root ownership helper may run at boot.
///
/// Unenrolled and Pending states deliberately skip the helper: creating the
/// default user is harmless, but assigning it a fleet or principal would
/// silently promote an authority before first-owner enrollment commits.
pub(crate) async fn legacy_root_bootstrap_allowed(
    store: &OwnershipStore,
) -> Result<bool, OwnershipError> {
    Ok(store.first_owner_state().await?.is_enrolled())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use astrid_core::{FleetUid, PrincipalUid, UserUid};
    use astrid_storage::{KvStore, MemoryKvStore, OwnershipStore, PrincipalDirectory};

    use super::*;

    fn fixture_nonce() -> [u8; 32] {
        let mut nonce: [u8; 32] = std::array::from_fn(|_| 0_u8);
        getrandom::fill(&mut nonce).expect("fixture nonce");
        nonce
    }

    fn unsigned_claim() -> FirstOwnerClaim {
        let nonce = fixture_nonce();
        let claim = FirstOwnerClaim::from_parts(
            [1; 32],
            [2; 32],
            [3; 32],
            [4; 32],
            UserUid::from_bytes([5; 32]),
            FleetUid::from_bytes([6; 32]),
            PrincipalUid::from_bytes([7; 32]),
            [8; 32],
            nonce,
            1,
            [0; 64],
        )
        .expect("non-zero epoch is valid");
        assert_eq!(*claim.nonce(), nonce);
        claim
    }

    #[test]
    fn fixture_and_host_path_contexts_fail_closed() {
        let zero = [0; 32];
        assert!(matches!(
            AuthenticatedBootContext::from_provenance(
                BootContextProvenance::Fixture,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
            ),
            Err(FirstOwnerBootError::UntrustedContext(
                BootContextProvenance::Fixture
            ))
        ));
        assert!(matches!(
            AuthenticatedBootContext::from_provenance(
                BootContextProvenance::HostPath,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
            ),
            Err(FirstOwnerBootError::UntrustedContext(
                BootContextProvenance::HostPath
            ))
        ));
        assert!(matches!(
            AuthenticatedBootContext::from_provenance(
                BootContextProvenance::AuthenticatedHandoff,
                zero,
                [2; 32],
                [3; 32],
                [4; 32],
            ),
            Err(FirstOwnerBootError::EmptyContext("machine context"))
        ));
    }

    #[test]
    fn claim_context_is_an_exact_copy() {
        let claim = unsigned_claim();
        let context = AuthenticatedBootContext::from_provenance(
            BootContextProvenance::AuthenticatedHandoff,
            *claim.machine_context(),
            *claim.boot_context(),
            *claim.kernel_identity(),
            *claim.system_generation(),
        )
        .unwrap();
        assert!(context.validate_claim(&claim).is_ok());
        let changed = AuthenticatedBootContext::from_provenance(
            BootContextProvenance::AuthenticatedHandoff,
            [10; 32],
            *claim.boot_context(),
            *claim.kernel_identity(),
            *claim.system_generation(),
        )
        .unwrap();
        assert!(matches!(
            changed.validate_claim(&claim),
            Err(FirstOwnerBootError::ContextMismatch("machine context"))
        ));
    }

    #[tokio::test]
    async fn begin_without_authenticated_context_fails_closed() {
        let backend: Arc<dyn KvStore> = Arc::new(MemoryKvStore::new());
        let store = OwnershipStore::new(backend, PrincipalDirectory::default()).unwrap();
        let claim = unsigned_claim();
        assert!(matches!(
            begin_first_owner(&store, None, &claim).await,
            Err(FirstOwnerBootError::MissingAuthenticatedContext)
        ));
    }
}
