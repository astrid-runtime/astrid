//! An idle resource keeps a weak handle. Its transport and original admission
//! belong to a task that wakes on close, cancellation or device retirement.
use super::super::consent_egress::EgressAuthority;
use super::KeyValuePair;
use crate::engine::wasm::host_state::HostState;
use astrid_core::{PrincipalId, PrincipalUid};
use std::sync::{Arc, Weak};
use tokio_util::sync::{CancellationToken, DropGuard};

pub(super) struct OpenResponse {
    // Drop the transport before releasing the admission.
    response: tokio::sync::Mutex<reqwest::Response>,
    pub(super) authority: EgressAuthority,
    pub(super) status: u16,
    pub(super) headers: Vec<KeyValuePair>,
    owner_cancel: CancellationToken,
    invocation_cancel: CancellationToken,
}

#[derive(Debug, Clone)]
pub(super) struct StreamLifetime {
    open: Weak<OpenResponse>,
    owner: PrincipalUid,
    _close: Arc<DropGuard>,
}

impl StreamLifetime {
    pub(super) fn start(
        state: &HostState,
        owner: PrincipalUid,
        owner_cancel: CancellationToken,
        response: reqwest::Response,
        authority: EgressAuthority,
        audit: Arc<std::sync::Mutex<super::audit::HttpExchange>>,
    ) -> Self {
        let status = response.status().as_u16();
        let mut resp_headers = Vec::new();
        for (k, v) in response.headers() {
            if let Ok(v_str) = v.to_str() {
                resp_headers.push(KeyValuePair {
                    key: k.as_str().to_string(),
                    value: v_str.to_string(),
                });
            }
        }

        let open = Arc::new(OpenResponse {
            status,
            headers: resp_headers,
            response: tokio::sync::Mutex::new(response),
            authority,
            owner_cancel,
            invocation_cancel: state.effective_cancel_token(),
        });
        let close = CancellationToken::new();
        let lifetime = Self {
            open: Arc::downgrade(&open),
            owner,
            _close: Arc::new(close.clone().drop_guard()),
        };
        state.runtime_handle.spawn(async move {
            let closed_by_guest = open
                .authority
                .while_live(async {
                    tokio::select! {
                        biased;
                        () = open.owner_cancel.cancelled() => false,
                        () = open.invocation_cancel.cancelled() => false,
                        () = close.cancelled() => true,
                    }
                })
                .await;
            if closed_by_guest != Some(true)
                && let Ok(mut exchange) = audit.lock()
            {
                exchange.finish_detached(
                    false,
                    crate::audit_sink::HostAuditOutcome::Failed("authority retired"),
                );
            }
        });
        lifetime
    }

    /// The directory read lock spans both the binding check and disclosure.
    pub(super) fn access<T>(
        &self,
        state: &HostState,
        creator: &PrincipalId,
        reader: &EgressAuthority,
        effect: impl FnOnce(Arc<OpenResponse>) -> T,
    ) -> Option<T> {
        self.access_with(state, creator, reader, (), |(open, ())| effect(open))
    }

    pub(super) fn access_with<I, T>(
        &self,
        state: &HostState,
        creator: &PrincipalId,
        reader: &EgressAuthority,
        input: I,
        effect: impl FnOnce((Arc<OpenResponse>, I)) -> T,
    ) -> Option<T> {
        let principal = state.effective_principal();
        let open = self.open.upgrade()?;
        state
            .principal_directory
            .with_bound_input(&principal, self.owner, (open, input), |(open, input)| {
                let expected = state.invocation_storage_uid.or(state.runtime_owner_uid);
                super::body::disclose(
                    super::body::same_owner(
                        principal.as_str(),
                        creator.as_str(),
                        expected.as_ref().map(PrincipalUid::as_bytes),
                        self.owner.as_bytes(),
                    ),
                    open.live_now(),
                    state.invocation_authority_active() && reader.devices_live(),
                    (open, input),
                    effect,
                )
            })
            .ok()
            .flatten()
    }

    pub(super) fn live_now(&self) -> bool {
        self.open.upgrade().is_some_and(|open| open.live_now())
    }

    #[cfg(test)]
    pub(super) fn closed() -> Self {
        Self {
            open: Weak::new(),
            owner: PrincipalUid::from_bytes([0; 32]),
            _close: Arc::new(CancellationToken::new().drop_guard()),
        }
    }
}

pub(super) type WireRead =
    Result<Result<Option<bytes::Bytes>, reqwest::Error>, tokio::time::error::Elapsed>;

type Observation = super::body::Observation<Arc<OpenResponse>, WireRead>;

impl OpenResponse {
    pub(super) fn outcome_of(self: &Arc<Self>, observation: Observation) -> Option<WireRead> {
        observation.release_for(self, Arc::ptr_eq)
    }

    pub(super) async fn read(self: &Arc<Self>, timeout: std::time::Duration) -> Observation {
        let mut response = self.response.lock().await;
        let outcome = tokio::time::timeout(timeout, response.chunk()).await;
        Observation::new(Arc::clone(self), outcome)
    }

    fn live_now(&self) -> bool {
        self.authority.devices_live()
            && !self.owner_cancel.is_cancelled()
            && !self.invocation_cancel.is_cancelled()
    }

    pub(super) async fn while_live<F: Future>(&self, read: F) -> Option<F::Output> {
        self.authority
            .while_live(async {
                tokio::select! {
                    biased;
                    () = self.owner_cancel.cancelled() => None,
                    () = self.invocation_cancel.cancelled() => None,
                    value = read => Some(value),
                }
            })
            .await
            .flatten()
    }
}

#[cfg(test)]
mod tests;
