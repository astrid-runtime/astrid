//! Lifetime of signed device sessions served by the local daemon.

use std::sync::{Arc, Mutex};

use tokio::sync::watch;

mod phase;
pub use phase::DeviceRetirement;
use phase::{Entry, Phase};

use super::DeviceKeyId;
use crate::PrincipalId;

/// Failure to establish or retire local device authority.
#[derive(Debug, thiserror::Error)]
pub enum DeviceSessionError {
    /// The device was removed after the handshake started.
    #[error("device retired during handshake")]
    Retired,
    /// The registry cannot establish the state of its entries.
    #[error("device session registry unavailable")]
    Unavailable,
}

/// Shared by the signed handshake and the device-revocation handler.
#[derive(Clone, Default, Debug)]
pub struct DeviceSessions(Arc<Mutex<Vec<Entry<watch::Sender<bool>>>>>);

/// A challenge registered before its nonce is sent.
pub struct DeviceChallenge {
    sessions: DeviceSessions,
    signal: watch::Sender<bool>,
    receiver: watch::Receiver<bool>,
}

/// Held until the serving future and its transport have been dropped.
#[derive(Debug)]
pub struct DeviceSession(watch::Receiver<bool>);

impl DeviceSessions {
    /// Register before consulting the profile or issuing a challenge.
    ///
    /// # Errors
    /// Returns an error when the registry lock is poisoned.
    pub fn challenge(&self, principal: PrincipalId) -> Result<DeviceChallenge, DeviceSessionError> {
        let (signal, receiver) = watch::channel(false);
        let mut entries = self.0.lock().map_err(|_| DeviceSessionError::Unavailable)?;
        entries.retain(|entry| !entry.signal.is_closed());
        entries.push(Entry {
            owner: principal.into_inner(),
            phase: Phase::challenge(),
            signal: signal.clone(),
        });
        Ok(DeviceChallenge {
            sessions: self.clone(),
            signal,
            receiver,
        })
    }

    /// After durable removal, invalidate outstanding challenges for this key
    /// and wait until every matching admitted connection stops serving.
    ///
    /// # Errors
    /// Returns an error if the registry cannot establish that all sessions drained.
    pub async fn retire(
        &self,
        principal: &PrincipalId,
        key: &DeviceKeyId,
    ) -> Result<(), DeviceSessionError> {
        self.retire_with_receipt(principal, key).await.map(|_| ())
    }

    /// Retire sessions and return the principal and key certified by the registry.
    ///
    /// # Errors
    /// Fails if closure cannot be established for all selected channels.
    pub async fn retire_with_receipt<'a>(
        &self,
        principal: &'a PrincipalId,
        key: &'a DeviceKeyId,
    ) -> Result<DeviceRetirement<'a>, DeviceSessionError> {
        let batch = {
            let mut entries = self.0.lock().map_err(|_| DeviceSessionError::Unavailable)?;
            entries.retain(|entry| !entry.signal.is_closed());
            phase::retire_and_capture(&mut entries, principal.as_str(), key.as_str(), |signal| {
                signal.send_replace(true);
                signal.clone()
            })
        };
        for signal in batch.signals() {
            signal.closed().await;
        }
        batch
            .certify(watch::Sender::is_closed)
            .ok_or(DeviceSessionError::Unavailable)
    }
}

impl DeviceChallenge {
    /// Bind the key that verified the signature, unless it retired during
    /// this particular challenge (including removal followed by re-pairing).
    ///
    /// # Errors
    /// Fails if the key retired or the registry state is unavailable.
    pub fn bind(self, key: DeviceKeyId) -> Result<DeviceSession, DeviceSessionError> {
        let mut entries = self
            .sessions
            .0
            .lock()
            .map_err(|_| DeviceSessionError::Unavailable)?;
        match phase::bind_registered(
            &mut entries,
            &self.signal,
            key.into_inner(),
            watch::Sender::same_channel,
        ) {
            phase::Binding::Bound => Ok(DeviceSession(self.receiver)),
            phase::Binding::Retired => Err(DeviceSessionError::Retired),
            phase::Binding::Missing => Err(DeviceSessionError::Unavailable),
        }
    }
}

// Rust drops fields in declaration order. This also covers a connection
// discarded before the returned future is polled for the first time.
struct ServingSession<Start> {
    start: Start,
    session: DeviceSession,
}

impl<Start> ServingSession<Start> {
    async fn run<F: Future<Output = ()>>(mut self)
    where
        Start: FnOnce() -> F,
    {
        // The select owns the work and only borrows the receiver. Cancellation
        // drops the select and its work before releasing the receiver.
        tokio::select! {
            biased;
            () = self.session.retired() => {},
            () = (self.start)() => {},
        }
    }
}

impl DeviceSession {
    /// Own the serving future and release its transport and pending operations
    /// before the registry can observe this session closed.
    pub fn serve<F: Future<Output = ()>>(
        self,
        start: impl FnOnce() -> F,
    ) -> impl Future<Output = ()> {
        ServingSession {
            start,
            session: self,
        }
        .run()
    }

    /// Resolves on retirement, including retirement before the first poll.
    pub async fn retired(&mut self) {
        let _ = self.0.wait_for(|retired| *retired).await;
    }
}

#[cfg(test)]
mod tests;
