//! Lifetime of signed device sessions served by the local daemon.

use std::sync::{Arc, Mutex};

use tokio::sync::watch;

mod phase;
use phase::{DrainBatch, Entry, Phase};

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
        let drains = {
            let mut entries = self.0.lock().map_err(|_| DeviceSessionError::Unavailable)?;
            entries.retain(|entry| !entry.signal.is_closed());
            phase::retire_and_capture(&mut entries, principal.as_str(), key.as_str(), |signal| {
                signal.send_replace(true);
                signal.clone()
            })
        };
        let mut batch = DrainBatch::new(drains);
        while let Some(signal) = batch.pending() {
            signal.closed().await;
            if !batch.confirm(watch::Sender::is_closed) {
                return Err(DeviceSessionError::Unavailable);
            }
        }
        Ok(())
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
        let entry = entries
            .iter_mut()
            .find(|e| self.signal.same_channel(&e.signal))
            .ok_or(DeviceSessionError::Unavailable)?;
        if entry.phase.bind(key.into_inner()) {
            return Ok(DeviceSession(self.receiver));
        }
        Err(DeviceSessionError::Retired)
    }
}

impl DeviceSession {
    /// Resolves on retirement, including retirement before the first poll.
    pub async fn retired(&mut self) {
        let _ = self.0.wait_for(|retired| *retired).await;
    }
}

#[cfg(test)]
mod tests;
