//! Lifetime of signed device sessions served by the local daemon.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use tokio::sync::watch;

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
pub struct DeviceSessions(Arc<Mutex<Vec<Entry>>>);

#[derive(Debug)]
struct Entry {
    principal: PrincipalId,
    phase: Phase,
    signal: watch::Sender<bool>,
}

#[derive(Debug)]
enum Phase {
    /// Keys removed while this challenge was outstanding.
    Challenge(HashSet<DeviceKeyId>),
    Serving(DeviceKeyId),
}

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
            principal,
            phase: Phase::Challenge(HashSet::new()),
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
            let mut drains = Vec::new();
            for entry in entries.iter_mut().filter(|e| &e.principal == principal) {
                match &mut entry.phase {
                    Phase::Challenge(keys) => {
                        keys.insert(key.clone());
                    },
                    Phase::Serving(bound) if bound.as_str() == key.as_str() => {
                        entry.signal.send_replace(true);
                        drains.push(entry.signal.clone());
                    },
                    Phase::Serving(_) => {},
                }
            }
            drains
        };
        for signal in drains {
            signal.closed().await;
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
        if let Phase::Challenge(retired) = &entry.phase
            && !retired.contains(&key)
        {
            entry.phase = Phase::Serving(key);
            return Ok(DeviceSession(self.receiver));
        }
        Err(DeviceSessionError::Retired)
    }
}

impl DeviceSession {
    /// Run one operation under this session. Retirement cancels the operation,
    /// and the receiver stays live until its future has been dropped.
    pub async fn while_live<F: Future>(&self, operation: F) -> Option<F::Output> {
        let mut signal = self.0.clone();
        tokio::select! {
            biased;
            _ = signal.wait_for(|retired| *retired) => None,
            value = operation => Some(value),
        }
    }

    /// Resolves on retirement, including retirement before the first poll.
    pub async fn retired(&mut self) {
        let _ = self.0.wait_for(|retired| *retired).await;
    }
}

#[cfg(test)]
mod tests;
