//! Fixed endpoint objects, one-deep queues, and blocked-receiver state.

use super::abi::MAX_PAYLOAD_BYTES;
use super::capability::{Capability, DomainToken};

const ENDPOINT_MEMBERS: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SendOutcome {
    Delivered,
    Ready,
    Full,
}

#[derive(Clone, Copy)]
pub(super) struct Message {
    sender: DomainToken,
    tag: u32,
    payload_len: u16,
    payload: [u8; MAX_PAYLOAD_BYTES],
    transfer: Option<Capability>,
}

impl Message {
    pub(super) const fn new(
        sender: DomainToken,
        tag: u32,
        payload_len: u16,
        payload: [u8; MAX_PAYLOAD_BYTES],
        transfer: Option<Capability>,
    ) -> Self {
        Self {
            sender,
            tag,
            payload_len,
            payload,
            transfer,
        }
    }

    pub(super) const fn sender(self) -> DomainToken {
        self.sender
    }

    pub(super) const fn tag(self) -> u32 {
        self.tag
    }

    pub(super) const fn payload_len(self) -> u16 {
        self.payload_len
    }

    pub(super) const fn payload(self) -> [u8; MAX_PAYLOAD_BYTES] {
        self.payload
    }

    pub(super) const fn transfer(self) -> Option<Capability> {
        self.transfer
    }
}

#[derive(Clone, Copy)]
pub(super) struct Endpoint {
    generation: super::ObjectGeneration,
    members: [Option<DomainToken>; ENDPOINT_MEMBERS],
    queues: [Option<Message>; ENDPOINT_MEMBERS],
    waiters: [Option<DomainToken>; ENDPOINT_MEMBERS],
}

impl Endpoint {
    pub(super) const fn new(generation: super::ObjectGeneration) -> Self {
        Self {
            generation,
            members: [None; ENDPOINT_MEMBERS],
            queues: [None; ENDPOINT_MEMBERS],
            waiters: [None; ENDPOINT_MEMBERS],
        }
    }

    pub(super) const fn generation(&self) -> super::ObjectGeneration {
        self.generation
    }

    pub(super) fn bind(&mut self, domain: DomainToken) -> bool {
        if self.members.contains(&Some(domain)) {
            return false;
        }
        match self.members.iter_mut().find(|member| member.is_none()) {
            Some(member) => {
                *member = Some(domain);
                true
            },
            None => false,
        }
    }

    pub(super) fn accepts(&self, domain: DomainToken) -> bool {
        self.members.contains(&Some(domain))
    }

    fn destination_index(&self, destination: DomainToken) -> Option<usize> {
        self.members
            .iter()
            .position(|member| *member == Some(destination))
    }

    pub(super) fn send(
        &mut self,
        sender: DomainToken,
        destination: DomainToken,
        message: Message,
    ) -> SendOutcome {
        if !self.accepts(sender) || !self.accepts(destination) {
            return SendOutcome::Full;
        }
        let Some(index) = self.destination_index(destination) else {
            return SendOutcome::Full;
        };
        if self.waiters[index] == Some(destination) && self.queues[index].is_some() {
            return SendOutcome::Full;
        }
        if self.waiters[index] == Some(destination) {
            self.waiters[index] = None;
            self.queues[index] = Some(message);
            SendOutcome::Ready
        } else if self.queues[index].is_none() {
            self.queues[index] = Some(message);
            SendOutcome::Delivered
        } else {
            SendOutcome::Full
        }
    }

    pub(super) fn park(&mut self, domain: DomainToken) -> bool {
        let Some(index) = self.destination_index(domain) else {
            return false;
        };
        if self.queues[index].is_some() || self.waiters[index].is_some() {
            return false;
        }
        self.waiters[index] = Some(domain);
        true
    }

    pub(super) fn receive(&mut self, domain: DomainToken) -> Option<Message> {
        let index = self.destination_index(domain)?;
        self.queues[index].take()
    }

    pub(super) fn restore(
        &mut self,
        destination: DomainToken,
        message: Message,
        wake_waiter: bool,
    ) -> bool {
        let Some(index) = self.destination_index(destination) else {
            return false;
        };
        if self.queues[index].is_some() {
            return false;
        }
        self.queues[index] = Some(message);
        if wake_waiter {
            self.waiters[index] = Some(destination);
        }
        true
    }

    pub(super) fn clear_domain(&mut self, domain: DomainToken) -> [Option<DomainToken>; 2] {
        let mut wakes = [None; 2];
        let mut wake_index = 0;
        for index in 0..ENDPOINT_MEMBERS {
            if self.members[index] == Some(domain) {
                self.members[index] = None;
                self.queues[index].take();
                self.waiters[index].take();
            } else if self.members[index].is_some() && self.waiters[index].take().is_some() {
                wakes[wake_index] = self.members[index];
                wake_index += 1;
            }
        }
        wakes
    }

    pub(super) fn unbind_without_capability(
        &mut self,
        domain: DomainToken,
    ) -> [Option<DomainToken>; 2] {
        if self.members.contains(&Some(domain)) {
            let mut wakes = self.clear_domain(domain);
            // The revoked domain itself may be parked even when it is the
            // only endpoint member; report it so revoke can fail it terminal.
            if !wakes.contains(&Some(domain))
                && let Some(slot) = wakes.iter_mut().find(|slot| slot.is_none())
            {
                *slot = Some(domain);
            }
            wakes
        } else {
            [None; 2]
        }
    }

    pub(super) fn drain_sender(&mut self, sender: DomainToken) -> usize {
        let mut removed = 0;
        for queue in &mut self.queues {
            if queue.is_some_and(|message| message.sender() == sender) && queue.take().is_some() {
                removed += 1;
            }
        }
        removed
    }

    pub(super) fn queued_peer_failures(
        &self,
        domain: DomainToken,
        peers: &mut [Option<DomainToken>; 2],
    ) {
        for (index, queue) in self.queues.iter().enumerate() {
            let Some(message) = queue else {
                continue;
            };
            let peer = if message.sender() == domain {
                self.members.get(index).copied().flatten()
            } else if self.members.get(index).copied().flatten() == Some(domain) {
                Some(message.sender())
            } else {
                None
            };
            let Some(peer) = peer else {
                continue;
            };
            if peer == domain || peers.contains(&Some(peer)) {
                continue;
            }
            if let Some(slot) = peers.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(peer);
            }
        }
    }

    pub(super) fn cancel_waiter(&mut self, domain: DomainToken) -> bool {
        let Some(index) = self
            .waiters
            .iter()
            .position(|waiter| *waiter == Some(domain))
        else {
            return false;
        };
        self.queues[index].take();
        self.waiters[index].take();
        true
    }

    pub(super) fn queue_message(&self, index: usize) -> Option<Message> {
        self.queues.get(index).copied().flatten()
    }

    pub(super) fn queued_for(&self, domain: DomainToken) -> usize {
        self.destination_index(domain)
            .map(|index| usize::from(self.queues[index].is_some()))
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn has_waiter(&self, domain: DomainToken) -> bool {
        self.waiters.contains(&Some(domain))
    }

    pub(super) fn clear_queue(&mut self, index: usize) -> bool {
        self.queues.get_mut(index).map(Option::take).is_some()
    }
}
