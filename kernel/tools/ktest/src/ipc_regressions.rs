//! Standalone helper contracts for the private capability-IPC repairs.

const SLOTS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Slot(u8);

impl Slot {
    fn try_new(value: usize) -> Option<Self> {
        (value < SLOTS).then_some(Self(value as u8))
    }

    fn index(self) -> usize {
        usize::from(self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Capability {
    endpoint: usize,
    parent: Option<Link>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Link {
    owner: usize,
    slot: Slot,
}

#[derive(Clone, Copy)]
struct Table {
    owner: Option<usize>,
    slots: [Option<Capability>; SLOTS],
}

impl Table {
    const fn new(owner: usize) -> Self {
        Self {
            owner: Some(owner),
            slots: [None; SLOTS],
        }
    }

    fn install(&mut self, owner: usize, slot: Slot, capability: Capability) -> bool {
        if self.owner != Some(owner) || self.slots[slot.index()].is_some() {
            return false;
        }
        self.slots[slot.index()] = Some(capability);
        true
    }

    fn free_slot(&self, owner: usize) -> Option<Slot> {
        if self.owner != Some(owner) {
            return None;
        }
        (0..SLOTS)
            .filter_map(Slot::try_new)
            .find(|slot| self.slots[slot.index()].is_none())
    }

    fn find(&self, owner: usize, endpoint: usize) -> Option<Slot> {
        if self.owner != Some(owner) {
            return None;
        }
        (0..SLOTS)
            .filter_map(Slot::try_new)
            .find(|slot| self.slots[slot.index()].is_some_and(|cap| cap.endpoint == endpoint))
    }
}

fn is_derived_from(capabilities: &[Table], mut parent: Option<Link>, ancestor: Link) -> bool {
    for _ in 0..SLOTS * capabilities.len() {
        let Some(link) = parent else {
            return false;
        };
        if link == ancestor {
            return true;
        }
        parent = capabilities[link.owner]
            .slots
            .get(link.slot.index())
            .copied()
            .flatten()
            .and_then(|capability| capability.parent);
    }
    false
}

fn revoke_subtree(capabilities: &mut [Table], ancestor: Link) -> usize {
    let mut descendants = Vec::new();
    for (owner, table) in capabilities.iter().enumerate() {
        for slot in (0..SLOTS).filter_map(Slot::try_new) {
            if table.slots[slot.index()].is_some_and(|capability| {
                is_derived_from(capabilities, capability.parent, ancestor)
            }) {
                descendants.push((owner, slot));
            }
        }
    }
    let removed_root = capabilities[ancestor.owner]
        .slots
        .get_mut(ancestor.slot.index())
        .and_then(Option::take)
        .is_some();
    let removed_descendants = descendants
        .iter()
        .filter(|(owner, slot)| capabilities[*owner].slots[slot.index()].take().is_some())
        .count();
    usize::from(removed_root) + removed_descendants
}

#[derive(Clone, Copy)]
struct TransferMessage {
    transfer: Option<Capability>,
}

#[derive(Default)]
struct DestinationQueue {
    message: Option<TransferMessage>,
}

impl DestinationQueue {
    fn receive_and_install(
        &mut self,
        destination: &mut Table,
        owner: usize,
        slot: Slot,
    ) -> Result<Slot, ()> {
        let Some(message) = self.message.take() else {
            return Err(());
        };
        let Some(capability) = message.transfer else {
            return Ok(slot);
        };
        if destination.install(owner, slot, capability) {
            Ok(slot)
        } else {
            self.message = Some(message);
            Err(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockStatus {
    Sent,
    Received,
    Cancelled,
    Faulted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Parked {
    handle: u64,
    status: BlockStatus,
}

#[derive(Default)]
struct ParkedTable([Option<Parked>; 2]);

impl ParkedTable {
    fn cancel(&mut self, handle: u64) -> bool {
        let Some(slot) = self
            .0
            .iter_mut()
            .find(|slot| slot.is_some_and(|parked| parked.handle == handle))
        else {
            return false;
        };
        if let Some(parked) = slot.as_mut() {
            parked.status = BlockStatus::Cancelled;
        }
        true
    }

    fn release(&mut self, handle: u64) -> bool {
        self.0
            .iter_mut()
            .any(|slot| slot.take_if(|parked| parked.handle == handle).is_some())
    }
}

struct Wait {
    endpoint_waiter: bool,
    parked: Option<BlockStatus>,
}

impl Wait {
    fn cancel(&mut self) -> Option<BlockStatus> {
        let endpoint = core::mem::take(&mut self.endpoint_waiter);
        if let Some(status) = self.parked.as_mut() {
            *status = BlockStatus::Cancelled;
        }
        (endpoint || self.parked.is_some()).then_some(BlockStatus::Cancelled)
    }
}

fn finish_copy(buffer: &mut [u8], scratch: &[u8], copied: bool) -> bool {
    if copied {
        buffer.copy_from_slice(scratch);
    }
    copied
}

struct SenderTeardown {
    queued_sender: Option<usize>,
    parked_sender: Option<BlockStatus>,
}

impl SenderTeardown {
    fn release_sender(&mut self, sender: usize) -> bool {
        let drained = self.queued_sender == Some(sender);
        if drained {
            self.queued_sender = None;
        }
        if self.parked_sender == Some(BlockStatus::Sent) {
            self.parked_sender = Some(BlockStatus::Faulted);
        }
        drained
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capability(endpoint: usize, parent: Option<Link>) -> Capability {
        Capability { endpoint, parent }
    }

    #[test]
    fn failed_transfer_destination_restores_message() {
        let transfer = capability(1, None);
        let occupied_slot = Slot::try_new(7).unwrap();
        let mut queue = DestinationQueue {
            message: Some(TransferMessage {
                transfer: Some(transfer),
            }),
        };
        let mut destination = Table::new(1);
        assert!(destination.install(1, occupied_slot, capability(2, None)));
        assert!(
            queue
                .receive_and_install(&mut destination, 1, occupied_slot)
                .is_err()
        );
        assert!(queue.message.is_some());
    }

    #[test]
    fn derivation_revoke_removes_grandchild() {
        let mut capabilities = [Table::new(0), Table::new(1)];
        let root = Link {
            owner: 0,
            slot: Slot::try_new(0).unwrap(),
        };
        let child_slot = Slot::try_new(1).unwrap();
        let grandchild_slot = Slot::try_new(2).unwrap();
        assert!(capabilities[0].install(0, root.slot, capability(1, None)));
        assert!(capabilities[1].install(1, child_slot, capability(1, Some(root),)));
        assert!(capabilities[1].install(
            1,
            grandchild_slot,
            capability(
                1,
                Some(Link {
                    owner: 1,
                    slot: child_slot,
                }),
            )
        ));
        assert_eq!(revoke_subtree(&mut capabilities, root), 3);
        assert!(capabilities[0].slots[0].is_none());
        assert!(capabilities[1].slots[1].is_none());
        assert!(capabilities[1].slots[2].is_none());
    }

    #[test]
    fn slot_scan_sees_every_hole_and_capability() {
        let mut table = Table::new(0);
        assert_eq!(table.free_slot(0), Slot::try_new(0));
        for (endpoint, index) in [1usize, 2, 3, 4, 5, 6, 7].into_iter().enumerate() {
            assert!(table.install(0, Slot::try_new(index).unwrap(), capability(endpoint, None),));
        }
        assert_eq!(table.find(0, 6), Slot::try_new(7));
        assert_eq!(table.free_slot(0), Slot::try_new(0));
        assert!(table.install(0, Slot::try_new(0).unwrap(), capability(9, None)));
        assert_eq!(table.find(0, 9), Slot::try_new(0));
    }

    #[test]
    fn user_cancel_returns_cancelled_status() {
        let mut recv_wait = Wait {
            endpoint_waiter: true,
            parked: Some(BlockStatus::Received),
        };
        assert_eq!(recv_wait.cancel(), Some(BlockStatus::Cancelled));
        assert_eq!(recv_wait.parked, Some(BlockStatus::Cancelled));
        let mut sent_wait = Wait {
            endpoint_waiter: false,
            parked: Some(BlockStatus::Sent),
        };
        assert_eq!(sent_wait.cancel(), Some(BlockStatus::Cancelled));
        let mut idle = Wait {
            endpoint_waiter: false,
            parked: None,
        };
        assert_eq!(idle.cancel(), None);
    }

    #[test]
    fn kernel_scratch_is_visible_in_wire_buffer() {
        let mut buffer = [0u8; 8];
        let scratch = [1, 2, 3, 4, 5, 6, 7, 8];
        assert!(finish_copy(&mut buffer, &scratch, true));
        assert_eq!(buffer, scratch);
        assert!(!finish_copy(&mut buffer, &scratch, false));
    }

    #[test]
    fn sender_teardown_drains_queue_and_fails_parked_send() {
        let mut state = SenderTeardown {
            queued_sender: Some(1),
            parked_sender: Some(BlockStatus::Sent),
        };
        assert!(state.release_sender(1));
        assert_eq!(state.queued_sender, None);
        assert_eq!(state.parked_sender, Some(BlockStatus::Faulted));
    }

    #[test]
    fn parked_cancel_then_release_clears_slot() {
        let mut parked = ParkedTable([
            Some(Parked {
                handle: 1,
                status: BlockStatus::Received,
            }),
            None,
        ]);
        assert!(parked.cancel(1));
        assert_eq!(parked.0[0].unwrap().status, BlockStatus::Cancelled);
        assert!(parked.release(1));
        assert!(parked.0[0].is_none());
        assert!(!parked.release(1));
    }
}
