use super::*;
use crate::engine::durable::tests::transaction;

#[test]
fn departing_queued_leaders_handoff_in_fifo_order_and_leave_empty_group_idle() {
    let group = Mutex::new(CommitGroup::default());
    let receipts = ["alice", "bob", "carol"].map(|owner| {
        let receipt = Arc::new(CommitReceipt::default());
        group.lock().queue.push_back(QueuedCommit {
            transaction: transaction(owner, None, b"queued").1,
            receipt: Arc::clone(&receipt),
            observer: None,
        });
        receipt
    });
    group.lock().leader_active = true;

    for (index, receipt) in receipts.iter().enumerate() {
        drop(LeaderLease::new(&group, receipt));
        let group = group.lock();
        assert_eq!(group.queue.len(), receipts.len() - index - 1);
        assert_eq!(group.leader_active, !group.queue.is_empty());
        for (queued, expected) in group.queue.iter().zip(&receipts[index + 1..]) {
            assert!(Arc::ptr_eq(&queued.receipt, expected));
            assert_eq!(
                expected.value.lock().promoted,
                Arc::ptr_eq(expected, &receipts[index + 1])
            );
        }
    }
    assert!(group.lock().is_idle());
}
