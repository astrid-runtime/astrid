use super::super::tests::{open, transaction};
#[test]
fn active_commit_group_cannot_transfer_authority() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    engine.commit_group.lock().leader_active = true;
    assert!(engine.handoff_for_retirement().is_err());
    engine.commit_group.lock().leader_active = false;
    let (_, transaction) = transaction("agent", None, b"still writable");
    engine.commit(transaction).unwrap();
    engine.handoff_for_retirement().unwrap().close().unwrap();
}
