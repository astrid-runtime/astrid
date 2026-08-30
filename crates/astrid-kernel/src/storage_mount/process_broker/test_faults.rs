//! Single-shot fault selectors for deterministic process-broker regressions.

use super::PROCESS_MOUNT_TEST_ID;
use super::process_launch::ProcessLaunchStage;

static PARTIAL_ISSUE_FAILURES: std::sync::Mutex<
    std::collections::BTreeMap<u64, ProcessLaunchStage>,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());

static PARTIAL_ISSUE_PROVIDER_ERRORS: std::sync::Mutex<
    std::collections::BTreeMap<u64, ProcessLaunchStage>,
> = std::sync::Mutex::new(std::collections::BTreeMap::new());

static ISSUE_ROOT_REMOVAL_FAILURES: std::sync::Mutex<std::collections::BTreeSet<u64>> =
    std::sync::Mutex::new(std::collections::BTreeSet::new());

static PREPARATION_FAILURES: std::sync::Mutex<std::collections::BTreeMap<u64, ProcessLaunchStage>> =
    std::sync::Mutex::new(std::collections::BTreeMap::new());

pub(crate) fn arm_partial_issue_failure(stage: ProcessLaunchStage, test_id: u64) {
    PARTIAL_ISSUE_FAILURES
        .lock()
        .expect("partial issue failure selector")
        .insert(test_id, stage);
}

pub(crate) fn arm_partial_issue_provider_error_for_test(stage: ProcessLaunchStage, test_id: u64) {
    PARTIAL_ISSUE_PROVIDER_ERRORS
        .lock()
        .expect("partial issue provider error selector")
        .insert(test_id, stage);
}

pub(super) fn take_partial_issue_provider_error(stage: ProcessLaunchStage) -> bool {
    let current_test_id = PROCESS_MOUNT_TEST_ID
        .try_with(|test_id| *test_id)
        .unwrap_or(0);
    let mut errors = PARTIAL_ISSUE_PROVIDER_ERRORS
        .lock()
        .expect("partial issue provider error selector");
    if errors.get(&current_test_id) != Some(&stage) {
        return false;
    }
    errors.remove(&current_test_id).is_some()
}

pub(super) fn take_partial_issue_failure(stage: ProcessLaunchStage) -> bool {
    let current_test_id = PROCESS_MOUNT_TEST_ID
        .try_with(|test_id| *test_id)
        .unwrap_or(0);
    let mut failures = PARTIAL_ISSUE_FAILURES
        .lock()
        .expect("partial issue failure selector");
    if failures.get(&current_test_id) != Some(&stage) {
        return false;
    }
    failures.remove(&current_test_id).is_some()
}

pub(crate) fn arm_issue_root_removal_failure_for_test(test_id: u64) {
    ISSUE_ROOT_REMOVAL_FAILURES
        .lock()
        .expect("issue root removal failure selector")
        .insert(test_id);
}

pub(super) fn take_issue_root_removal_failure_for_test() -> bool {
    let current_test_id = PROCESS_MOUNT_TEST_ID
        .try_with(|test_id| *test_id)
        .unwrap_or(0);
    ISSUE_ROOT_REMOVAL_FAILURES
        .lock()
        .expect("issue root removal failure selector")
        .remove(&current_test_id)
}

pub(crate) fn arm_preparation_failure_for_test(stage: ProcessLaunchStage, test_id: u64) {
    PREPARATION_FAILURES
        .lock()
        .expect("preparation failure selector")
        .insert(test_id, stage);
}

pub(super) fn take_preparation_failure_for_test(stage: ProcessLaunchStage) -> bool {
    let current_test_id = PROCESS_MOUNT_TEST_ID
        .try_with(|test_id| *test_id)
        .unwrap_or(0);
    PREPARATION_FAILURES
        .lock()
        .expect("preparation failure selector")
        .remove(&current_test_id)
        == Some(stage)
}
