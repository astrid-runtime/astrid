//! The narrow machine boundary used by the production IPC authority model.

use spin::Mutex;

use crate::ipc::DomainToken;

/// CPU context observed by IPC operations. The x86 trap stub fills this
/// representation; the authority state machine never touches machine registers.
#[repr(C)]
pub struct TrapFrame {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub vector: u64,
    pub error_code: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[cfg(test)]
impl TrapFrame {
    pub(crate) const fn zeroed() -> Self {
        Self {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            vector: 0,
            error_code: 0,
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
        }
    }
}

pub trait Platform: Sync + Send + 'static {
    fn copy_current_user(&self, address: u64, buffer: &mut [u8], to_user: bool) -> bool;
    fn mark_ipc_cancelled(&self, domain: DomainToken) -> bool;
    fn mark_ipc_peer_failed(&self, domain: DomainToken);
    fn ev_ipc_op(&self, id: u64, generation: u64, operation: &str, status: &str);
}

static PLATFORM: Mutex<Option<&'static dyn Platform>> = Mutex::new(None);

pub fn install<P: Platform>(platform: &'static P) {
    *PLATFORM.lock() = Some(platform);
}

pub fn current() -> &'static dyn Platform {
    PLATFORM
        .lock()
        .expect("IPC platform adapter is not installed")
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum TestStatus {
    Sent,
    Received,
    Cancelled,
    Faulted,
}

#[cfg(test)]
impl TestStatus {
    const fn name(self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
            Self::Cancelled => "cancelled",
            Self::Faulted => "faulted",
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct ParkedPeer {
    status: Option<TestStatus>,
    failed: Option<DomainToken>,
}

#[cfg(test)]
#[derive(Clone, Copy)]
struct TestState {
    parked: [ParkedPeer; 2],
    user_memory: [u8; crate::ipc::MAX_BUFFER_BYTES],
}

#[cfg(test)]
impl Default for TestState {
    fn default() -> Self {
        Self {
            parked: [ParkedPeer::default(); 2],
            user_memory: [0; crate::ipc::MAX_BUFFER_BYTES],
        }
    }
}

#[cfg(test)]
static TEST_STATE: Mutex<TestState> = Mutex::new(TestState {
    parked: [ParkedPeer {
        status: None,
        failed: None,
    }; 2],
    user_memory: [0; crate::ipc::MAX_BUFFER_BYTES],
});

#[cfg(test)]
struct TestPlatform;

#[cfg(test)]
impl Platform for TestPlatform {
    fn copy_current_user(&self, address: u64, buffer: &mut [u8], to_user: bool) -> bool {
        if address != 0 || buffer.len() != crate::ipc::MAX_BUFFER_BYTES {
            return false;
        }
        let mut state = TEST_STATE.lock();
        if to_user {
            state.user_memory.copy_from_slice(buffer);
        } else {
            buffer.copy_from_slice(&state.user_memory);
        }
        true
    }

    fn mark_ipc_cancelled(&self, domain: DomainToken) -> bool {
        let mut state = TEST_STATE.lock();
        let parked = &mut state.parked[domain.slot().index()];
        if let Some(_status @ (TestStatus::Sent | TestStatus::Received)) = parked.status {
            parked.status = Some(TestStatus::Cancelled);
            true
        } else {
            false
        }
    }

    fn mark_ipc_peer_failed(&self, domain: DomainToken) {
        let mut state = TEST_STATE.lock();
        let parked = &mut state.parked[domain.slot().index()];
        if matches!(parked.status, Some(TestStatus::Sent | TestStatus::Received)) {
            parked.status = Some(TestStatus::Faulted);
        }
        parked.failed = Some(domain);
    }

    fn ev_ipc_op(&self, _id: u64, _generation: u64, _operation: &str, _status: &str) {}
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    install(&TestPlatform);
    *TEST_STATE.lock() = TestState::default();
}

#[cfg(test)]
pub(crate) fn set_user_memory_for_test(payload: [u8; crate::ipc::MAX_BUFFER_BYTES]) {
    TEST_STATE.lock().user_memory = payload;
}

#[cfg(test)]
pub(crate) fn park_peer_for_test(domain: DomainToken, status: &str) -> bool {
    let status = match status {
        "sent" => TestStatus::Sent,
        "received" => TestStatus::Received,
        _ => return false,
    };
    TEST_STATE.lock().parked[domain.slot().index()].status = Some(status);
    true
}

#[cfg(test)]
pub(crate) fn peer_status_for_test(domain: DomainToken) -> Option<&'static str> {
    TEST_STATE.lock().parked[domain.slot().index()]
        .status
        .map(TestStatus::name)
}
