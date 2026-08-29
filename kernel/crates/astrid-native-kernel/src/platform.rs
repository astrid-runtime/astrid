//! The narrow machine boundary used by the production IPC authority model.

#[cfg(test)]
use crate::ipc::DomainToken;
use spin::Mutex;

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
struct TestState {
    user_memory: [u8; crate::ipc::MAX_BUFFER_BYTES],
}

#[cfg(test)]
impl Default for TestState {
    fn default() -> Self {
        Self {
            user_memory: [0; crate::ipc::MAX_BUFFER_BYTES],
        }
    }
}
#[cfg(test)]
static TEST_STATE: Mutex<TestState> = Mutex::new(TestState {
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

    fn ev_ipc_op(&self, _id: u64, _generation: u64, _operation: &str, _status: &str) {}
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    install(&TestPlatform);
    *TEST_STATE.lock() = TestState::default();
    crate::domains::reset_wait_state_for_test();
}

#[cfg(test)]
pub(crate) fn set_user_memory_for_test(payload: [u8; crate::ipc::MAX_BUFFER_BYTES]) {
    TEST_STATE.lock().user_memory = payload;
}

#[cfg(test)]
pub(crate) fn park_peer_for_test(domain: DomainToken, status: &str) -> bool {
    crate::domains::park_ipc_peer_for_test(domain, status)
}

#[cfg(test)]
pub(crate) fn peer_status_for_test(domain: DomainToken) -> Option<&'static str> {
    crate::domains::ipc_peer_status_for_test(domain)
}

#[cfg(test)]
pub(crate) fn peer_parked_for_test(domain: DomainToken) -> bool {
    crate::domains::ipc_peer_parked_for_test(domain)
}
