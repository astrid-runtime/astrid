#![no_std]
#![cfg(test)]
#![cfg_attr(test, allow(unused_imports, dead_code, private_interfaces))]

#[cfg(test)]
#[path = "test_domains/mod.rs"]
pub mod domains;
#[cfg(test)]
#[path = "ipc/mod.rs"]
pub mod ipc;
#[cfg(test)]
pub(crate) mod memory {
    pub(crate) const FRAME_SIZE: u64 = 4096;
}

#[cfg(test)]
pub(crate) mod trap {
    #[derive(Clone, Copy)]
    pub(crate) struct TrapFrame {
        pub(crate) rax: u64,
        pub(crate) rbx: u64,
        pub(crate) rcx: u64,
        pub(crate) rdx: u64,
        pub(crate) rsi: u64,
        pub(crate) rdi: u64,
        pub(crate) rbp: u64,
        pub(crate) r8: u64,
        pub(crate) r9: u64,
        pub(crate) r10: u64,
        pub(crate) r11: u64,
        pub(crate) r12: u64,
        pub(crate) r13: u64,
        pub(crate) r14: u64,
        pub(crate) r15: u64,
        pub(crate) vector: u64,
        pub(crate) error_code: u64,
        pub(crate) rip: u64,
        pub(crate) cs: u64,
        pub(crate) rflags: u64,
        pub(crate) rsp: u64,
        pub(crate) ss: u64,
    }

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
}

#[cfg(test)]
pub(crate) mod serial {
    pub(crate) fn ev_ipc_op(_id: u64, _generation: u64, _op: &str, _status: &str) {}
}

#[cfg(test)]
pub(crate) mod test_lock {
    use spin::Mutex;

    pub(crate) static LOCK: Mutex<()> = Mutex::new(());
}
