//! Typed private-IPC terminals shared by the ABI decoder and object pools.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpcError {
    WouldBlock,
    NoSpace,
    Busy,
    Stale,
    Denied,
    Faulted,
    Cancelled,
    Malformed,
    AuditUnavailable,
    AuditRejected,
    AuditRelation,
    AuditFold,
}

impl IpcError {
    pub(crate) const fn as_code(self) -> u64 {
        match self {
            Self::WouldBlock => 1,
            Self::NoSpace => 2,
            Self::Busy => 3,
            Self::Stale => 4,
            Self::Denied => 5,
            Self::Faulted => 6,
            Self::Cancelled => 7,
            Self::Malformed => 8,
            Self::AuditUnavailable => 9,
            Self::AuditRejected => 10,
            Self::AuditRelation => 11,
            Self::AuditFold => 12,
        }
    }

    pub(crate) const fn as_name(self) -> &'static str {
        match self {
            Self::WouldBlock => "would_block",
            Self::NoSpace => "no_space",
            Self::Busy => "busy",
            Self::Stale => "stale",
            Self::Denied => "denied",
            Self::Faulted => "faulted",
            Self::Cancelled => "cancelled",
            Self::Malformed => "malformed",
            Self::AuditUnavailable => "audit_unavailable",
            Self::AuditRejected => "audit_rejected",
            Self::AuditRelation => "audit_relation",
            Self::AuditFold => "audit_fold",
        }
    }
}
