//! Astrid Core - Foundation types for the Astrid secure agent runtime.
//!
//! This crate provides:
//! - Identity management across platforms
//! - Uplink types for capsule integration
//! - Approval and elicitation primitives
//! - Common types used throughout the runtime
//! - Retry configuration with exponential backoff

#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::all)]
#![deny(unreachable_pub)]
#![deny(clippy::unwrap_used)]
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod prelude;

pub mod capability_grammar;
pub mod dirs;
pub mod elicitation;
pub mod env_policy;
pub mod groups;
pub mod identity;
pub mod kernel_api;
pub mod principal;
pub mod profile;
pub mod retry;
pub mod session_token;
pub mod types;
pub mod uplink;
pub(crate) mod utils;

pub use capability_grammar::{
    CAP_NET_BIND, CAP_RESOURCES_UNBOUNDED, CAP_UPLINK, CapabilityGrammarError, EXEMPT_CAPABILITIES,
    MAX_CAPABILITY_LEN, capability_matches, validate_capability,
};
pub use elicitation::{
    ElicitationAction, ElicitationRequest, ElicitationResponse, ElicitationSchema, SelectOption,
    UrlElicitationRequest, UrlElicitationResponse, UrlElicitationType,
};
pub use groups::{
    BUILTIN_ADMIN, BUILTIN_AGENT, BUILTIN_RESTRICTED, Group, GroupConfig, GroupConfigError,
    GroupConfigResult,
};
pub use principal::{PrincipalId, PrincipalIdError};
pub use profile::{
    AuthConfig, AuthMethod, BACKGROUND_PROCESSES_UPPER_BOUND, CURRENT_PROFILE_VERSION,
    DEFAULT_MAX_BACKGROUND_PROCESSES, DEFAULT_MAX_IPC_THROUGHPUT_BYTES, DEFAULT_MAX_MEMORY_BYTES,
    DEFAULT_MAX_STORAGE_BYTES, DEFAULT_MAX_TIMEOUT_SECS, MAX_GROUP_NAME_LEN, NetworkConfig,
    PrincipalProfile, ProcessConfig, ProfileError, ProfileResult, Quotas, TIMEOUT_SECS_UPPER_BOUND,
};
pub use retry::RetryConfig;
pub use types::{
    AgentId, ApprovalDecision, ApprovalOption, ApprovalRequest, Permission, SessionId, Timestamp,
    TokenId,
};
pub use utils::truncate_to_boundary;

// Identity types
pub use identity::{AstridUserId, FrontendLink, normalize_platform};

// Uplink types
pub use uplink::{
    InboundMessage, MAX_UPLINKS_PER_CAPSULE, UplinkCapabilities, UplinkDescriptor, UplinkError,
    UplinkId, UplinkProfile, UplinkResult, UplinkSource,
};
