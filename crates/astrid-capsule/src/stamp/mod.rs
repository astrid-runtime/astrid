//! Host-internal identity stamps for the dual-path capsule ingress boundary.
//!
//! [`StampedInvocation`] is host attribution of a principal UID. It is not a
//! grant, initiator binding, or bearer capability. Resolution stays crate-private
//! at the trusted host boundary. Public consumers may inspect a stamp they
//! already hold; they cannot mint one.

mod identity;
mod invocation;

pub use identity::IngressIdentity;
pub use invocation::StampedInvocation;

#[cfg(test)]
mod tests;
