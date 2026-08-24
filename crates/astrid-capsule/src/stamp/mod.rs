//! Host-internal identity stamps for the dual-path capsule ingress boundary.

mod identity;
mod invocation;

pub use identity::IngressIdentity;
pub use invocation::StampedInvocation;

#[cfg(test)]
mod tests;
