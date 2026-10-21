use std::num::NonZeroU32;

use super::{CapabilityDanger, CapabilityRegistryRevision};

/// Exact capability IDs in capability-registry revision 2.
///
/// Revision 2 is the smallest expansion of the frozen revision-1 authority
/// registry: it adds only the dedicated Distro self-grant operation.
pub(super) const IDS: [&str; 52] = [
    "system:shutdown",
    "system:status",
    "capsule:install",
    "self:capsule:install",
    "capsule:reload",
    "self:capsule:reload",
    "capsule:remove",
    "self:capsule:remove",
    "self:workspace:promote",
    "self:workspace:rollback",
    "capsule:list",
    "self:capsule:list",
    "self:distro:grant",
    "agent:create",
    "agent:create:inherit",
    "agent:create:clone",
    "agent:delete",
    "agent:enable",
    "agent:disable",
    "agent:modify",
    "agent:list",
    "self:agent:list",
    "quota:set",
    "self:quota:set",
    "quota:get",
    "self:quota:get",
    "group:create",
    "group:delete",
    "group:modify",
    "group:list",
    "self:group:list",
    "caps:grant",
    "caps:revoke",
    "caps:token:mint",
    "caps:token:revoke",
    "caps:token:list",
    "invite:issue",
    "invite:redeem",
    "invite:list",
    "invite:revoke",
    "audit:read_all",
    "self:approval:respond",
    "self:auth:pair",
    "self:auth:pair:admin",
    "auth:pair:redeem",
    "auth:pair",
    "system:resources:unbounded",
    "net_bind",
    "uplink",
    "capsule:access:any",
    "authority:profile:manage",
    "authority:repair",
];

/// Schema revision for the 52-ID authority registry.
pub(super) const REVISION: CapabilityRegistryRevision =
    CapabilityRegistryRevision::new(NonZeroU32::new(2).expect("non-zero"));

pub(super) fn danger(id: &str) -> Option<CapabilityDanger> {
    if id == "self:distro:grant" {
        return Some(CapabilityDanger::Elevated);
    }
    super::revision_1::danger(id)
}
