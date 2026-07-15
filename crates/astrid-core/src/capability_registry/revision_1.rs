use super::CapabilityDanger;

pub(super) fn danger(id: &str) -> Option<CapabilityDanger> {
    use CapabilityDanger::{Elevated, Extreme, Normal, Safe};

    Some(match id {
        "system:status"
        | "capsule:list"
        | "self:capsule:list"
        | "agent:list"
        | "self:agent:list"
        | "quota:get"
        | "self:quota:get"
        | "group:list"
        | "self:group:list"
        | "caps:token:list"
        | "invite:list"
        | "self:approval:respond" => Safe,
        "capsule:reload"
        | "self:capsule:reload"
        | "self:capsule:remove"
        | "self:workspace:rollback"
        | "agent:create"
        | "agent:enable"
        | "quota:set"
        | "self:quota:set"
        | "invite:redeem"
        | "invite:revoke"
        | "self:auth:pair"
        | "auth:pair:redeem" => Normal,
        "self:capsule:install"
        | "capsule:remove"
        | "self:workspace:promote"
        | "agent:delete"
        | "agent:disable"
        | "agent:modify"
        | "group:create"
        | "group:delete"
        | "group:modify"
        | "caps:revoke"
        | "caps:token:revoke"
        | "invite:issue"
        | "audit:read_all"
        | "self:auth:pair:admin"
        | "auth:pair" => Elevated,
        "system:shutdown"
        | "capsule:install"
        | "agent:create:inherit"
        | "agent:create:clone"
        | "caps:grant"
        | "caps:token:mint"
        | "system:resources:unbounded"
        | "net_bind"
        | "uplink"
        | "capsule:access:any"
        | "authority:profile:manage"
        | "authority:repair" => Extreme,
        _ => return None,
    })
}
