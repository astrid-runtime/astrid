use super::CapabilityDanger;

pub(super) fn danger(id: &str) -> Option<CapabilityDanger> {
    if id == "self:distro:grant" {
        return Some(CapabilityDanger::Elevated);
    }
    super::revision_1::danger(id)
}
