//! The native capsule sandbox has no per-destination network mode.
use vstd::prelude::*;

verus! {

pub(super) struct StdioSettings {
    pub(super) trusted: bool,
    pub(super) allow_network: bool,
}

pub(super) fn admit<D,P>(domains: &[D], peers: &[P]) -> (out: Option<StdioSettings>)
    ensures match out {
        Some(settings) => domains.len() == 0 && peers.len() == 0 &&
            !settings.trusted && !settings.allow_network,
        None => domains.len() > 0 || peers.len() > 0,
    },
{
    if domains.is_empty() && peers.is_empty() {
        Some(StdioSettings { trusted: false, allow_network: false })
    } else {
        None
    }
}

}
