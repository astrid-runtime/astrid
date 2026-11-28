//! Lookup against the native transport's exact topics and topic prefixes.

use vstd::prelude::*;

verus! {

pub(super) open spec fn accepts(rule: Seq<u8>, topic: Seq<u8>, prefix: bool) -> bool {
    if prefix { rule.is_prefix_of(topic) } else { rule == topic }
}

fn accepts_rule(rule: &[u8], topic: &[u8], prefix: bool) -> (accepted: bool)
    ensures accepted == accepts(rule@, topic@, prefix),
{
    if rule.len() > topic.len() || (!prefix && rule.len() != topic.len()) { return false; }
    let (candidate, _) = topic.split_at(rule.len());
    if candidate != rule { return false; }
    assert(candidate@ =~= rule@);
    if !prefix { assert(topic@ =~= rule@); }
    true
}

#[expect(clippy::arithmetic_side_effects, reason = "Verus proves i is below the slice length before each increment")]
fn listed(rules: &[&[u8]], topic: &[u8], prefix: bool) -> (found: bool)
    ensures found == (exists|i: int| 0 <= i < rules.len() &&
        accepts(#[trigger] rules@[i]@, topic@, prefix)),
{
    let mut i = 0;
    while i < rules.len()
        invariant i <= rules.len(),
            forall|j: int| 0 <= j < i ==> !accepts(#[trigger] rules@[j]@, topic@, prefix),
        decreases rules.len() - i,
    {
        if accepts_rule(rules[i], topic, prefix) { return true; }
        i += 1;
    }
    false
}

pub(super) fn ingress(blocked: bool, capsule: bool, control: bool) -> (allowed: bool)
    ensures allowed == (!blocked && (capsule || control)),
{
    !blocked && (capsule || control)
}

pub(super) fn exact(rules: &[&[u8]], topic: &[u8]) -> (found: bool)
    ensures found == (exists|i: int| 0 <= i < rules.len() && #[trigger] rules@[i]@ == topic@),
{
    listed(rules, topic, false)
}

pub(super) fn under(rules: &[&[u8]], topic: &[u8]) -> (found: bool)
    ensures found == (exists|i: int| 0 <= i < rules.len() && (#[trigger] rules@[i]@).is_prefix_of(topic@)),
{
    listed(rules, topic, true)
}

}
