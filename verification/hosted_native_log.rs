//! Compose the native UID lookup and log admission with the locked tracker transition.
use std::collections::HashMap;
use vstd::{prelude::*,std_specs::hash::hash_map_inv};
use crate::principal_invocation_state::{PrincipalInvocation,acquire,binding};

verus! {

spec fn available(entries:Map<u64,PrincipalInvocation>,owner:u64) -> bool {
    let (retired,count) = binding(entries,owner);
    !retired && count < usize::MAX
}

/// A managed log's UID supplies its current bidirectional directory binding
/// before reusing or requesting the selected alias's lifecycle admission.
fn log_for_uid<'a>(aliases:&HashMap<u64,u64>,principals:&HashMap<u64,u64>,
    uid:u64,tracker:u64,held:Option<&'a (u64,Option<u64>)>,entries:HashMap<u64,PrincipalInvocation>)
    -> (out:Option<(u64,bool)>)
    requires hash_map_inv(aliases), hash_map_inv(principals), hash_map_inv(&entries),
    ensures match principals@.get(uid) {
        None => out.is_none(),
        Some(alias) => if aliases@.get(alias) == Some(uid) {
            out == Some((alias, available(entries@,alias) || (held matches Some(g) && g.0 == tracker && g.1 == Some(alias))))
        } else {out.is_none()},
    },
{
    let operation = move |alias:&u64| -> (r:(u64,bool))
        ensures r == (*alias,available(entries@,*alias) || (held matches Some(g) && g.0 == tracker && g.1 == Some(*alias)))
    { (*alias,log_operation(&tracker,alias,held,entries).is_some()) };
    crate::principal_binding::with_live_alias(aliases,principals,&uid,operation).ok()
}

/// Reusing an outstanding log operation after retirement requires the same
/// tracker and owner. Otherwise opening a managed log needs a new guard.
fn log_operation<'a>(tracker:&u64,owner:&u64,held:Option<&'a (u64,Option<u64>)>,entries:HashMap<u64,PrincipalInvocation>)
    -> (out:Option<crate::native_log_admission::Operation<'a,(u64,Option<u64>)>>)
    requires hash_map_inv(&entries),
    ensures ({
        let live = available(entries@,*owner);
        let matches = held matches Some(g) && g.0 == *tracker && g.1 == Some(*owner);
        match out {
            Some(crate::native_log_admission::Operation::Borrowed{_borrowed:g}) => matches && held == Some(g),
            Some(crate::native_log_admission::Operation::Owned{_owned:g}) => !matches && live && g == (*tracker,Some(*owner)),
            None => !matches && !live,
        }
    }),
{
    let covers = |g:&(u64,Option<u64>),t:&u64,p:&u64| -> (ok:bool)
        ensures ok == (g.0 == *t && g.1 == Some(*p))
    {
        crate::principal_invocation_state::covers(&g.0,g.1.as_ref(),t,p,
            |a:&u64,b:&u64| -> (same:bool) ensures same == (*a == *b) { *a == *b })
    };
    let begin = move |t:&u64,p:&u64| -> (g:Option<(u64,Option<u64>)>)
        ensures g == (if available(entries@,*p) {Some((*t,Some(*p)))} else {None})
    {
        let mut tracked = entries;
        match acquire(&mut tracked,p) {
            Some(key) => Some((*t,Some(key))),
            None => None,
        }
    };
    crate::native_log_admission::admit(tracker,owner,held,covers,begin)
}

/// On Unix, either exclusive creation returned this handle, or the open
/// of the same parent and leaf returned it and identity confirmation passed.
fn append_handle<T,I,H,E,A:crate::private_append_leaf::LeafAccess<T,I,H,E>>(io:&mut A,target:&T)
    -> (out:Result<H,E>)
    ensures ({
        let prior = old(io).calls().len();
        let calls = final(io).calls();
        &&& prior < calls.len() <= prior + 5
        &&& match out {
            Ok(h) => match calls.last() {
                crate::private_append_leaf::Call::Create(t,Ok(created)) => t == *target && created == h,
                crate::private_append_leaf::Call::Confirm(t,id,opened,Ok(())) => t == *target && opened == h &&
                    calls[calls.len()-2] == crate::private_append_leaf::Call::Open(*target,Ok(h)) &&
                    calls[calls.len()-3] == crate::private_append_leaf::Call::Observe(*target,Ok(id)),
                _ => false,
            },
            Err(_) => true,
        }
    }),
{
    let out = crate::private_append_leaf::open(io,target);
    out
}

}
