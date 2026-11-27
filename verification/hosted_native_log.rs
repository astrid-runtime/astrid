//! Compose the native UID lookup and log admission with the locked tracker transition.
use std::collections::HashMap;
use vstd::{prelude::*,std_specs::hash::hash_map_inv};
use crate::native_log_admission::Operation;
use crate::native_log_dispatch::{DaemonPolicy,Destination,Event,Output};
use crate::windows_append_confirmation::{Call,Failure};
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

/// Compose the locked tracker decision with dispatch for a single managed file.
/// The native resolver supplies the candidate and classifies injected files.
fn managed_write<'a,F,R,O:Output<F,Operation<'a,(u64,Option<u64>)>,R>>(
    output:&mut O, file:F, record:&R, policy:DaemonPolicy, tracker:u64, owner:u64,
    held:Option<&'a (u64,Option<u64>)>, entries:HashMap<u64,PrincipalInvocation>,
)
    requires hash_map_inv(&entries),
    ensures ({
        let prior = old(output).events();
        let after = final(output).events();
        let covers = held matches Some(g) && *g == (tracker,Some(owner));
        if !covers && !available(entries@,owner) {
            after == prior.push(Event::Daemon(*record))
        } else {
            match after[prior.len() as int] {
                Event::Write(f,Some(guard),line,written) => {
                    &&& f == file && line == *record
                    &&& match guard {
                        Operation::Borrowed{_borrowed:g} => covers && held == Some(g),
                        Operation::Owned{_owned:g} => !covers && available(entries@,owner) && g == (tracker,Some(owner)),
                    }
                    &&& {
                        let first = prior.push(Event::Write(file,Some(guard),*record,written));
                        after == if !written || policy is Always { first.push(Event::Daemon(*record)) } else { first }
                    }
                },
                _ => false,
            }
        }
    }),
{
    let destination = match log_operation(&tracker,&owner,held,entries) {
        Some(guard) => Destination::Managed(file,guard),
        None => Destination::Absent,
    };
    crate::native_log_dispatch::dispatch(output,&destination,record,policy);
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


/// A returned Windows handle is the leaf whose volume matched the retained
/// root. The parent and root-directory checks precede the final recapture.
fn windows_handle<H,D,P,E,A:crate::windows_append_confirmation::Checks<H,D,P,E>>(
    io:&mut A,file:H,root:&H,parent:&D,root_directory:&D,path:&P,
) -> (out:Result<H,crate::windows_append_confirmation::Failure<E>>)
    ensures ({
        let prior = old(io).calls().len() as int;
        let calls = final(io).calls();
        match out {
            Ok(h) => {
                &&& h == file
                &&& calls.len() == prior + 5
                &&& (calls[prior] matches Call::Volume(leaf,Ok(v)) &&
                    leaf == h && calls[prior+1] == Call::Volume(*root,Ok(v)))
                &&& calls[prior+2] == Call::Directory(*parent,None)
                &&& calls[prior+3] == Call::Directory(*root_directory,None)
                &&& calls[prior+4] == Call::Recapture(*path,*root,None)
            },
            Err(Failure::CrossVolume) => {
                &&& calls.len() == prior + 2
                &&& (calls[prior] matches Call::Volume(leaf,Ok(v)) && leaf == file &&
                    (calls[prior+1] matches Call::Volume(r,Ok(w)) && r == *root && v != w))
            },
            Err(Failure::Native(error)) => {
                let n = calls.len() - prior;
                if n == 1 {
                    calls[prior] == Call::Volume(file,Err(error))
                } else {
                    calls[prior] matches Call::Volume(h,Ok(volume)) && h == file && (
                        if n == 2 {
                            calls[prior+1] == Call::Volume(*root,Err(error))
                        } else {
                            &&& calls[prior+1] == Call::Volume(*root,Ok(volume))
                            &&& if n == 3 {
                                calls[prior+2] == Call::Directory(*parent,Some(error))
                            } else {
                                &&& calls[prior+2] == Call::Directory(*parent,None)
                                &&& if n == 4 {
                                    calls[prior+3] == Call::Directory(*root_directory,Some(error))
                                } else {
                                    &&& n == 5
                                    &&& calls[prior+3] == Call::Directory(*root_directory,None)
                                    &&& calls[prior+4] == Call::Recapture(*path,*root,Some(error))
                                }
                            }
                        }
                    )
                }
            },
        }
    }),
{
    crate::windows_append_confirmation::finish(io,file,root,parent,root_directory,path)
}

}
