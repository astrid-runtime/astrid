//! KV accounting used on both sides of durable replay.
use super::checkpoint_totals::NodeTotals;
use vstd::prelude::*;

verus! {
#[derive(Clone,Copy)]
pub(super) enum Error { Key, Entries, Logical, Quota }

pub(super) open spec fn changed(old:NodeTotals,key:nat,previous:Option<usize>,replacement:Option<usize>)
    -> Result<NodeTotals,Error> {
    let a = match previous {None=>0int,Some(n)=>n as int};
    let b = match replacement {None=>0int,Some(n)=>n as int};
    let add = if previous.is_none() && replacement.is_some() {1int} else {0int};
    let remove = if previous.is_some() && replacement.is_none() {1int} else {0int};
    let entries = old.entries as int + add - remove;
    let logical = old.logical_bytes as int - a + b;
    let left = old.quota_bytes as int - a;
    let keys = if add == 1 {left + key} else if remove == 1 {left-key} else {left};
    let quota = keys + b;
    if key > u64::MAX {Err(Error::Key)}
    else if entries < 0 || entries > u64::MAX {Err(Error::Entries)}
    else if a > old.logical_bytes || logical > u64::MAX {Err(Error::Logical)}
    else if left < 0 || keys < 0 || keys > u64::MAX || quota > u64::MAX {Err(Error::Quota)}
    else {Ok(NodeTotals {entries:entries as u64,logical_bytes:logical as u64,quota_bytes:quota as u64})}
}

pub(super) fn update(old:NodeTotals,key:usize,previous:Option<usize>,replacement:Option<usize>)
    -> (out:Result<NodeTotals,Error>)
    ensures out == changed(old,key as nat,previous,replacement),
{
    let key_bytes = u64::try_from(key).map_err(|_| Error::Key)?;
    let a = previous.unwrap_or(0) as u64;
    let b = replacement.unwrap_or(0) as u64;
    let entries = match (previous,replacement) {
        (None,Some(_)) => old.entries.checked_add(1),
        (Some(_),None) => old.entries.checked_sub(1),
        _ => Some(old.entries),
    }.ok_or(Error::Entries)?;
    let logical = old.logical_bytes.checked_sub(a).ok_or(Error::Logical)?.checked_add(b).ok_or(Error::Logical)?;
    let left = old.quota_bytes.checked_sub(a).ok_or(Error::Quota)?;
    let keys = match (previous,replacement) {
        (None,Some(_)) => left.checked_add(key_bytes),
        (Some(_),None) => left.checked_sub(key_bytes),
        _ => Some(left),
    };
    let quota = keys.ok_or(Error::Quota)?.checked_add(b).ok_or(Error::Quota)?;
    Ok(NodeTotals {entries,logical_bytes:logical,quota_bytes:quota})
}

pub(super) enum ApplyError<E> { Load(E), Change(ReplayError) }

pub(super) enum ReplayError { Unchanged, Accounting(Error) }

pub(super) fn admit(old:NodeTotals,key:usize,previous:Option<usize>,replacement:Option<usize>,unchanged:bool)
    -> (out:Result<NodeTotals,ReplayError>)
    ensures out == if unchanged || (previous.is_none() && replacement.is_none()) {Err(ReplayError::Unchanged)}
        else { match changed(old,key as nat,previous,replacement) {
            Ok(t)=>Ok(t),Err(e)=>Err(ReplayError::Accounting(e)),
        }},
{
    if unchanged || (previous.is_none() && replacement.is_none()) {return Err(ReplayError::Unchanged);}
    match update(old,key,previous,replacement) {
        Ok(t)=>Ok(t),Err(e)=>Err(ReplayError::Accounting(e)),
    }
}

pub(super) struct Prepared {
    pub(super) key:Vec<u8>,
    pub(super) value:Option<Vec<u8>>,
    pub(super) totals:NodeTotals,
}

pub(super) open spec fn prior_bytes(prior:Option<&[u8]>) -> Option<Seq<u8>> {
    match prior {Some(s)=>Some(s@),None=>None}
}

pub(super) open spec fn data_bytes(value:Option<Vec<u8>>) -> Option<Seq<u8>> {
    match value {Some(v)=>Some(v@),None=>None}
}

pub(super) fn prepare(old:NodeTotals,key:&[u8],prior:Option<&[u8]>,value:Option<Vec<u8>>)
    -> (out:Result<Prepared,ReplayError>)
    ensures ({
        let before = prior_bytes(prior);
        let after = data_bytes(value);
        let accounting = changed(old,key.len() as nat,
            match before {Some(s)=>Some(s.len() as usize),None=>None},
            match after {Some(s)=>Some(s.len() as usize),None=>None});
        if before == after {out == Err(ReplayError::Unchanged)}
        else {match accounting {
            Ok(t) => out matches Ok(p) && p.key@ == key@ && p.value == value && p.totals == t,
            Err(e) => out == Err(ReplayError::Accounting(e)),
        }}
    }),
{
    let equal = match (prior,&value) {
        (Some(a),Some(b)) => {
            let same = a == b.as_slice();
            if same {assert(a@ =~= b@);}
            same
        },
        (None,None) => true,
        _ => false,
    };
    let before = prior.map(<[u8]>::len);
    let after = value.as_ref().map(Vec::len);
    let totals = admit(old,key.len(),before,after,equal)?;
    let mut address = Vec::with_capacity(key.len());
    address.extend_from_slice(key);
    assert(address@ =~= key@);
    Ok(Prepared {key:address,value,totals})
}
}
