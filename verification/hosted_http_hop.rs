//! Exercise the actual admitted-hop constructor and request handoff.
use crate::http_hop;
use vstd::prelude::*;

verus! {

fn matching(method:u8,url:u64, permitted_method:u8,permitted_url:u64) -> (out:Result<(u8,u64),()>)
    ensures out == if method == permitted_method && url == permitted_url { Ok((method,url)) } else { Err(()) },
{
    let check = |m:u8,u:u64| -> (r:Result<(),()>)
        ensures r == if m == permitted_method && u == permitted_url {Ok(())} else {Err(())},
    { if m == permitted_method && u == permitted_url {Ok(())} else {Err(())} };
    let (hop,_) = http_hop::admit(method,url,check)?;
    let request = |m:u8,u:u64| -> (r:(u8,u64)) ensures r == (m,u), { (m,u) };
    Ok(hop.request(request))
}

}
