//! Exercise the actual admitted-hop constructor and request handoff.
use crate::http_hop;
use vstd::prelude::*;

verus! {

fn matching(method:u8,url:u64, permitted_method:u8,permitted_url:u64, denial:u8) -> (out:Result<(u8,u64),u8>)
    ensures out == if method == permitted_method && url == permitted_url { Ok((method,url)) } else { Err(denial) },
{
    let check = |m:u8,u:u64| -> (r:Result<(),u8>)
        ensures r == if m == permitted_method && u == permitted_url {Ok(())} else {Err(denial)},
    { if m == permitted_method && u == permitted_url {Ok(())} else {Err(denial)} };
    let (hop,_) = http_hop::admit(method,url,check)?;
    let request = |m:u8,u:u64| -> (r:(u8,u64)) ensures r == (m,u), { (m,u) };
    Ok(hop.request(request))
}

fn buffered_receipt(body: Vec<u8>, device_live: bool, invocation_live: bool,
    transport: Result<(),u8>, closed:u8) -> (out:Result<Vec<u8>,u8>)
    ensures
        !device_live || !invocation_live ==> out == Err(closed),
        device_live && invocation_live ==> match transport {
            Ok(()) => out matches Ok(bytes) && bytes@ == body@,
            Err(e) => out == Err(e),
        },
{
    let outcome = if !device_live { None }
        else if !invocation_live { Some(None) }
        else { Some(Some(transport)) };
    crate::http_body::finish(body,outcome,closed)
}

fn stream_release(owner:bool, opening:bool, reader:bool, payload:u64) -> (r:Option<u64>)
    ensures r == if owner && opening && reader { Some(payload) } else { None },
{
    crate::http_body::disclose(owner,opening,reader,payload,|selected:u64| -> (v:u64) ensures v == selected, {selected})
}

}
