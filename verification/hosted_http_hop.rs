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

fn pinned_metadata(reader: &str, creator: &str, expected: Option<&[u8; 32]>, owner: &[u8; 32],
    opening: bool, reading: bool, status: u16) -> (result: Option<u16>)
    ensures result == if reader@ == creator@ && opening && reading &&
        (match expected { Some(uid) => uid@ == owner@, None => true }) { Some(status) } else { None },
{
    let bound = crate::http_body::same_owner(reader, creator, expected, owner);
    crate::http_body::disclose(bound, opening, reading, status,
        |selected: u16| -> (v: u16) ensures v == selected, { selected })
}

fn stream_release(owner:bool, opening:bool, reader:bool, payload:u64) -> (r:Option<u64>)
    ensures r == if owner && opening && reader { Some(payload) } else { None },
{
    crate::http_body::disclose(owner,opening,reader,payload,|selected:u64| -> (v:u64) ensures v == selected, {selected})
}

fn stream_result(received: Option<Vec<u8>>, receipt: u64) -> (out: (Vec<u8>, Option<u64>))
    ensures match received {
        Some(bytes) => out.0@ == bytes@ && out.1.is_none(),
        None => out.0@.len() == 0 && out.1 == Some(receipt),
    },
{
    crate::http_body::stream_result(received,
        |bytes: Vec<u8>| -> (r: Vec<u8>) ensures r@ == bytes@, { bytes },
        || -> (r: Option<u64>) ensures r == Some(receipt), { Some(receipt) })
}

fn read_receipt(read: Option<Result<Option<Vec<u8>>, u8>>, timeout: u8, receipt: u64)
    -> (out: (Result<Vec<u8>, u8>, Option<u64>))
    ensures match read {
        Some(Ok(Some(body))) => out.0 matches Ok(bytes) && bytes@ == body@ && out.1.is_none(),
        Some(Ok(None)) => out.0 matches Ok(bytes) && bytes@.len() == 0 && out.1 == Some(receipt),
        Some(Err(reason)) => out == (Err(reason), Some(receipt)),
        None => out == (Err(timeout), None),
    },
{
    crate::http_body::read_outcome(read, timeout,
        |received: Option<Vec<u8>>| -> (r: (Vec<u8>, Option<u64>))
            ensures match received {
                Some(body) => r.0@ == body@ && r.1.is_none(),
                None => r.0@.len() == 0 && r.1 == Some(receipt),
            }, { stream_result(received, receipt) },
        |error: u8| -> (r: (u8, Option<u64>)) ensures r == (error, Some(receipt)), { (error, Some(receipt)) })
}

}
