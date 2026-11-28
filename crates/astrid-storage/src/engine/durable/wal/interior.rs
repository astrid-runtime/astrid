//! Search each candidate offset in order. A reader can report an early end
//! when its stream is shorter than the size observed at the initial seek.
use vstd::prelude::*;

verus! {

pub(super) enum Probe { Miss, Found, End }

pub(super) enum Boundary { End(u64), Tail(u64) }

pub(super) fn boundary(active_begin:Option<u64>,cursor:u64,damaged:bool) -> (out:Boundary)
    ensures out == match active_begin {
        Some(begin) => Boundary::Tail(begin),
        None => if damaged {Boundary::Tail(cursor)} else {Boundary::End(cursor)},
    },
{
    match active_begin {
        Some(begin) => Boundary::Tail(begin),
        None if damaged => Boundary::Tail(cursor),
        None => Boundary::End(cursor),
    }
}

pub(super) open spec fn observed<R,E,F:Fn(R,u64)->(R,Result<Probe,E>)>(probe:F, at:u64, value:Result<Probe,E>) -> bool {
    exists|before:R,after:R| #[trigger] probe.ensures((before,at),(after,value))
}

pub(super) fn search<R,E,F:Fn(R,u64)->(R,Result<Probe,E>)>(mut reader:R, start:u64, end:u64, probe:F)
    -> (result:(R,Result<Option<u64>,(u64,E)>))
    requires forall|r:R,at:u64| start <= at < end ==> #[trigger] probe.requires((r,at)),
    ensures ({
        match result.1 {
            Ok(Some(hit)) => start <= hit < end && observed(probe,hit,Ok(Probe::Found)) &&
                forall|j:u64| start <= j < hit ==> #[trigger] observed(probe,j,Ok(Probe::Miss)),
            Ok(None) => (forall|j:u64| start <= j < end ==> #[trigger] observed(probe,j,Ok(Probe::Miss))) ||
                exists|stop:u64| start <= stop < end && #[trigger] observed(probe,stop,Ok(Probe::End)) &&
                forall|j:u64| start <= j < stop ==> #[trigger] observed(probe,j,Ok(Probe::Miss)),
            Err((stop,e)) => start <= stop < end && observed(probe,stop,Err(e)) &&
                forall|j:u64| start <= j < stop ==> #[trigger] observed(probe,j,Ok(Probe::Miss)),
        }
    }),
{
    let mut at = start;
    while at < end
        invariant start <= at, at <= end || at == start,
            forall|r:R,k:u64| start <= k < end ==> #[trigger] probe.requires((r,k)),
            forall|j:u64| start <= j < at ==> #[trigger] observed(probe,j,Ok(Probe::Miss)),
        decreases end as int - at,
    {
        let (next,value) = probe(reader,at);
        assert(probe.ensures((reader,at),(next,value)));
        assert(observed(probe,at,value));
        reader = next;
        match value {
            Ok(Probe::Found) => return (reader,Ok(Some(at))),
            Ok(Probe::End) => return (reader,Ok(None)),
            Err(error) => { assert(observed(probe,at,Err(error))); return (reader,Err((at,error))); },
            Ok(Probe::Miss) => {},
        }
        at = at.saturating_add(1);
    }
    assert forall|j:u64| start <= j < end implies #[trigger] observed(probe,j,Ok(Probe::Miss)) by {};
    (reader,Ok(None))
}

}
