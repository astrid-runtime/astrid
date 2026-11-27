//! Select a validated checkpoint or publish the state recovered by the arena scan.
use vstd::prelude::*;

verus! {

/// A replacement is required only after a cache miss. Both failure paths
/// propagate their original error before exposing a recovered state.
pub(super) fn select<T,E,S,P>(cached:Option<T>,scan:S,publish:P) -> (out:Result<T,E>)
    where S:FnOnce()->Result<T,E>, P:FnOnce(&T)->Result<(),E>,
    requires scan.requires(()), forall|s:&T| #[trigger] publish.requires((s,)),
    ensures match cached {
        Some(s) => out == Ok(s),
        None => match out {
            Ok(s) => scan.ensures((),Result::<T,E>::Ok(s)) &&
                exists|value:&T,r:Result<(),E>| *value == s && r.is_ok() && #[trigger] publish.ensures((value,),r),
            Err(e) => scan.ensures((),Result::<T,E>::Err(e)) ||
                exists|value:&T| scan.ensures((),Result::<T,E>::Ok(*value)) && #[trigger] publish.ensures((value,),Result::<(),E>::Err(e)),
        },
    },
{
    if let Some(s) = cached {return Ok(s);}
    let recovered = scan()?;
    let value = &recovered;
    let result = publish(value);
    assert(publish.ensures((value,),result));
    if let Err(e) = result {
        assert(publish.ensures((value,),Result::<(),E>::Err(e)));
        return Err(e);
    }
    assert(result.is_ok() && publish.ensures((value,),result));
    Ok(recovered)
}

}
