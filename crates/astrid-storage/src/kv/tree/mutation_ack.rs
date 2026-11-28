//! Release a mutation result only after its changed replacements are published.
use vstd::prelude::*;

verus! {
pub(super) fn finish<T,M,E,F:FnOnce(M)->Result<bool,E>>(
    output:T, mutations:M, changed:bool, publish:F,
) -> (out:Result<Option<T>,E>)
    requires changed ==> publish.requires((mutations,)),
    ensures !changed ==> out == Ok(Some(output)),
        changed ==> match out {
            Ok(Some(value)) => value == output && publish.ensures((mutations,),Ok(true)),
            Ok(None) => publish.ensures((mutations,),Ok(false)),
            Err(e) => publish.ensures((mutations,),Err(e)),
        },
{
    if !changed || publish(mutations)? { Ok(Some(output)) } else { Ok(None) }
}
}
