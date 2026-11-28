//! Create shared authority handles after the ownership read and retirement replay succeed.
use std::sync::Arc;
use vstd::prelude::*;

verus! {
pub(super) fn publish<G,S,C,A,E,F:FnOnce(G,S)->Result<(C,A),E>>(
    read:Result<G,E>,private:S,restore:F,
) -> (out:Result<(Arc<C>,Arc<A>),E>)
    requires read matches Ok(graph) ==> restore.requires((graph,private)),
    ensures match read {
        Err(e) => out == Err(e),
        Ok(graph) => match out {
            Ok((capabilities,allowances)) => restore.ensures((graph,private),Ok((*capabilities,*allowances))),
            Err(e) => restore.ensures((graph,private),Err(e)),
        },
    },
{
    let graph = read?;
    let (capabilities,allowances) = restore(graph,private)?;
    Ok((Arc::new(capabilities),Arc::new(allowances)))
}
}
