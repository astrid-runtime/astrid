//! Bind a pending tool request to the selected registration before releasing the registry lock.
use super::peer_selection::{LookupError, select};
use std::collections::HashMap;
use vstd::prelude::*;
#[cfg(verus_keep_ghost)]
use vstd::std_specs::hash::hash_map_inv;

verus! {

pub(crate) struct ToolCall<'a,A> {
    tool: &'a str,
    arguments: A,
}

impl<'a,A> ToolCall<'a,A> {
    pub(crate) closed spec fn parts(&self) -> (&'a str,A) { (self.tool,self.arguments) }

    pub(crate) fn new(tool: &'a str, arguments: A) -> (call: Self)
        ensures call.parts() == (tool,arguments),
    {
        Self { tool, arguments }
    }

    pub(crate) fn tool(&self) -> (tool: &'a str)
        ensures tool == self.parts().0,
    { self.tool }
}

impl<A> ToolCall<'static,A> {
    pub(crate) fn hook<'a,V,F: FnOnce(&'a str,V) -> A>(action: &'a str, payload: V, encode: F)
        -> (call: Self)
        requires encode.requires((action,payload)),
        ensures call.parts().0@ == "astrid_hook_intercept"@ && encode.ensures((action,payload),call.parts().1),
    {
        Self::new("astrid_hook_intercept", encode(action,payload))
    }
}

pub(crate) struct RoutedCall<'a,P,A> {
    peer: P,
    call: ToolCall<'a,A>,
}

impl<'a,P,A> RoutedCall<'a,P,A> {
    pub(crate) closed spec fn parts(&self) -> (P,&'a str,A) {
        (self.peer,self.call.tool,self.call.arguments)
    }

    pub(crate) fn send<R,F: FnOnce(P,&'a str,A) -> R>(self, send: F) -> (out: R)
        requires send.requires(self.parts()),
        ensures send.ensures(self.parts(),out),
    {
        send(self.peer,self.call.tool,self.call.arguments)
    }
}

pub(super) fn bind<'a,S,P,A,F: Fn(&S) -> Option<P>>(servers: &HashMap<String,S>,
    requested: &str, call: ToolCall<'a,A>, peer: F) -> (result: Result<RoutedCall<'a,P,A>,LookupError>)
    requires hash_map_inv(servers), forall|s:&S| #[trigger] peer.requires((s,)),
    ensures match result {
        Ok(bound) => bound.parts().1 == call.parts().0 && bound.parts().2 == call.parts().1
            && exists|k:String| #[trigger] servers@.contains_key(k) && k@ == requested@
                && peer.ensures((&servers@[k],),Some(bound.parts().0)),
        Err(LookupError::Disconnected) => exists|k:String| #[trigger] servers@.contains_key(k)
            && k@ == requested@ && peer.ensures((&servers@[k],),None),
        Err(LookupError::Missing) => forall|k:String| #[trigger] servers@.contains_key(k) ==> k@ != requested@,
    },
{
    let selected = select(servers,requested,peer)?;
    Ok(RoutedCall { peer: selected, call })
}
}
