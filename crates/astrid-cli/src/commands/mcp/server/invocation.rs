//! The broker tool call carries the same invocation used for consent and retry.
use vstd::prelude::*;

verus! {

pub(super) const TOOL_CALL_TOPIC: &str = "astrid.v1.request.mcp.tool.call";

pub(super) struct Invocation<'a,A> {
    name: &'a str,
    arguments: &'a A,
}

impl<'a,A> Invocation<'a,A> {
    pub(super) closed spec fn parts(&self) -> (&'a str,&'a A) {
        (self.name,self.arguments)
    }

    pub(super) fn new(name:&'a str, arguments:&'a A) -> (call:Self)
        ensures call.parts() == (name,arguments),
    { Self { name, arguments } }

    pub(super) fn consent_context(&self) -> (pair:(&'a str,&'a A))
        ensures pair == self.parts(),
    { (self.name,self.arguments) }

    pub(super) fn publish<'r,B,R,E,S>(&self, id:&'r str, encode:E, send:S) -> (out:R)
        where E: FnOnce(&'r str,&'a str,&'a A) -> B, S: FnOnce(&'static str,&'r str,B) -> R,
        requires encode.requires((id,self.parts().0,self.parts().1)),
            forall|b:B| encode.ensures((id,self.parts().0,self.parts().1),b)
                ==> send.requires((TOOL_CALL_TOPIC,id,b)),
        ensures exists|b:B| encode.ensures((id,self.parts().0,self.parts().1),b)
            && #[trigger] send.ensures((TOOL_CALL_TOPIC,id,b),out),
    {
        let body = encode(id,self.name,self.arguments);
        send(TOOL_CALL_TOPIC,id,body)
    }
}
}
