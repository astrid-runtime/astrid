//! Select a command builder, preserving sandbox errors before process launch.
use vstd::prelude::*;

verus! {

#[cfg(verus_keep_ghost)]
pub(super) enum Build<C,T,E> {
    Sandboxed(Seq<char>,C,bool,Result<T,E>),
    Direct(Seq<char>,C,T),
}

pub(super) trait Builder<C,T,E> {
    spec fn calls(&self) -> Seq<Build<C,T,E>>;

    fn sandboxed(&mut self, program: &str, config: &C, network: bool) -> (out: Result<T,E>)
        ensures final(self).calls() == old(self).calls().push(Build::Sandboxed(program@,*config,network,out));

    fn direct(&mut self, program: &str, config: &C) -> (command: T)
        ensures final(self).calls() == old(self).calls().push(Build::Direct(program@,*config,command));
}

pub(super) fn prepare<C,T,E,B:Builder<C,T,E>>(
    builder: &mut B, program: &str, config: &C, trusted: bool, allow_network: bool,
) -> (out: Result<T,E>)
    ensures if trusted {
        out matches Ok(t) && final(builder).calls() == old(builder).calls().push(Build::Direct(program@,*config,t))
    } else {
        final(builder).calls() == old(builder).calls().push(Build::Sandboxed(program@,*config,allow_network,out))
    },
{
    if trusted {
        Ok(builder.direct(program,config))
    } else {
        builder.sandboxed(program,config,allow_network)
    }
}

}
