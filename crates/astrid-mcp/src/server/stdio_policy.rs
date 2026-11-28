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

#[cfg(verus_keep_ghost)]
pub(super) enum Assembly<P,C,T> { Wrapped(P,C,T), Bare(C,T) }

pub(super) trait Assembler<P,C,T> {
    spec fn commands(&self) -> Seq<Assembly<P,C,T>>;

    fn wrapped(&mut self, prefix: P, child: &C) -> (command:T)
        ensures final(self).commands() == old(self).commands().push(Assembly::Wrapped(prefix,*child,command));

    fn bare(&mut self, child: &C) -> (command:T)
        ensures final(self).commands() == old(self).commands().push(Assembly::Bare(*child,command));
}

/// Preserve the approved prefix, child program and arguments through construction.
pub(super) fn assemble<P,C,T,E,A:Assembler<P,C,T>>(
    assembler:&mut A, prefix:Result<Option<P>,E>, child:&C,
) -> (out:Result<T,E>)
    ensures ({
        let before = old(assembler).commands();
        let after = final(assembler).commands();
        match prefix {
            Err(e) => out == Err(e) && after == before,
            Ok(Some(p)) => out matches Ok(t) && after == before.push(Assembly::Wrapped(p,*child,t)),
            Ok(None) => out matches Ok(t) && after == before.push(Assembly::Bare(*child,t)),
        }
    }),
{
    match prefix {
        Err(error) => Err(error),
        Ok(Some(prefix)) => Ok(assembler.wrapped(prefix,child)),
        Ok(None) => Ok(assembler.bare(child)),
    }
}

}
