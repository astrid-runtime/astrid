//! Independent consumer for an overlapping request and host environment key.
use crate::process_command::{self, Builder, Step};
use vstd::prelude::*;

verus! {

fn overlapping_setting<'a, D, B: Builder<'a, D>>(
    program: &'a str, args: &'a [String], cwd: D,
    request: &'a [(String, String)], host: &'a [(String, String)],
) -> (cmd: B)
    requires request.len() == 1, host.len() == 1, request@[0].0@ == host@[0].0@,
    ensures
        cmd.steps().len() == 6,
        cmd.steps()[0] == Step::Program(program),
        cmd.steps()[1] == Step::Arguments(args),
        cmd.steps()[2] == Step::Directory(cwd),
        cmd.steps()[3] == Step::Clear,
        cmd.steps()[4] == Step::Set(request@[0].0@, request@[0].1@),
        cmd.steps()[5] == Step::Set(request@[0].0@, host@[0].1@),
{
    process_command::build(program, args, cwd, request, host)
}

}
