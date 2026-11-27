//! Construct the command passed to the hosted sandbox wrapper.
use vstd::prelude::*;

verus! {

/// Proof-only history of calls to the native command builder.
#[allow(dead_code)]
pub(super) ghost enum Step<'a, D> {
    Program(&'a str),
    Arguments(&'a [String]),
    Directory(D),
    Clear,
    Set(Seq<char>, Seq<char>),
}

pub(super) trait Builder<'a, D>: Sized {
    spec fn steps(&self) -> Seq<Step<'a, D>>;

    fn new(program: &'a str) -> (builder: Self)
        ensures builder.steps() == seq![Step::Program(program)];

    fn arguments(&mut self, args: &'a [String])
        ensures final(self).steps() == old(self).steps().push(Step::Arguments(args));

    fn directory(&mut self, cwd: D)
        ensures final(self).steps() == old(self).steps().push(Step::Directory(cwd));

    fn clear_environment(&mut self)
        ensures final(self).steps() == old(self).steps().push(Step::Clear);

    fn set(&mut self, key: &str, value: &str)
        ensures final(self).steps() == old(self).steps().push(Step::Set(key@, value@));
}

pub(super) open spec fn assignments<'a, D>(env: &'a [(String, String)]) -> Seq<Step<'a, D>> {
    Seq::new(env@.len(), |i: int| Step::Set(env@[i].0@, env@[i].1@))
}

fn apply_environment<'a, D, B: Builder<'a, D>>(builder: &mut B, env: &'a [(String, String)])
    ensures final(builder).steps() == old(builder).steps() + assignments(env),
{
    let mut i = 0;
    while i < env.len()
        invariant
            i <= env.len(),
            builder.steps() == old(builder).steps() + assignments(env).take(i as int),
        decreases env.len() - i,
    {
        let pair = &env[i];
        builder.set(pair.0.as_str(), pair.1.as_str());
        assert(assignments::<D>(env).take(i as int + 1) =~=
            assignments::<D>(env).take(i as int).push(Step::Set(pair.0@, pair.1@)));
        i += 1;
    }
    assert(assignments::<D>(env).take(i as int) =~= assignments::<D>(env));
}

pub(super) fn build<'a, D, B: Builder<'a, D>>(
    program: &'a str, args: &'a [String], cwd: D,
    environment: &'a [(String, String)], injections: &'a [(String, String)],
) -> (builder: B)
    ensures builder.steps() == seq![Step::Program(program), Step::Arguments(args),
        Step::Directory(cwd), Step::Clear] + assignments(environment) + assignments(injections),
{
    let mut builder = B::new(program);
    builder.arguments(args);
    builder.directory(cwd);
    builder.clear_environment();
    apply_environment(&mut builder, environment);
    apply_environment(&mut builder, injections);
    builder
}

}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::process::Command;

    #[test]
    fn process_builder_preserves_program_arguments_and_directory() {
        let cwd = tempfile::tempdir().unwrap();
        let args = ["", "two words", "--", "λ"].map(str::to_owned);
        let cmd: Command = super::build("bin/program name", &args, cwd.path(), &[], &[]);
        assert_eq!(cmd.get_program(), OsStr::new("bin/program name"));
        assert!(cmd.get_args().eq(args.iter().map(OsStr::new)));
        assert_eq!(cmd.get_current_dir(), Some(cwd.path()));
    }

    #[cfg(unix)]
    #[test]
    fn process_builder_clears_inheritance_and_applies_host_injections_last() {
        let cwd = tempfile::tempdir().unwrap();
        let environment = [
            ("REQUEST".to_owned(), "guest value".to_owned()),
            ("DUP".to_owned(), "first".to_owned()),
            ("DUP".to_owned(), "second".to_owned()),
        ];
        let injections = [("REQUEST".to_owned(), "host value".to_owned())];
        let mut cmd: Command =
            super::build("/usr/bin/env", &[], cwd.path(), &environment, &injections);
        let output = cmd.output().unwrap();
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let mut lines: Vec<_> = stdout.lines().collect();
        lines.sort_unstable();
        assert_eq!(lines, ["DUP=second", "REQUEST=host value"]);
    }
}
