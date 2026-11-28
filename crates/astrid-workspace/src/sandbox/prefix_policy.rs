//! Operator policy for selecting the native process sandbox wrapper.
use vstd::prelude::*;

verus! {

/// Operator-side policy controlling what happens when OS-level
/// sandboxing is unavailable (e.g. `bwrap` missing or
/// `kernel.apparmor_restrict_unprivileged_userns=1` on Ubuntu 24.04+).
///
/// Two-state on purpose. The default is [`SandboxPolicy::Required`] —
/// refuse to launch unsandboxed subprocesses, matching the security
/// guarantee the README documents. The only escape hatch is
/// [`SandboxPolicy::Off`], which silently launches without a sandbox.
///
/// There is **no** "warn and fall through" middle state. That was the
/// pre-#655 behaviour and it is exactly the bug: a soft fallback hides
/// the fact that the security model isn't applying. Either the sandbox
/// works (`Required`) or the operator explicitly opted out (`Off`). On
/// a clean target system the kernel sandbox should always be available;
/// if it isn't, that's a deployment problem to surface, not paper over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SandboxPolicy {
    /// Refuse to launch if the OS-level sandbox cannot be applied.
    /// [`crate::ProcessSandboxConfig::sandbox_prefix`] returns an error with
    /// an actionable hint (typically the `sysctl` command on Ubuntu
    /// 24.04+). This is the default — fail loudly rather than silently
    /// weaken isolation. Production deployments should always run with
    /// this policy on a properly configured system.
    #[default]
    Required,
    /// Always launch without an OS-level sandbox, no warning. The
    /// operator has explicitly accepted that subprocess capsules will
    /// run with the host user's full reach. Use only for trusted dev
    /// environments, CI runners where the kernel can't be configured
    /// for unprivileged namespaces, or other situations where the
    /// trade-off is documented elsewhere.
    Off,
}

#[cfg(verus_keep_ghost)]
pub(super) enum Check<C,P,E> {
    Paths(C,Option<E>),
    Platform(C,Result<P,E>),
}

pub(super) trait Platform<C,P,E> {
    spec fn checks(&self) -> Seq<Check<C,P,E>>;

    fn path_error(&mut self, config: &C) -> (error: Option<E>)
        ensures final(self).checks() == old(self).checks().push(Check::Paths(*config,error));

    fn prefix(&mut self, config: &C) -> (out:Result<P,E>)
        ensures final(self).checks() == old(self).checks().push(Check::Platform(*config,out));
}

pub(super) fn select<C,P,E,B:Platform<C,P,E>>(io:&mut B,config:&C,policy:SandboxPolicy)
    -> (out:Result<Option<P>,E>)
    ensures ({
        let before = old(io).checks();
        let checked = before.push(Check::Paths(*config,None));
        let after = final(io).checks();
        match out {
            Ok(Some(prefix)) => policy is Required && after == checked.push(Check::Platform(*config,Ok(prefix))),
            Ok(None) => policy is Off && after == checked,
            Err(e) => after == before.push(Check::Paths(*config,Some(e))) ||
                (policy is Required && after == checked.push(Check::Platform(*config,Err(e)))),
        }
    }),
{
    if let Some(error) = io.path_error(config) {
        return Err(error);
    }
    match policy {
        SandboxPolicy::Off => Ok(None),
        SandboxPolicy::Required => match io.prefix(config) {
            Ok(prefix) => Ok(Some(prefix)),
            Err(error) => Err(error),
        }
    }
}

}
