//! Mount precedence and resolution of gated guest paths to a VFS bundle.

use vstd::prelude::*;

verus! {

/// Choose an invocation override before the runtime's load-time mount.
pub(super) fn effective<T>(invocation: Option<T>, runtime: Option<T>) -> (mount: Option<T>)
    ensures mount == if invocation.is_some() { invocation } else { runtime },
{
    match invocation { Some(value) => Some(value), None => runtime }
}

/// A principal-bound workspace lookup must never inherit a load-time branch.
pub(super) fn workspace<T>(requires_binding: bool, invocation: Option<T>, runtime: Option<T>) -> (mount: Option<T>)
    ensures mount == if requires_binding || invocation.is_some() { invocation } else { runtime },
{
    if requires_binding { invocation } else { effective(invocation, runtime) }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum VfsTarget {
    Workspace,
    Home,
    Tmp,
}

/// Storage-backed roots whose capability spelling and VFS destination must agree.
#[derive(Clone, Copy)]
pub(super) enum LogicalRoot { Home, Workspace }

impl LogicalRoot {
    pub(super) fn bind_path(self, relative: &str) -> (bound: (String, &str, VfsTarget))
        ensures
            bound.1@ == relative@,
            match self {
                Self::Home => bound.0@ == "home://"@ + relative@ && bound.2 == VfsTarget::Home,
                Self::Workspace => bound.0@ == "workspace://"@ + relative@ && bound.2 == VfsTarget::Workspace,
            },
    {
        let (scheme, target) = match self {
            Self::Home => ("home://", VfsTarget::Home),
            Self::Workspace => ("workspace://", VfsTarget::Workspace),
        };
        let mut gate = scheme.to_owned();
        gate.push_str(relative);
        (gate, relative, target)
    }
}

impl VfsTarget {
    /// Hold the policy result together with the mount and address it releases.
    pub(super) fn admitted<K,P,M,G,E,F:FnOnce(K)->Result<G,E>>(
        self, gate:K, path:P, mounts:(Option<M>,Option<M>,Option<M>), missing:E, check:F,
    ) -> (out:Result<(G,M,P),E>)
        requires check.requires((gate,)),
        ensures ({
            let selected = match self { Self::Workspace => mounts.0, Self::Home => mounts.1, Self::Tmp => mounts.2 };
            match out {
                Ok((guard,mount,address)) => check.ensures((gate,),Ok(guard))
                    && Some(mount) == selected && address == path,
                Err(e) => check.ensures((gate,),Err(e)) || (selected.is_none() && e == missing
                    && exists|g:G| #[trigger] check.ensures((gate,),Ok(g))),
            }
        }),
    {
        let guard = check(gate)?;
        match self.bind(path,mounts.0,mounts.1,mounts.2) {
            Some((mount,address)) => Ok((guard,mount,address)),
            None => Err(missing),
        }
    }

    /// Return the selected mount with the same admitted relative path.
    #[expect(clippy::manual_map, reason = "The explicit match lets Verus track the original mount and path through both branches")]
    pub(super) fn bind<M, P>(self, path: P, workspace: Option<M>, home: Option<M>, tmp: Option<M>)
        -> (bound: Option<(M, P)>)
        ensures ({
            let selected = match self { Self::Workspace => workspace, Self::Home => home, Self::Tmp => tmp };
            match selected { Some(mount) => bound == Some((mount, path)), None => bound.is_none() }
        }),
    {
        let mount = match self {
            Self::Workspace => workspace,
            Self::Home => home,
            Self::Tmp => tmp,
        };
        match mount { Some(value) => Some((value, path)), None => None }
    }
}

}
