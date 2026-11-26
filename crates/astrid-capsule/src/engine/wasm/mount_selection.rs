//! Mount precedence and resolution of gated guest paths to a VFS bundle.

use vstd::prelude::*;

verus! {

/// Choose an invocation override before the runtime's load-time mount.
pub(super) fn effective<T>(invocation: Option<T>, runtime: Option<T>) -> (mount: Option<T>)
    ensures mount == if invocation.is_some() { invocation } else { runtime },
{
    match invocation { Some(value) => Some(value), None => runtime }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum VfsTarget {
    Workspace,
    Home,
    Tmp,
}

impl VfsTarget {
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
