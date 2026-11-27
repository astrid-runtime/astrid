//! Bind construction of one HTTP request to the operation and URL admitted for that hop.
use vstd::prelude::*;

verus! {

pub(super) struct Admitted<M,U> { method: M, url: U }

impl<M: Copy,U: Copy> Admitted<M,U> {
    pub(super) closed spec fn target(&self) -> (M,U) { (self.method,self.url) }

    pub(super) fn request<R,F:FnOnce(M,U)->R>(self, build:F) -> (r:R)
        requires build.requires(self.target()),
        ensures build.ensures(self.target(),r),
    {
        build(self.method,self.url)
    }
}

pub(super) fn admit<M:Copy,U:Copy,G,E,F:FnOnce(M,U)->Result<G,E>>(
    method:M, url:U, check:F,
) -> (out:Result<(Admitted<M,U>,G),E>)
    requires check.requires((method,url)),
    ensures match out {
        Ok((hop,grant)) => hop.target() == (method,url) && check.ensures((method,url),Ok(grant)),
        Err(e) => check.ensures((method,url),Err(e)),
    },
{
    let grant = check(method,url)?;
    Ok((Admitted { method, url },grant))
}

}
