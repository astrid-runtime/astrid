//! Apply the native file-open flags before passing the options to the retained directory.
use vstd::prelude::*;

verus! {
pub(super) trait Options: Sized {
    spec fn flags(&self) -> (bool,bool,bool,bool);
    fn new() -> Self;
    fn read(&mut self, value:bool)
        ensures final(self).flags() == (value,old(self).flags().1,old(self).flags().2,old(self).flags().3);
    fn write(&mut self, value:bool)
        ensures final(self).flags() == (old(self).flags().0,value,old(self).flags().2,old(self).flags().3);
    fn create(&mut self, value:bool)
        ensures final(self).flags() == (old(self).flags().0,old(self).flags().1,value,old(self).flags().3);
    fn truncate(&mut self, value:bool)
        ensures final(self).flags() == (old(self).flags().0,old(self).flags().1,old(self).flags().2,value);
}

pub(super) fn open_with<D,P,B:Options,R,F:FnOnce(D,P,B)->R>(dir:D,path:P,write:bool,truncate:bool,open:F)
    -> (result:R)
    requires forall|b:B| b.flags() == (true,write,write,truncate) ==> #[trigger] open.requires((dir,path,b)),
    ensures exists|b:B| b.flags() == (true,write,write,truncate) && #[trigger] open.ensures((dir,path,b),result),
{
    let mut b = B::new();
    b.read(true);
    b.write(write);
    b.create(write);
    b.truncate(truncate);
    open(dir,path,b)
}
}
