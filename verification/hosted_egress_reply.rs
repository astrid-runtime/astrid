//! Consume the local-egress transition for an arbitrary endpoint and existing grant history.
use crate::consent_reply::{self, Decision};
use crate::egress_reply::{self, Store, Writer};
use vstd::prelude::*;

verus! {

type Target<'a> = egress_reply::GrantTarget<&'a str,&'a str,&'a str>;

struct Grants<'a> {
    history:Vec<(Store,Target<'a>)>,
    profile_error:Option<u8>,
}

impl<'a> Writer<Target<'a>> for Grants<'a> {
    type Error = u8;
    closed spec fn attempts(&self) -> Seq<(Store,Target<'a>)> { self.history@ }
    closed spec fn result(&self,store:Store,_target:Target<'a>,r:Result<(),u8>) -> bool {
        r == match (store,self.profile_error) {
            (Store::Profile,Some(e)) => Err(e),
            _ => Ok(()),
        }
    }
    fn install(&mut self,store:Store,target:Target<'a>) -> Result<(),u8> {
        self.history.push((store,target));
        match (store,self.profile_error) {
            (Store::Profile,Some(e)) => Err(e),
            _ => Ok(()),
        }
    }
}

fn receipt<'a>(wire:&[u8],profile:bool,principal:&'a str,capsule:&'a str,host:&'a str,
    port:u16,grants:&mut Grants<'a>) -> (out:Result<Decision,u8>)
    ensures ({
        let d = consent_reply::scope(wire@);
        let target = Target {principal,capsule,host,port};
        let history = old(grants).history@;
        &&& final(grants).history@ == match d {
            Decision::Always if profile => history.push((Store::Profile,target)),
            Decision::Session | Decision::Always => history.push((Store::Session,target)),
            _ => history,
        }
        &&& out == match (d,profile,old(grants).profile_error) {
            (Decision::Always,true,Some(e)) => Err(e),
            _ => Ok(d),
        }
    }),
{
    egress_reply::apply(wire,profile,Target {principal,capsule,host,port},grants)
}
}
