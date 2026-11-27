//! An authorized port and all IP classifications constrain the complete dial list.
use crate::tcp_destinations::{connect,Refusal};
use vstd::prelude::*;

verus! {
fn dial(answers:&[(bool,u16,u128)], port:u16) -> (out:Result<&[(bool,u16,u128)],Refusal>)
    ensures
        (out matches Err(Refusal::Empty)) == (answers.len() == 0),
        (out matches Err(Refusal::Denied)) == (exists|i:int| 0 <= i < answers.len()
            && (!(#[trigger] answers@[i]).0 || answers@[i].1 != port)),
        out matches Ok(selected) ==> selected == answers && selected.len() > 0
            && forall|i:int| 0 <= i < selected.len() ==> (#[trigger] selected@[i]).0 && selected@[i].1 == port,
{
    let check = |a:&(bool,u16,u128),p:u16| -> (allow:bool)
        ensures allow == (a.0 && a.1 == p), { a.0 && a.1 == p };
    let out = connect(answers,port,check,
        |selected:&[(bool,u16,u128)]| -> (r:&[(bool,u16,u128)]) ensures r == selected, { selected });
    proof {
        match out {
            Ok(_) => {
                assert forall|i:int| 0 <= i < answers.len() implies
                    (#[trigger] answers@[i]).0 && answers@[i].1 == port by {
                    assert(check.ensures((&answers@[i],port),true));
                }
            }
            Err(Refusal::Denied) => {
                let i = choose|i:int| 0 <= i < answers.len() && #[trigger] check.ensures((&answers@[i],port),false);
                assert(!answers@[i].0 || answers@[i].1 != port);
            }
            _ => {}
        }
    }
    out
}
}
