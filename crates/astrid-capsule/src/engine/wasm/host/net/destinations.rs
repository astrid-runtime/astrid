//! Check every resolved TCP destination before handing this same slice to the connector.
use vstd::prelude::*;

verus! {
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Refusal { Empty, Denied }

pub(super) fn connect<'a,A,R,C,F>(answers: &'a [A], port:u16, check:C, dial:F)
    -> (out:Result<R,Refusal>)
    where C:Fn(&A,u16)->bool, F:FnOnce(&'a [A])->R,
    requires forall|a:&A| #[trigger] check.requires((a,port)), dial.requires((answers,)),
    ensures
        (out matches Err(Refusal::Empty)) == (answers.len() == 0),
        out matches Err(Refusal::Denied) ==> exists|i:int| 0 <= i < answers.len()
            && #[trigger] check.ensures((&answers@[i],port),false),
        out matches Ok(r) ==> dial.ensures((answers,),r)
            && forall|i:int| 0 <= i < answers.len() ==> #[trigger] check.ensures((&answers@[i],port),true),
{
    if answers.is_empty() { return Err(Refusal::Empty); }
    let mut i = 0;
    while i < answers.len()
        invariant i <= answers.len(), answers.len() > 0,
            forall|a:&A| #[trigger] check.requires((a,port)), dial.requires((answers,)),
            forall|j:int| 0 <= j < i ==> #[trigger] check.ensures((&answers@[j],port),true),
        decreases answers.len() - i,
    {
        if !check(&answers[i],port) { return Err(Refusal::Denied); }
        i += 1;
    }
    Ok(dial(answers))
}
}
