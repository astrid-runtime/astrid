//! A range spanning adjacent children emits the left suffix followed by the right prefix.
use crate::{ObjectId, ObjectRecord, ObjectFormatVersion, child_range, chunk_range};
use vstd::prelude::*;

verus! {
fn accept(record:&ObjectRecord, version:ObjectFormatVersion, length:u64, count:u64, depth:u32)
    -> (out:Option<chunk_range::Chunk<'_>>)
    ensures ({
        let r = record.contents();
        out.is_some() == (r.0 == crate::ObjectKind::Chunk && r.1 == version.number() &&
            r.5 == crate::ObjectClass::Data && r.4 == 0 && r.3.len() == 0 &&
            r.2.len() == length && count == 1 && depth == 0)
    }),
{
    chunk_range::Chunk::from_record(record,version,length,count,depth)
}

fn crossing<L>(children:&[(ObjectId,u64,u64)], version:ObjectFormatVersion, load:L,
    from:u64, to:u64, output:&mut chunk_range::RangeOutput, table:Ghost<spec_fn(ObjectId)->ObjectRecord>)
    -> (out:Result<(),chunk_range::Error>)
    where L:Fn(ObjectId)->ObjectRecord,
    requires children.len() == 2, children@[0].1 + children@[1].1 <= u64::MAX,
        from < children@[0].1 < to <= children@[0].1 + children@[1].1,
        old(output).snapshot() is Bytes,
        forall|id:ObjectId| #[trigger] load.requires((id,)),
        forall|id:ObjectId,r:ObjectRecord| #[trigger] load.ensures((id,),r) ==> r == (table@)(id),
        forall|i:int| 0 <= i < 2 ==> chunk_range::valid((table@)(#[trigger] children@[i].0),
            version,children@[i].1,children@[i].2,0),
    ensures out.is_ok(), ({
        let a = (table@)(children@[0].0).contents().2;
        let b = (table@)(children@[1].0).contents().2;
        (final(output).snapshot() matches chunk_range::Output::Bytes(bytes) &&
            bytes == old(output).snapshot()->Bytes_0 + a.skip(from as int) + b.take(to - children@[0].1))
    }),
{
    let ghost xs = children@;
    proof {
        assert(xs.drop_last() =~= seq![xs[0]]);
        assert(xs.drop_last().drop_last() =~= Seq::empty());
        reveal_with_fuel(child_range::length,3);
        reveal_with_fuel(child_range::visits,3);
    }
    let plan = child_range::select(children,0,from,to).unwrap();
    let left = &plan[0];
    let right = &plan[1];
    let a = load(left.object);
    let b = load(right.object);
    let first = chunk_range::Chunk::from_record(&a, version,left.length,left.chunks,0).unwrap();
    let second = chunk_range::Chunk::from_record(&b, version,right.length,right.chunks,0).unwrap();
    chunk_range::emit(&first,left.base,from,to,output)?;
    chunk_range::emit(&second,right.base,from,to,output)?;
    assert(a.contents().2.subrange(from as int,a.contents().2.len() as int) =~= a.contents().2.skip(from as int));
    assert(b.contents().2.subrange(0,to - right.base) =~= b.contents().2.take(to - right.base));
    Ok(())
}
}
