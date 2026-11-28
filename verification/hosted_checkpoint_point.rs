//! Lookup runs on the same ordered entries and pointers admitted by the page decoder.
use crate::{ObjectId, checkpoint_entries::Row, checkpoint_leaf_summary as leaf, checkpoint_point as point,
    checkpoint_range::Child, checkpoint_summary as branch, checkpoint_totals::NodeTotals,
    checkpoint_value::ValueSlot};
use vstd::prelude::*;

verus! {
// Even an unordered leaf cannot return the slot from an unrelated key.
fn hit_source(rows:Vec<Row>,key:&[u8]) {
    let ghost input = rows@;
    let out = point::leaf(rows,key);
    assert(out matches Some(v) ==> exists|i:int| 0 <= i < input.len() &&
        (#[trigger] input[i]).key@ == key@ && input[i].value == v);
}

fn checked_leaf(rows:Vec<Row>,totals:NodeTotals,key:&[u8],i:usize) {
    let ghost original = rows@;
    if let Ok(page) = leaf::finish(rows,totals) {
        let out = point::leaf(page.entries,key);
        assert(i < original.len() && original[i as int].key@ == key@ ==> out == Some(original[i as int].value));
        assert(out matches Some(v) ==> exists|j:int| 0 <= j < original.len() &&
            (#[trigger] original[j]).key@ == key@ && original[j].value == v);
    }
}

fn wire_order(query:u8,first:ObjectId,middle:ObjectId,last:ObjectId) {
    let zero = NodeTotals {entries:0,logical_bytes:0,quota_bytes:0};
    let pointers = vec![
        Child {lower_bound:vec![10u8],object:first,level:0,totals:zero},
        Child {lower_bound:vec![20u8],object:middle,level:0,totals:zero},
        Child {lower_bound:vec![30u8],object:last,level:0,totals:zero},
    ];
    let ghost input = pointers@;
    let key = [query];
    proof {
        reveal_with_fuel(crate::encoding::below,2);
        assert(crate::encoding::below(input[0].lower_bound@,input[1].lower_bound@));
        assert(crate::encoding::below(input[1].lower_bound@,input[2].lower_bound@));
        assert(branch::ordered(input,3));
        reveal_with_fuel(branch::counts,4);
    }
    let Ok(page) = branch::finish(0,0,1,pointers,zero) else {unreached()};
    let i = point::child(&page.children,&key);
    let selected = &page.children[i];
    proof {
        reveal_with_fuel(crate::encoding::below,2);
        assert(i == if query < 20 {0int} else if query < 30 {1int} else {2int});
        assert(selected.object == if query < 20 {first} else if query < 30 {middle} else {last});
    }
    let data = vec![
        Row {key:vec![10u8],value:ValueSlot::Inline(vec![11u8])},
        Row {key:vec![20u8],value:ValueSlot::Spilled {object:middle,length:12345}},
        Row {key:vec![30u8],value:ValueSlot::Inline(vec![33u8])},
    ];
    proof {
        reveal_with_fuel(crate::encoding::below,2);
        assert(crate::encoding::below(data@[0].key@,data@[1].key@));
        assert(crate::encoding::below(data@[1].key@,data@[2].key@));
        assert(leaf::ordered(data@,3));
    }
    let out = point::leaf(data,&key);
    assert(match query {
        10 => out matches Some(ValueSlot::Inline(d)) && d@ == seq![11u8],
        20 => out == Some(ValueSlot::Spilled {object:middle,length:12345}),
        30 => out matches Some(ValueSlot::Inline(d)) && d@ == seq![33u8],
        _ => out == None,
    });
}
}
