//! Admission under the currently resolved profile's keypair policy.

use vstd::prelude::*;

verus! {

pub(super) fn enabled_keys<T>(enabled: bool, keypair: bool, keys: &[T]) -> (result: Option<&[T]>)
    ensures result == if enabled && keypair { Some(keys) } else { None },
{
    if enabled && keypair { Some(keys) } else { None }
}

}
