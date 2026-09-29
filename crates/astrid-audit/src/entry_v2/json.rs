//! Deterministic CBOR form of a JSON value committed in an entry.
//!
//! Only `AdminRequest.params` carries free-form JSON. The mapping is total and
//! unambiguous: JSON has no byte strings, so a number that is not a 64-bit
//! integer is carried as a byte string holding its literal decimal text.

use serde_json::{Number, Value};

use super::cbor::Cbor;

/// Map a JSON value onto the CBOR data model.
///
/// - `null`, `true`, `false` map to the CBOR simple values;
/// - an integer in `0..=u64::MAX` maps to an unsigned integer and a negative
///   integer in `i64` range to a negative integer;
/// - any other number maps to a byte string holding its JSON text;
/// - a string maps to a text string, an array to an array, and an object to
///   a map whose text keys are sorted by the deterministic key order.
pub(super) fn to_cbor(value: &Value) -> Cbor {
    match value {
        Value::Null => Cbor::Null,
        Value::Bool(value) => Cbor::Bool(*value),
        Value::Number(number) => number_to_cbor(number),
        Value::String(text) => Cbor::text(text.as_str()),
        Value::Array(items) => Cbor::Array(items.iter().map(to_cbor).collect()),
        Value::Object(map) => Cbor::Map(
            map.iter()
                .map(|(key, value)| (Cbor::text(key.as_str()), to_cbor(value)))
                .collect(),
        ),
    }
}

fn number_to_cbor(number: &Number) -> Cbor {
    if let Some(value) = number.as_u64() {
        return Cbor::Uint(value);
    }
    if let Some(value) = number.as_i64()
        && let Ok(magnitude) = u64::try_from(!value)
    {
        // CBOR stores a negative integer `v` as `-1 - v`; `!v` is exactly
        // that for two's-complement `v < 0`.
        return Cbor::Nint(magnitude);
    }
    Cbor::bytes(number.to_string().into_bytes())
}
