//! Lowercase-hex serde forms for fixed-size byte arrays in stored records.

use serde::{Deserialize, Deserializer, Serializer};

fn decode<const N: usize, E: serde::de::Error>(text: &str) -> Result<[u8; N], E> {
    let bytes = hex::decode(text).map_err(E::custom)?;
    <[u8; N]>::try_from(bytes)
        .map_err(|bytes| E::custom(format!("expected {N} bytes, got {}", bytes.len())))
}

/// `[u8; N]` as a hex string.
pub(crate) mod array {
    use super::{Deserialize, Deserializer, Serializer, decode};

    pub(crate) fn serialize<S: Serializer, const N: usize>(
        bytes: &[u8; N],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<[u8; N], D::Error> {
        let text = String::deserialize(deserializer)?;
        decode(&text)
    }
}

/// `Option<[u8; N]>` as an optional hex string.
pub(crate) mod option_array {
    use super::{Deserialize, Deserializer, Serializer, decode};

    #[expect(
        clippy::ref_option,
        reason = "serde `with` modules receive a reference to the field"
    )]
    pub(crate) fn serialize<S: Serializer, const N: usize>(
        bytes: &Option<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>, const N: usize>(
        deserializer: D,
    ) -> Result<Option<[u8; N]>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| decode(&text))
            .transpose()
    }
}
