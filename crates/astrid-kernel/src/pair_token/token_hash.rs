use super::canonical_fingerprint;

/// Canonical durable token identifier used to derive record keys.
///
/// The public records retain their string-shaped wire field for compatibility;
/// storage operations cross this validated edge before constructing a key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct TokenHash(String);

impl TokenHash {
    pub(super) fn parse(value: &str) -> astrid_storage::StorageResult<Self> {
        if canonical_fingerprint(value).is_none() {
            return Err(astrid_storage::StorageError::Serialization(
                "pair-token record has a non-canonical token identifier".to_owned(),
            ));
        }
        Ok(Self(value.to_owned()))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}
