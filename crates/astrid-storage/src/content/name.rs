//! Validated UTF-8 keys in the owner-local content catalog.
use vstd::prelude::*;

verus! {
/// Canonical name of one principal-owned content value.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentName(String);

/// Failure to validate a principal content name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentNameError {
    /// The name was empty.
    Empty,
    /// The name contained a null byte.
    ContainsNull,
    /// Persisted name bytes were not valid UTF-8.
    InvalidUtf8,
}

impl ContentName {
    pub closed spec fn spelling(&self) -> Seq<char> { self.0@ }

    pub(crate) fn from_owned(value:String) -> (out:Result<Self,ContentNameError>)
        ensures match out {
            Ok(name) => name.spelling() == value@ && value@.len() != 0
                && !vstd::utf8::encode_utf8(value@).contains(0u8),
            Err(ContentNameError::Empty) => value@.len() == 0,
            Err(ContentNameError::ContainsNull) => value@.len() != 0 && vstd::utf8::encode_utf8(value@).contains(0u8),
            Err(ContentNameError::InvalidUtf8) => false,
        },
    {
        if value.is_empty() { return Err(ContentNameError::Empty); }
        let text = value.as_str();
        if text.as_bytes().contains(&0) { return Err(ContentNameError::ContainsNull); }
        Ok(Self(value))
    }

    /// Convert an already resolved filesystem spelling into the identical catalog key.
    pub(crate) fn from_path(path:&str) -> (out:Result<Self,ContentNameError>)
        ensures match out {
            Ok(name) => name.spelling() == path@ && path@.len() != 0
                && !vstd::utf8::encode_utf8(path@).contains(0u8),
            Err(ContentNameError::Empty) => path@.len() == 0,
            Err(ContentNameError::ContainsNull) => path@.len() != 0 && vstd::utf8::encode_utf8(path@).contains(0u8),
            Err(ContentNameError::InvalidUtf8) => false,
        },
    { Self::from_owned(path.to_owned()) }

    /// Borrow the canonical UTF-8 name.
    #[must_use]
    pub fn as_str(&self) -> (text:&str)
        ensures text@ == self.spelling(),
    { self.0.as_str() }

    /// Consume the name and return its UTF-8 representation.
    #[must_use]
    pub fn into_inner(self) -> (text:String)
        ensures text@ == self.spelling(),
    { self.0 }
}
}
