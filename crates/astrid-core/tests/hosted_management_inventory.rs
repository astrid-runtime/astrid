//! Keep the hosted contract's management inventory in step with both wire decoders.
use std::{collections::BTreeSet, fmt};

use astrid_core::kernel_api::{AdminRequestKind, KernelRequest};
use serde::de::{self, DeserializeOwned, value::MapDeserializer};

#[derive(Debug, thiserror::Error)]
enum DecodeError {
    #[error("supported management methods: {0:?}")]
    Methods(&'static [&'static str]),
    #[error("{0}")]
    Unexpected(String),
}

impl de::Error for DecodeError {
    fn custom<T: fmt::Display>(message: T) -> Self {
        Self::Unexpected(message.to_string())
    }

    fn unknown_variant(_: &str, expected: &'static [&'static str]) -> Self {
        Self::Methods(expected)
    }
}

// Serde's adjacent-tag decoder reports its complete method set when decoding
// an unknown tag. Capture that structured set before any payload is decoded.
fn wire_methods<T: DeserializeOwned>() -> BTreeSet<&'static str> {
    let envelope = [("method", "__inventory_probe__")];
    let decoder = MapDeserializer::<_, DecodeError>::new(envelope.into_iter());
    match T::deserialize(decoder) {
        Err(DecodeError::Methods(names)) => names.iter().copied().collect(),
        Err(other) => panic!("could not enumerate the production method tag: {other}"),
        Ok(_) => panic!("production decoder accepted an unknown management method"),
    }
}

#[test]
fn each_management_method_has_a_target_obligation_on_its_subscriber() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../verification/hosted-security-contract.md");
    let contract = std::fs::read_to_string(path).unwrap();
    let (_, table) = contract
        .split_once("| Subscriber | Effect family |")
        .unwrap();
    let mut kernel = BTreeSet::new();
    let mut admin = BTreeSet::new();
    for row in table.lines().skip(2).take_while(|row| row.starts_with('|')) {
        let columns: Vec<_> = row.trim_matches('|').split('|').map(str::trim).collect();
        let [subscriber, family, methods, target] = columns.as_slice() else {
            panic!("incomplete inventory row: {row}");
        };
        assert!(!family.is_empty() && !target.is_empty(), "{row}");
        let entries = match *subscriber {
            "Kernel" => &mut kernel,
            "Admin" => &mut admin,
            _ => panic!("unknown subscriber in {row}"),
        };
        for method in methods.split(", ") {
            let name = method
                .strip_prefix('`')
                .and_then(|s| s.strip_suffix('`'))
                .unwrap();
            assert!(entries.insert(name), "duplicate {subscriber} method {name}");
        }
    }
    assert_eq!(kernel, wire_methods::<KernelRequest>());
    assert_eq!(admin, wire_methods::<AdminRequestKind>());
}
