//! Reproducible density and construction-cost sweep for physical-map layouts.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use astrid_storage_model::{
    CanonicalPhysicalMap, PhysicalIdentity, PhysicalMapDomain, PhysicalMapKey,
};

const FRAME_AND_WRAPPER_BYTES: usize = 101;
const VALUE_BYTES: usize = 199;

#[derive(Clone, Copy)]
struct Blake3Identity;

impl PhysicalIdentity for Blake3Identity {
    fn identify(&self, context: &'static str, material: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(context);
        hasher.update(material);
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Copy)]
enum Construction {
    Legacy,
    Dense,
}

impl Construction {
    const fn name(self) -> &'static str {
        match self {
            Self::Legacy => "legacy-binary",
            Self::Dense => "dense-radix-1",
        }
    }

    fn build(self, entries: Vec<(PhysicalMapKey, Vec<u8>)>) -> CanonicalPhysicalMap {
        match self {
            Self::Legacy => CanonicalPhysicalMap::build(
                &Blake3Identity,
                PhysicalMapDomain::Representation,
                entries,
            ),
            Self::Dense => CanonicalPhysicalMap::build_dense(
                &Blake3Identity,
                PhysicalMapDomain::Representation,
                entries,
            ),
        }
        .expect("sweep entries must form a valid physical map")
    }
}

fn main() {
    println!("scenario,construction,entries,nodes,authoritative_bytes,build_us");
    scenario("sparse", random_entries(8));
    scenario("full", random_entries(65_536));
    scenario("adversarial-prefix", adversarial_entries(4_096));
    incremental("incremental", random_entries(6_748), random_entry(6_748));
}

fn scenario(name: &str, entries: Vec<(PhysicalMapKey, Vec<u8>)>) {
    for construction in [Construction::Legacy, Construction::Dense] {
        let started = Instant::now();
        let map = construction.build(entries.clone());
        print_measurement(name, construction, &map, started.elapsed());
    }
}

fn incremental(
    name: &str,
    mut entries: Vec<(PhysicalMapKey, Vec<u8>)>,
    addition: (PhysicalMapKey, Vec<u8>),
) {
    for construction in [Construction::Legacy, Construction::Dense] {
        let mut after = construction.build(entries.clone());
        let prior = after.nodes().keys().copied().collect::<BTreeSet<_>>();
        let started = Instant::now();
        assert!(
            after
                .insert(&Blake3Identity, addition.0, addition.1.clone())
                .expect("point insertion must succeed")
        );
        let elapsed = started.elapsed();
        entries.push(addition.clone());
        let rebuilt = construction.build(entries.clone());
        assert_eq!(after.root(), rebuilt.root());
        let appended = after
            .nodes()
            .iter()
            .filter(|(id, _)| !prior.contains(id))
            .map(|(_, node)| node_bytes(node.encode().expect("node must encode")))
            .sum::<usize>();
        println!(
            "{},{},{},{},{},{}",
            name,
            construction.name(),
            after.entry_count(),
            after
                .nodes()
                .keys()
                .filter(|id| !prior.contains(id))
                .count(),
            appended,
            micros(elapsed),
        );
        entries.pop();
    }
}

fn print_measurement(
    name: &str,
    construction: Construction,
    map: &CanonicalPhysicalMap,
    elapsed: Duration,
) {
    let bytes = map
        .nodes()
        .values()
        .map(|node| node_bytes(node.encode().expect("node must encode")))
        .sum::<usize>();
    println!(
        "{},{},{},{},{},{}",
        name,
        construction.name(),
        map.entry_count(),
        map.nodes().len(),
        bytes,
        micros(elapsed),
    );
}

fn node_bytes(encoded: Vec<u8>) -> usize {
    FRAME_AND_WRAPPER_BYTES.saturating_add(encoded.len())
}

fn micros(elapsed: Duration) -> u128 {
    elapsed.as_micros()
}

fn random_entries(count: u32) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (0..count).map(random_entry).collect()
}

fn random_entry(index: u32) -> (PhysicalMapKey, Vec<u8>) {
    let digest = blake3::hash(&index.to_le_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"physical-map-sweep-value");
    hasher.update(&index.to_le_bytes());
    let mut value = hasher.finalize_xof();
    let mut bytes = vec![0; VALUE_BYTES];
    value.fill(&mut bytes);
    (PhysicalMapKey::new(*digest.as_bytes()), bytes)
}

fn adversarial_entries(count: u32) -> Vec<(PhysicalMapKey, Vec<u8>)> {
    (0..count)
        .map(|index| {
            let mut key = [0x55; 32];
            key[28..].copy_from_slice(&index.to_be_bytes());
            (PhysicalMapKey::new(key), vec![0xA5; VALUE_BYTES])
        })
        .collect()
}
