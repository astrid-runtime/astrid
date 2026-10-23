use super::*;

fn inventory(count: usize) -> Vec<ContentEntry> {
    (0..count)
        .map(|index| {
            ContentEntry::new(
                ContentName::new(format!(
                    "etc/agent-{index:05}/{}/{}",
                    "name".repeat(50),
                    "name".repeat(50)
                ))
                .unwrap(),
                ObjectId::new([0x47; 32]),
                7,
            )
        })
        .collect()
}

#[test]
fn ten_thousand_entry_receipt_exceeds_old_cap_and_authenticates_every_identity() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let catalog = inventory(10_000);
    let entries = catalog
        .iter()
        .rev()
        .map(|entry| ActiveProjectionEntry {
            name: entry.name().clone(),
            file: entry.file(),
            logical_bytes: entry.logical_bytes(),
        })
        .collect::<Vec<_>>();
    let bytes = encode(&home, ReceiptPhase::Active, &entries).unwrap();
    assert!(bytes.len() as u64 > RECEIPT_FRAMING_BYTES);
    assert!(
        bytes.len() as u64 <= receipt_size_bound(catalog.iter().map(ContentEntry::name)).unwrap()
    );
    let receipt = decode_receipt(home.root(), &bytes, catalog.clone())
        .unwrap()
        .unwrap();
    for entry in &catalog {
        assert!(receipt.contains_inventory_name(entry.name().as_str()));
    }
    assert!(!receipt.contains_inventory_name("etc/missing"));
    // Surviving input is deliberately unordered, and a genuine absence must
    // still produce exactly one removal from the authenticated inventory.
    let surviving = catalog
        .iter()
        .rev()
        .skip(1)
        .map(|entry| entry.name().clone())
        .collect::<Vec<_>>();
    assert_eq!(
        removals(&receipt, &surviving).unwrap(),
        vec![catalog.last().unwrap().name().clone()]
    );
    let mut corrupt: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    corrupt["entries"][4]["file"] = serde_json::Value::String("00".repeat(32));
    assert!(decode_receipt(home.root(), &serde_json::to_vec(&corrupt).unwrap(), catalog).is_err());
}

#[test]
fn receipt_cannot_amplify_inventory_with_duplicate_names() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let catalog = inventory(2);
    let entry = ActiveProjectionEntry {
        name: catalog[0].name().clone(),
        file: catalog[0].file(),
        logical_bytes: 7,
    };
    let bytes = encode(&home, ReceiptPhase::Active, &[entry.clone(), entry]).unwrap();
    assert!(
        decode_receipt(home.root(), &bytes, catalog)
            .unwrap_err()
            .to_string()
            .contains("repeats")
    );
}

#[test]
fn receipt_allowance_scales_only_with_authenticated_catalog_names() {
    let catalog = inventory(10_000);
    let bound = receipt_size_bound(catalog.iter().map(ContentEntry::name)).unwrap();
    assert!(bound > RECEIPT_FRAMING_BYTES);
    assert_eq!(
        receipt_size_bound(std::iter::empty()).unwrap(),
        RECEIPT_FRAMING_BYTES
    );
    assert_eq!(
        bound,
        RECEIPT_FRAMING_BYTES
            + catalog
                .iter()
                .map(|entry| 128 + 6 * entry.name().as_str().len() as u64)
                .sum::<u64>()
    );
}

#[test]
fn oversized_receipt_is_rejected_before_json_decoding() {
    let bytes = vec![
        b' ';
        usize::try_from(RECEIPT_FRAMING_BYTES)
            .unwrap()
            .checked_add(1)
            .unwrap()
    ];
    let error = decode_receipt(Path::new("receipt"), &bytes, Vec::new()).unwrap_err();
    assert!(error.to_string().contains("exceeds catalog-derived"));
}
