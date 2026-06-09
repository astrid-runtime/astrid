//! Compile-time tripwires for the rmcp resource-model shapes the Astrid resource
//! interface depends on.
//!
//! The forthcoming `astrid mcp serve` resource surface (Astrid bus contract
//! `astrid-bus:resource`) reshapes capsule-served resources onto rmcp's
//! `Resource` / `ResourceContents` / `Annotations` types. Those reshape
//! assumptions are pinned here so a future `rmcp` bump that changes a shape
//! **fails to compile** (or fails a test) rather than drifting silently:
//!
//! - `RawResource.size` is `Option<u32>` — the bus `resource-definition.size`
//!   mirrors it as `u32`, a lossless round-trip. A widening to `u64` must be a
//!   deliberate WIT change, not an invisible one.
//! - `ReadResourceResult` carries `contents: Vec<ResourceContents>` and has **no
//!   `is_error`** (unlike `CallToolResult`) — so a resource read failure must
//!   surface as a JSON-RPC error, never an is-error result.
//! - `ResourceContents` is the discriminated text/blob union the WIT `variant`
//!   maps onto 1:1 (the discriminant is the arm, never a MIME-type guess).
//! - `Annotations` carries exactly `audience` / `priority` / `last_modified`
//!   (`Option<DateTime<Utc>>`); the WIT carries an ISO-8601 string the shim
//!   parses, and any future annotation field rides `_meta`, not a new typed one.
//!
//! These guards exercise no Astrid code — they exist purely to break the build
//! when the dependency's surface moves out from under the contract.

#![cfg(test)]

use rmcp::model::{Annotations, RawResource, ReadResourceResult, ResourceContents, Role};

/// `RawResource`'s field set and the WIT-relevant field types. The struct
/// literal (rmcp marks `RawResource` intentionally exhaustive) breaks if a field
/// is added, removed, or renamed; the explicit type bindings break if `size` or
/// `icons` are retyped.
#[allow(dead_code)]
fn raw_resource_shape() {
    let r = RawResource {
        uri: String::new(),
        name: String::new(),
        title: None,
        description: None,
        mime_type: None,
        size: None,
        icons: None,
        meta: None,
    };
    let _: Option<u32> = r.size;
    let _: Option<Vec<rmcp::model::Icon>> = r.icons;
}

/// `ReadResourceResult` exposes `contents: Vec<ResourceContents>` and nothing the
/// read reshape needs beyond it. The binding breaks if `contents` is renamed or
/// retyped. (There is deliberately no `is_error` here to assert — its absence is
/// the point: read failures are JSON-RPC errors.)
#[allow(dead_code)]
fn read_resource_result_shape(r: &ReadResourceResult) {
    let _: &Vec<ResourceContents> = &r.contents;
}

/// `ResourceContents` is the exhaustive text/blob union. The match (no `_` arm)
/// breaks if a variant is added or removed; the field bindings break if a
/// variant's shape changes.
#[allow(dead_code)]
fn resource_contents_variants(c: ResourceContents) {
    match c {
        ResourceContents::TextResourceContents {
            uri,
            mime_type,
            text,
            meta,
        } => {
            let _: String = uri;
            let _: Option<String> = mime_type;
            let _: String = text;
            let _: Option<rmcp::model::Meta> = meta;
        },
        ResourceContents::BlobResourceContents {
            uri,
            mime_type,
            blob,
            meta,
        } => {
            let _: String = uri;
            let _: Option<String> = mime_type;
            let _: String = blob;
            let _: Option<rmcp::model::Meta> = meta;
        },
    }
}

/// `Annotations` carries exactly these three fields, with `last_modified` as
/// `Option<DateTime<Utc>>`. Breaks if rmcp retypes a field; a new annotation
/// field would not break this (by design — future fields ride `_meta`).
#[allow(dead_code)]
fn annotations_shape(a: &Annotations) {
    let _: &Option<Vec<Role>> = &a.audience;
    let _: &Option<f32> = &a.priority;
    let _: &Option<chrono::DateTime<chrono::Utc>> = &a.last_modified;
}

#[test]
fn raw_resource_size_round_trips_u32_max() {
    let r = RawResource {
        uri: "astrid://x".into(),
        name: "x".into(),
        title: None,
        description: None,
        mime_type: None,
        size: Some(u32::MAX),
        icons: None,
        meta: None,
    };
    let json = serde_json::to_value(&r).expect("serialize RawResource");
    assert_eq!(
        json["size"],
        u32::MAX,
        "RawResource.size must round-trip as u32"
    );
}

#[test]
fn resource_contents_text_is_untagged_text() {
    // The untagged enum discriminates by the present field, not a tag: a text
    // chunk serializes with `text` and no `blob`, and vice-versa. This is what
    // makes the WIT `variant` arm (never a MIME-type guess) the correct mapping.
    let text = ResourceContents::text("hello", "astrid://x");
    let jt = serde_json::to_value(&text).expect("serialize text contents");
    assert_eq!(jt["text"], "hello");
    assert!(
        jt.get("blob").is_none(),
        "text contents must not carry blob"
    );

    let blob = ResourceContents::blob("YmluYXJ5", "astrid://y");
    let jb = serde_json::to_value(&blob).expect("serialize blob contents");
    assert_eq!(jb["blob"], "YmluYXJ5");
    assert!(
        jb.get("text").is_none(),
        "blob contents must not carry text"
    );
}
