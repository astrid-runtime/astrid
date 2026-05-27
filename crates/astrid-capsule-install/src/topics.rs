//! Bake topic schema declarations inline into `meta.json`.
//!
//! At install time, each `[[topic]]` entry's schema is resolved from
//! one of two sources (in priority order):
//!
//! 1. **`wit_type`** — references a WIT record name in the capsule's
//!    `wit/` directory. The record is parsed from WIT and converted
//!    to JSON Schema, with `///` doc comments becoming
//!    `"description"` fields.
//! 2. **`schema`** — path to a JSON Schema file relative to the
//!    capsule's source directory.
//!
//! If neither is set, the topic is baked without a schema. The
//! resolved schemas live in `meta.json` at runtime, so the kernel
//! never needs to re-parse WIT or re-read schema files to dispatch a
//! topic — every consumer reads the inlined copy.

use std::path::Path;

use anyhow::{Context, bail};
use astrid_capsule::manifest::CapsuleManifest;

use crate::meta::BakedTopic;

/// 1 MB cap — prevents an oversized schema from bloating `meta.json`.
const MAX_SCHEMA_FILE_SIZE: u64 = 1024 * 1024;

/// Read topic declarations from the manifest and bake schema content inline.
///
/// `source_dir` is the capsule source on disk — schema paths and the
/// `wit/` directory are both resolved against it. The function reads
/// only; it never writes.
pub fn bake_topics(
    manifest: &CapsuleManifest,
    source_dir: &Path,
) -> anyhow::Result<Vec<BakedTopic>> {
    let mut baked = Vec::with_capacity(manifest.topics.len());

    let canonical_source_dir = std::fs::canonicalize(source_dir).with_context(|| {
        format!(
            "failed to canonicalize capsule source dir: {}",
            source_dir.display()
        )
    })?;

    // Lazily parse WIT — only if at least one topic references wit_type.
    let wit_schemas = if manifest.topics.iter().any(|t| t.wit_type.is_some()) {
        Some(
            astrid_build::wit_schema::WitSchemas::from_dir(&source_dir.join("wit")).with_context(
                || {
                    format!(
                        "failed to parse WIT files in {}",
                        source_dir.join("wit").display()
                    )
                },
            )?,
        )
    } else {
        None
    };

    for topic in &manifest.topics {
        // wit_type takes precedence over schema file path.
        let schema = if let Some(ref wit_type) = topic.wit_type {
            let schemas = wit_schemas
                .as_ref()
                .expect("wit_schemas is Some when any topic has wit_type");
            let json_schema = schemas.get(wit_type).ok_or_else(|| {
                anyhow::anyhow!(
                    "[[topic]] '{}' references wit_type '{}' but no WIT record with \
                     that name was found in {}/wit/",
                    topic.name,
                    wit_type,
                    source_dir.display()
                )
            })?;
            Some(json_schema.clone())
        } else if let Some(ref schema_path) = topic.schema {
            Some(read_schema_file(
                &topic.name,
                schema_path,
                source_dir,
                &canonical_source_dir,
            )?)
        } else {
            None
        };

        baked.push(BakedTopic {
            name: topic.name.clone(),
            direction: topic.direction,
            description: topic.description.clone(),
            schema,
        });
    }

    Ok(baked)
}

/// Read and validate a JSON Schema file for a topic declaration.
///
/// Verifies the path stays within the capsule source directory,
/// enforces a size limit, and parses the content as JSON.
fn read_schema_file(
    topic_name: &str,
    schema_path: &Path,
    source_dir: &Path,
    canonical_source_dir: &Path,
) -> anyhow::Result<serde_json::Value> {
    let full_path = source_dir.join(schema_path);

    let canonical = std::fs::canonicalize(&full_path).with_context(|| {
        format!(
            "[[topic]] '{}' schema file not found: '{}'",
            topic_name,
            full_path.display()
        )
    })?;
    if !canonical.starts_with(canonical_source_dir) {
        bail!(
            "[[topic]] '{}' schema path '{}' resolves outside the capsule directory",
            topic_name,
            schema_path.display()
        );
    }

    let file = std::fs::File::open(&canonical).with_context(|| {
        format!(
            "failed to open schema file for topic '{}': '{}'",
            topic_name,
            canonical.display()
        )
    })?;
    let file_len = file
        .metadata()
        .with_context(|| format!("failed to stat schema file: {}", canonical.display()))?
        .len();
    if file_len > MAX_SCHEMA_FILE_SIZE {
        bail!(
            "[[topic]] '{}' schema file '{}' is {} bytes, exceeding the {} byte limit",
            topic_name,
            schema_path.display(),
            file_len,
            MAX_SCHEMA_FILE_SIZE
        );
    }
    let capacity = usize::try_from(file_len)
        .with_context(|| format!("schema file size {file_len} exceeds platform usize limit"))?;
    let mut content = String::with_capacity(capacity);
    std::io::Read::read_to_string(
        &mut std::io::Read::take(file, MAX_SCHEMA_FILE_SIZE + 1),
        &mut content,
    )
    .with_context(|| {
        format!(
            "failed to read schema file for topic '{}': '{}'",
            topic_name,
            canonical.display()
        )
    })?;
    if content.len() as u64 > MAX_SCHEMA_FILE_SIZE {
        bail!(
            "[[topic]] '{}' schema file '{}' exceeded the {} byte limit during read",
            topic_name,
            schema_path.display(),
            MAX_SCHEMA_FILE_SIZE
        );
    }
    serde_json::from_str(&content).with_context(|| {
        format!(
            "[[topic]] '{}' schema file '{}' contains invalid JSON",
            topic_name,
            schema_path.display()
        )
    })
}
