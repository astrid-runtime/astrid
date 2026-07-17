use super::*;

const VERSION: &str = "1.2.3";
const COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONTRACTS_COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn targets() -> Vec<TargetMetadata> {
    TARGETS
        .iter()
        .enumerate()
        .map(|(index, triple)| {
            let ordinal = index.checked_add(1).expect("target ordinal fits usize");
            let checksum_ordinal = index
                .checked_add(10)
                .expect("target checksum ordinal fits usize");
            let asset = format!("astrid-{VERSION}-{triple}.tar.gz");
            TargetMetadata {
                triple: (*triple).to_owned(),
                asset: asset.clone(),
                size: i64::try_from(ordinal).expect("target ordinal fits i64"),
                blake3: format!("{ordinal:064x}"),
                sha256: format!("{checksum_ordinal:064x}"),
                sigstore_bundle: format!("{asset}.sigstore.json"),
            }
        })
        .collect()
}

fn release_manifest() -> Vec<u8> {
    toml::to_string(&ReleaseManifest {
        schema_version: 1,
        kind: "astrid-release".to_owned(),
        product: PRODUCT.to_owned(),
        repository: REPOSITORY.to_owned(),
        version: VERSION.to_owned(),
        tag: format!("v{VERSION}"),
        source_commit: COMMIT.to_owned(),
        release_workflow_identity: format!(
            "https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{VERSION}"
        ),
        contracts: ContractsMetadata {
            repository: CONTRACTS_REPOSITORY.to_owned(),
            commit: CONTRACTS_COMMIT.to_owned(),
        },
        targets: targets(),
    })
    .unwrap()
    .into_bytes()
}

fn pointer(channel: UpdateChannel, generation: i64) -> ChannelPointer {
    let manifest = release_manifest();
    let expires_at = match channel {
        UpdateChannel::Stable => "2026-08-15T00:00:00Z",
        UpdateChannel::Dev => "2026-07-23T00:00:00Z",
        UpdateChannel::Nightly => "2026-07-18T00:00:00Z",
    };
    ChannelPointer {
        schema_version: 1,
        kind: "astrid-channel".to_owned(),
        product: PRODUCT.to_owned(),
        repository: REPOSITORY.to_owned(),
        channel: channel.as_str().to_owned(),
        generation,
        published_at: "2026-07-16T00:00:00Z".to_owned(),
        expires_at: expires_at.to_owned(),
        release: ChannelRelease {
            version: VERSION.to_owned(),
            tag: format!("v{VERSION}"),
            source_commit: COMMIT.to_owned(),
            metadata_asset: format!("astrid-{VERSION}-release.toml"),
            metadata_blake3: blake3::hash(&manifest).to_hex().to_string(),
            release_workflow_identity: format!(
                "https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{VERSION}"
            ),
        },
        targets: targets(),
    }
}

fn nightly_pointer(generation: i64) -> ChannelPointer {
    let version = format!("1.2.4-nightly.20260716.g{COMMIT}");
    let mut value = pointer(UpdateChannel::Nightly, generation);
    value.release.version.clone_from(&version);
    value.release.tag = format!("v{version}");
    value.release.metadata_asset = format!("astrid-{version}-release.toml");
    value.release.release_workflow_identity = format!(
        "https://github.com/{REPOSITORY}/.github/workflows/release.yml@refs/tags/v{version}"
    );
    for target in &mut value.targets {
        target.asset = format!("astrid-{version}-{}.tar.gz", target.triple);
        target.sigstore_bundle = format!("{}.sigstore.json", target.asset);
    }
    value
}

fn encoded(pointer: &ChannelPointer) -> Vec<u8> {
    toml::to_string(pointer).unwrap().into_bytes()
}

fn validation_time() -> DateTime<Utc> {
    "2026-07-17T00:00:00Z".parse().unwrap()
}

#[test]
fn all_channels_parse_with_strict_identity_and_expiry() {
    for channel in [UpdateChannel::Stable, UpdateChannel::Dev] {
        let value = pointer(channel, 1);
        assert_eq!(
            parse_channel(&encoded(&value), channel, validation_time())
                .unwrap()
                .version(),
            VERSION
        );
    }
    let nightly = nightly_pointer(1);
    assert_eq!(
        parse_channel(
            &encoded(&nightly),
            UpdateChannel::Nightly,
            validation_time()
        )
        .unwrap()
        .version(),
        format!("1.2.4-nightly.20260716.g{COMMIT}")
    );
}

#[test]
fn channel_release_classes_do_not_cross() {
    let mut nightly_as_dev = nightly_pointer(1);
    nightly_as_dev.channel = "dev".to_owned();
    nightly_as_dev.expires_at = "2026-07-23T00:00:00Z".to_owned();
    assert!(
        parse_channel(
            &encoded(&nightly_as_dev),
            UpdateChannel::Dev,
            validation_time()
        )
        .unwrap_err()
        .to_string()
        .contains("canonical releases")
    );
    assert!(
        parse_channel(
            &encoded(&pointer(UpdateChannel::Nightly, 1)),
            UpdateChannel::Nightly,
            validation_time()
        )
        .unwrap_err()
        .to_string()
        .contains("exact nightly")
    );
    let mut mismatch = nightly_pointer(1);
    mismatch.release.source_commit = "cccccccccccccccccccccccccccccccccccccccc".to_owned();
    assert!(
        parse_channel(
            &encoded(&mismatch),
            UpdateChannel::Nightly,
            validation_time()
        )
        .unwrap_err()
        .to_string()
        .contains("embed its source commit")
    );
    let mut impossible = nightly_pointer(1);
    impossible.release.version = impossible.release.version.replace("20260716", "20260230");
    impossible.release.tag = format!("v{}", impossible.release.version);
    assert!(
        parse_channel(
            &encoded(&impossible),
            UpdateChannel::Nightly,
            validation_time()
        )
        .unwrap_err()
        .to_string()
        .contains("exact nightly")
    );
}

#[test]
fn type_confusion_unknown_fields_and_expiry_fail_closed() {
    let value = pointer(UpdateChannel::Stable, 1);
    let text = String::from_utf8(encoded(&value)).unwrap();
    let wrong_type = text.replacen("generation = 1", "generation = true", 1);
    assert!(
        parse_channel(
            wrong_type.as_bytes(),
            UpdateChannel::Stable,
            validation_time()
        )
        .is_err()
    );
    let unknown = format!("{text}\nlatest = true\n");
    assert!(parse_channel(unknown.as_bytes(), UpdateChannel::Stable, validation_time()).is_err());
    assert!(
        parse_channel(
            text.as_bytes(),
            UpdateChannel::Stable,
            "2026-08-16T00:00:00Z".parse().unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("expired")
    );

    let mut too_long = pointer(UpdateChannel::Nightly, 1);
    too_long.expires_at = "2026-07-19T00:00:01Z".to_owned();
    assert!(
        parse_channel(
            &encoded(&too_long),
            UpdateChannel::Nightly,
            validation_time()
        )
        .unwrap_err()
        .to_string()
        .contains("lifetime exceeds")
    );
    assert!(
        parse_channel(
            &encoded(&value),
            UpdateChannel::Stable,
            "2026-07-15T23:54:59Z".parse().unwrap()
        )
        .unwrap_err()
        .to_string()
        .contains("future")
    );
}

#[test]
fn workflow_identity_and_metadata_digest_are_exact() {
    let mut wrong_identity = pointer(UpdateChannel::Stable, 1);
    wrong_identity.release.release_workflow_identity =
        "https://github.com/astrid-runtime/astrid/.github/workflows/release.yml@refs/heads/main"
            .to_owned();
    assert!(
        parse_channel(
            &encoded(&wrong_identity),
            UpdateChannel::Stable,
            validation_time()
        )
        .unwrap_err()
        .to_string()
        .contains("workflow identity")
    );

    let value = pointer(UpdateChannel::Stable, 1);
    let mut manifest = release_manifest();
    verify_release_manifest(&manifest, &value).unwrap();
    manifest.push(b'\n');
    assert!(
        verify_release_manifest(&manifest, &value)
            .unwrap_err()
            .to_string()
            .contains("BLAKE3 digest")
    );
}

#[test]
fn generation_rollback_and_same_generation_equivocation_are_rejected() {
    let previous = pointer(UpdateChannel::Stable, 5);
    let previous_bytes = encoded(&previous);
    let rollback = pointer(UpdateChannel::Stable, 4);
    assert!(
        enforce_continuity_values(&rollback, &encoded(&rollback), &previous, &previous_bytes)
            .unwrap_err()
            .to_string()
            .contains("rollback")
    );
    let mut equivocation = previous.clone();
    equivocation.expires_at = "2026-08-14T00:00:00Z".to_owned();
    assert!(
        enforce_continuity_values(
            &equivocation,
            &encoded(&equivocation),
            &previous,
            &previous_bytes
        )
        .unwrap_err()
        .to_string()
        .contains("equivocation")
    );
    enforce_continuity_values(&previous, &previous_bytes, &previous, &previous_bytes).unwrap();
    let advanced = pointer(UpdateChannel::Stable, 6);
    enforce_continuity_values(&advanced, &encoded(&advanced), &previous, &previous_bytes).unwrap();
}
