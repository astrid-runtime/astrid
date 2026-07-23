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

fn musl_targets() -> Vec<TargetMetadata> {
    MUSL_TARGETS
        .iter()
        .enumerate()
        .map(|(index, triple)| {
            let ordinal = index.checked_add(30).expect("target ordinal fits usize");
            let checksum_ordinal = index
                .checked_add(40)
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

fn musl_extension(pointer: &ChannelPointer, legacy_manifest: &[u8]) -> Vec<u8> {
    toml::to_string(&MuslReleaseExtension {
        schema_version: 1,
        kind: "astrid-release-musl-extension".to_owned(),
        product: PRODUCT.to_owned(),
        repository: REPOSITORY.to_owned(),
        version: pointer.release.version.clone(),
        tag: pointer.release.tag.clone(),
        source_commit: pointer.release.source_commit.clone(),
        release_workflow_identity: pointer.release.release_workflow_identity.clone(),
        legacy_release: LegacyReleaseBinding {
            metadata_asset: pointer.release.metadata_asset.clone(),
            metadata_blake3: blake3::hash(legacy_manifest).to_hex().to_string(),
        },
        targets: musl_targets(),
    })
    .unwrap()
    .into_bytes()
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

struct RecordingMuslMetadataSource {
    extension: Vec<u8>,
    bundle: Vec<u8>,
    downloads: std::sync::Mutex<Vec<String>>,
    authentications: std::sync::atomic::AtomicUsize,
}

impl MuslMetadataSource for RecordingMuslMetadataSource {
    async fn download(&self, url: &str, _limit: usize, _label: &str) -> anyhow::Result<Vec<u8>> {
        self.downloads.lock().unwrap().push(url.to_owned());
        if url.ends_with(".sigstore.json") {
            Ok(self.bundle.clone())
        } else {
            Ok(self.extension.clone())
        }
    }

    fn authenticate(
        &self,
        bytes: Vec<u8>,
        bundle: &[u8],
        version: &str,
    ) -> anyhow::Result<Vec<u8>> {
        assert_eq!(bundle, self.bundle);
        assert_eq!(version, VERSION);
        self.authentications
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(bytes)
    }
}

#[tokio::test]
async fn target_resolver_fetches_and_authenticates_extension_only_for_musl() {
    let legacy = release_manifest();
    let value = pointer(UpdateChannel::Stable, 1);
    let extension = musl_extension(&value, &legacy);
    let metadata_name = musl_metadata_asset(VERSION);
    let metadata_url = format!("https://release.example/{metadata_name}");
    let bundle_url = format!("{metadata_url}.sigstore.json");
    let release = serde_json::json!({
        "assets": [
            {
                "name": metadata_name.clone(),
                "browser_download_url": metadata_url.clone()
            },
            {
                "name": format!("{metadata_name}.sigstore.json"),
                "browser_download_url": bundle_url.clone()
            }
        ]
    });
    let source = RecordingMuslMetadataSource {
        extension,
        bundle: b"authenticated-bundle".to_vec(),
        downloads: std::sync::Mutex::new(Vec::new()),
        authentications: std::sync::atomic::AtomicUsize::new(0),
    };

    let gnu_target = TARGETS[1];
    assert_eq!(
        resolve_target_blake3(
            &source,
            &serde_json::Value::Null,
            &legacy,
            &value,
            gnu_target
        )
        .await
        .unwrap(),
        value.target(gnu_target).unwrap().blake3
    );
    assert!(source.downloads.lock().unwrap().is_empty());
    assert_eq!(
        source
            .authentications
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );

    let musl_target = MUSL_TARGETS[0];
    assert_eq!(
        resolve_target_blake3(&source, &release, &legacy, &value, musl_target)
            .await
            .unwrap(),
        musl_targets()[0].blake3
    );
    assert_eq!(
        *source.downloads.lock().unwrap(),
        vec![metadata_url, bundle_url]
    );
    assert_eq!(
        source
            .authentications
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[test]
fn legacy_channel_and_release_documents_stay_exactly_four_target_only() {
    let mut value = pointer(UpdateChannel::Stable, 1);
    value.targets.extend(musl_targets());
    assert!(
        parse_channel(&encoded(&value), UpdateChannel::Stable, validation_time())
            .unwrap_err()
            .to_string()
            .contains("exactly 4 targets")
    );

    let pointer = pointer(UpdateChannel::Stable, 1);
    let mut manifest: ReleaseManifest =
        toml::from_str(std::str::from_utf8(&release_manifest()).unwrap()).unwrap();
    manifest.targets.extend(musl_targets());
    let bytes = toml::to_string(&manifest).unwrap();
    let mut rebound = pointer.clone();
    rebound.release.metadata_blake3 = blake3::hash(bytes.as_bytes()).to_hex().to_string();
    assert!(
        verify_release_manifest(bytes.as_bytes(), &rebound)
            .unwrap_err()
            .to_string()
            .contains("exactly 4 targets")
    );
}

#[test]
fn musl_extension_accepts_exactly_two_targets_and_selects_requested_digest() {
    let legacy = release_manifest();
    let value = pointer(UpdateChannel::Stable, 1);
    let extension = musl_extension(&value, &legacy);
    for target in musl_targets() {
        assert_eq!(
            verify_musl_extension(&extension, &legacy, &value, &target.triple).unwrap(),
            target.blake3
        );
    }
}

#[test]
fn musl_extension_rejects_missing_duplicate_and_unexpected_targets() {
    let legacy = release_manifest();
    let value = pointer(UpdateChannel::Stable, 1);
    let extension = musl_extension(&value, &legacy);
    let parsed: MuslReleaseExtension =
        toml::from_str(std::str::from_utf8(&extension).unwrap()).unwrap();

    let mut missing = parsed.clone();
    missing.targets.pop();
    assert!(
        verify_musl_extension(
            toml::to_string(&missing).unwrap().as_bytes(),
            &legacy,
            &value,
            MUSL_TARGETS[0]
        )
        .unwrap_err()
        .to_string()
        .contains("exactly 2 targets")
    );

    let mut duplicate = parsed.clone();
    duplicate.targets[1] = duplicate.targets[0].clone();
    assert!(
        verify_musl_extension(
            toml::to_string(&duplicate).unwrap().as_bytes(),
            &legacy,
            &value,
            MUSL_TARGETS[0]
        )
        .unwrap_err()
        .to_string()
        .contains("target set")
    );

    let mut unexpected = parsed;
    unexpected.targets[0].triple = TARGETS[0].to_owned();
    assert!(
        verify_musl_extension(
            toml::to_string(&unexpected).unwrap().as_bytes(),
            &legacy,
            &value,
            MUSL_TARGETS[1]
        )
        .unwrap_err()
        .to_string()
        .contains("target set")
    );
}

#[test]
fn musl_extension_rejects_release_identity_and_legacy_binding_mismatches() {
    let legacy = release_manifest();
    let value = pointer(UpdateChannel::Stable, 1);
    let extension = musl_extension(&value, &legacy);
    let parsed: MuslReleaseExtension =
        toml::from_str(std::str::from_utf8(&extension).unwrap()).unwrap();

    let mut wrong_source = parsed.clone();
    wrong_source.source_commit = "cccccccccccccccccccccccccccccccccccccccc".to_owned();
    assert!(
        verify_musl_extension(
            toml::to_string(&wrong_source).unwrap().as_bytes(),
            &legacy,
            &value,
            MUSL_TARGETS[0]
        )
        .unwrap_err()
        .to_string()
        .contains("does not match")
    );

    let mut wrong_identity = parsed.clone();
    wrong_identity.release_workflow_identity =
        "https://github.com/astrid-runtime/astrid/.github/workflows/release.yml@refs/heads/main"
            .to_owned();
    assert!(
        verify_musl_extension(
            toml::to_string(&wrong_identity).unwrap().as_bytes(),
            &legacy,
            &value,
            MUSL_TARGETS[0]
        )
        .unwrap_err()
        .to_string()
        .contains("does not match")
    );

    let mut wrong_digest = parsed;
    wrong_digest.legacy_release.metadata_blake3 = "f".repeat(64);
    assert!(
        verify_musl_extension(
            toml::to_string(&wrong_digest).unwrap().as_bytes(),
            &legacy,
            &value,
            MUSL_TARGETS[0]
        )
        .unwrap_err()
        .to_string()
        .contains("does not bind")
    );
}
