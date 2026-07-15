use sigstore_verify::trust_root::{SigstoreInstance, TrustedRoot};

use super::*;

const LEGACY_IDENTITY: &str =
    "https://github.com/unicity-astrid/astrid/.github/workflows/release.yml@refs/tags/v0.9.4";
const FIXTURE_BYTES: &[u8] =
    include_bytes!("../../tests/fixtures/self_update/v0.9.4/SHA256SUMS.txt");
const FIXTURE_BUNDLE: &[u8] =
    include_bytes!("../../tests/fixtures/self_update/v0.9.4/SHA256SUMS.txt.sigstore.json");

fn fixture_root() -> TrustedRoot {
    TrustedRoot::from_embedded(SigstoreInstance::PublicGood)
        .expect("embedded public-good root parses")
}

fn verify_fixture(identity: &str, issuer: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let bundle = parse_bundle(FIXTURE_BUNDLE)?;
    let policy = VerificationPolicy::default()
        .require_identity(identity)
        .require_issuer(issuer);
    verify(bytes, &bundle, &policy, &fixture_root())
        .map(|_| ())
        .context("fixture verification failed")
}

#[test]
fn release_identity_is_exact_and_tag_bound() {
    assert_eq!(
        release_identity("1.2.3"),
        "https://github.com/astrid-runtime/astrid/.github/workflows/release.yml@refs/tags/v1.2.3"
    );
}

#[test]
fn real_bundle_verifies_with_its_historical_identity_and_signed_time() {
    // The leaf certificate expired ten minutes after v0.9.4 was signed. A
    // successful verification now proves the bundle's Rekor/TSA evidence is
    // used as signing time rather than incorrectly requiring a live leaf cert.
    verify_fixture(LEGACY_IDENTITY, GITHUB_ACTIONS_ISSUER, FIXTURE_BYTES)
        .expect("authentic historical bundle verifies");
}

#[test]
fn production_identity_rejects_the_pre_rename_release() {
    let error = authenticate_for_test(
        FIXTURE_BYTES.to_vec(),
        FIXTURE_BUNDLE,
        &release_identity("0.9.4"),
        GITHUB_ACTIONS_ISSUER,
        &fixture_root(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        UpdateStageError::PublisherAuthentication(_)
    ));
}

#[test]
fn modified_bytes_fail_publisher_authentication() {
    let mut modified = FIXTURE_BYTES.to_vec();
    modified.extend_from_slice(b"modified");
    let error = authenticate_for_test(
        modified,
        FIXTURE_BUNDLE,
        LEGACY_IDENTITY,
        GITHUB_ACTIONS_ISSUER,
        &fixture_root(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        UpdateStageError::PublisherAuthentication(_)
    ));
}

#[test]
fn rejected_evidence_cannot_reach_filesystem_mutation() {
    let production_identity = release_identity("0.9.4");
    let cases: [(Vec<u8>, &str); 2] = [
        (
            {
                let mut modified = FIXTURE_BYTES.to_vec();
                modified.extend_from_slice(b"modified");
                modified
            },
            LEGACY_IDENTITY,
        ),
        (FIXTURE_BYTES.to_vec(), production_identity.as_str()),
    ];

    for (bytes, identity) in cases {
        let mutation_root = tempfile::tempdir().expect("create mutation sentinel");
        let digest = blake3::hash(&bytes);
        let result = (|| -> Result<_, UpdateStageError> {
            let authenticated = authenticate_for_test(
                bytes,
                FIXTURE_BUNDLE,
                identity,
                GITHUB_ACTIONS_ISSUER,
                &fixture_root(),
            )?;
            let sums = format!("{digest}  archive.tar.gz\n");
            let verified = verify_integrity(authenticated, &sums, "archive.tar.gz")?;
            extract_verified_archive_with(verified, "archive.tar.gz", "archive", || {
                tempfile::Builder::new()
                    .prefix("extraction-")
                    .tempdir_in(mutation_root.path())
            })
            .map_err(UpdateStageError::Preparation)
        })();

        assert!(matches!(
            result.unwrap_err(),
            UpdateStageError::PublisherAuthentication(_)
        ));
        assert_eq!(
            std::fs::read_dir(mutation_root.path()).unwrap().count(),
            0,
            "publisher rejection must happen before any temp directory or archive is written"
        );
    }
}

#[test]
fn wrong_repository_workflow_tag_and_issuer_fail() {
    let wrong_values = [
        (
            "https://github.com/other/astrid/.github/workflows/release.yml@refs/tags/v0.9.4",
            GITHUB_ACTIONS_ISSUER,
        ),
        (
            "https://github.com/unicity-astrid/astrid/.github/workflows/other.yml@refs/tags/v0.9.4",
            GITHUB_ACTIONS_ISSUER,
        ),
        (
            "https://github.com/unicity-astrid/astrid/.github/workflows/release.yml@refs/tags/v0.9.5",
            GITHUB_ACTIONS_ISSUER,
        ),
        (
            "https://github.com/unicity-astrid/astrid/.github/workflows/release.yml@refs/heads/main",
            GITHUB_ACTIONS_ISSUER,
        ),
        (
            "https://github.com/unicity-astrid/astrid/.github/workflows/release.yml@refs/pull/1250/merge",
            GITHUB_ACTIONS_ISSUER,
        ),
        (LEGACY_IDENTITY, "https://issuer.example.invalid"),
    ];

    for (identity, issuer) in wrong_values {
        assert!(
            verify_fixture(identity, issuer, FIXTURE_BYTES).is_err(),
            "unexpectedly accepted identity={identity} issuer={issuer}"
        );
    }
}

#[test]
fn malformed_bundle_is_rejected() {
    assert!(matches!(
        parse_publisher_bundle(b"{not-json").unwrap_err(),
        UpdateStageError::PublisherAuthentication(_)
    ));
}

#[test]
fn integrity_stage_is_strict_and_consumes_authenticated_bytes() {
    let asset = "astrid-1.0.0-x86_64-unknown-linux-gnu.tar.gz";
    let digest = blake3::hash(b"archive");
    let body = format!("{}  {asset}\n", digest.to_hex());
    let authenticated = PublisherAuthenticatedArchive(b"archive".to_vec());
    let verified = verify_integrity(authenticated, &body, asset).expect("matching digest");
    assert_eq!(verified.as_bytes(), b"archive");

    let bad = PublisherAuthenticatedArchive(b"modified".to_vec());
    assert!(matches!(
        verify_integrity(bad, &body, asset).unwrap_err(),
        UpdateStageError::Integrity(_)
    ));
}

#[test]
fn integrity_manifest_rejects_noncanonical_and_duplicate_entries() {
    let asset = "astrid-1.0.0-x86_64-unknown-linux-gnu.tar.gz";
    let digest = blake3::hash(b"archive").to_hex();
    let uppercase = format!("{}  {asset}\n", digest.to_string().to_uppercase());
    assert!(matches!(
        verify_integrity(
            PublisherAuthenticatedArchive(b"archive".to_vec()),
            &uppercase,
            asset
        )
        .unwrap_err(),
        UpdateStageError::Integrity(_)
    ));

    let duplicate = format!("{digest}  {asset}\n{digest}  {asset}\n");
    assert!(matches!(
        verify_integrity(
            PublisherAuthenticatedArchive(b"archive".to_vec()),
            &duplicate,
            asset
        )
        .unwrap_err(),
        UpdateStageError::Integrity(_)
    ));
}

#[tokio::test]
#[ignore = "release workflow only: requires freshly signed archives and live TUF metadata"]
async fn release_gate_authenticates_all_archives_with_production_policy() {
    let artifacts = std::path::PathBuf::from(
        std::env::var_os("ASTRID_RELEASE_GATE_ARTIFACTS")
            .expect("ASTRID_RELEASE_GATE_ARTIFACTS must name the release artifact directory"),
    );
    let version = std::env::var("ASTRID_RELEASE_GATE_VERSION")
        .expect("ASTRID_RELEASE_GATE_VERSION must contain canonical semver without v");
    let parsed = semver::Version::parse(&version).expect("release gate version must be semver");
    assert_eq!(
        version,
        parsed.to_string(),
        "release gate version is not canonical"
    );

    let mut archives = std::fs::read_dir(&artifacts)
        .expect("read release artifact directory")
        .map(|entry| entry.expect("read release artifact entry").path())
        .filter(|path| {
            path.file_name()
                .and_then(std::ffi::OsStr::to_str)
                .is_some_and(|name| name.ends_with(".tar.gz"))
        })
        .collect::<Vec<_>>();
    archives.sort();
    assert!(!archives.is_empty(), "release gate found no archives");

    for archive_path in archives {
        let archive_name = archive_path
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .expect("release archive name must be UTF-8");
        let bundle_path = archive_path.with_file_name(format!("{archive_name}.sigstore.json"));
        let archive = std::fs::read(&archive_path).expect("read release archive");
        let bundle = std::fs::read(&bundle_path).unwrap_or_else(|error| {
            panic!(
                "read native-verifier bundle {}: {error}",
                bundle_path.display()
            )
        });

        authenticate_archive(archive, &bundle, &version)
            .await
            .unwrap_or_else(|error| {
                panic!(
                    "native verifier rejected {} after Cosign accepted it: {error}",
                    archive_path.display()
                )
            });
    }
}
