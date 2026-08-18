//! `astrid capsule publish` — offline, deterministic Index preparation.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use astrid_capsule_index::{
    ActorId, BuildProvenance, CanonicalSemVer, CapsuleName, Coordinate, Digest, GitObjectId,
    IndexId, MirrorUrl, Namespace, PublicationClassification, PublisherIdentity, SourceProvenance,
};
use astrid_capsule_publish::{
    FilePreflight, PreparedPublication, PublishOptions, WriteOutcome, prepare, write_submission,
};
use clap::{ArgAction, Args};

/// Arguments for `astrid capsule publish`.
#[derive(Debug, Args)]
pub(crate) struct PublishArgs {
    /// Existing installable `.capsule` artifact to inspect and hash.
    pub(crate) artifact: PathBuf,
    /// Explicit Index identifier (use with `--index-base`).
    #[arg(long, conflicts_with = "index_source")]
    pub(crate) index_id: Option<String>,
    /// Explicit HTTPS Index base URL (use with `--index-id`).
    #[arg(long, conflicts_with = "index_source")]
    pub(crate) index_base: Option<String>,
    /// Use a previously configured local Index source, without refreshing it.
    #[arg(long = "index-source", conflicts_with_all = ["index_id", "index_base"])]
    pub(crate) index_source: Option<String>,
    /// Lowercase namespace portion of the publication coordinate.
    #[arg(long)]
    pub(crate) namespace: String,
    /// Lowercase capsule-name portion of the publication coordinate.
    #[arg(long)]
    pub(crate) name: String,
    /// Canonical `SemVer` release (build metadata is rejected).
    #[arg(long)]
    pub(crate) version: String,
    /// Publisher actor identity; no local signer fallback exists.
    #[arg(long)]
    pub(crate) publisher: String,
    /// Tagged signing-key fingerprint (`sha256:`/`blake3:` etc.).
    #[arg(long)]
    pub(crate) signing_key: String,
    /// Original artifact URL. Repeat for mirrors.
    #[arg(long = "artifact-url", action = ArgAction::Append, required = true)]
    pub(crate) artifact_urls: Vec<String>,
    /// Source repository URL.
    #[arg(long)]
    pub(crate) source_repository: String,
    /// Numeric GitHub owner ID.
    #[arg(long)]
    pub(crate) github_owner_id: u64,
    /// Numeric GitHub repository ID.
    #[arg(long)]
    pub(crate) github_repository_id: u64,
    /// Lowercase source commit object ID.
    #[arg(long)]
    pub(crate) source_commit: String,
    /// Lowercase source tree object ID.
    #[arg(long)]
    pub(crate) source_tree: String,
    /// Source release tag/ref.
    #[arg(long)]
    pub(crate) source_tag: String,
    /// Optional source subdirectory.
    #[arg(long)]
    pub(crate) source_subdirectory: Option<String>,
    /// Digest of the source tree/provenance projection.
    #[arg(long)]
    pub(crate) source_digest: String,
    /// Provenance predicate type.
    #[arg(long)]
    pub(crate) predicate_type: String,
    /// Digest of the provenance statement.
    #[arg(long)]
    pub(crate) statement_digest: String,
    /// Explicit builder identity URL.
    #[arg(long)]
    pub(crate) builder_identity: String,
    /// Explicit attestation identity.
    #[arg(long)]
    pub(crate) attestation_identity: String,
    /// Runtime requirement. Must equal `package.astrid-version`.
    #[arg(long)]
    pub(crate) runtime: String,
    /// Component Model ABI requirement.
    #[arg(long)]
    pub(crate) abi: String,
    /// Explicit output directory for the PR-ready submission tree.
    #[arg(long, value_name = "DIR")]
    pub(crate) output_dir: PathBuf,
    /// Validate and print the record without writing any output.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Emit machine-readable JSON instead of the short human summary.
    #[arg(long)]
    pub(crate) json: bool,
}

/// Run offline publication preparation.  This function has no network or
/// GitHub mutation path; configured sources are read-only local input.
pub(crate) fn run(args: &PublishArgs) -> Result<ExitCode> {
    let (index_id, index_base) = resolve_index(args)?;
    let coordinate = Coordinate::new(
        Namespace::new(args.namespace.clone())?,
        CapsuleName::new(args.name.clone())?,
    );
    let version = CanonicalSemVer::parse(&args.version)?;
    let artifact_locations = args
        .artifact_urls
        .iter()
        .map(|url| MirrorUrl::new(url.clone()))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let publisher = PublisherIdentity::new(
        ActorId::new(args.publisher.clone())?,
        args.signing_key.parse::<Digest>()?,
    );
    let source = SourceProvenance::new(
        MirrorUrl::new(args.source_repository.clone())?,
        args.github_owner_id,
        args.github_repository_id,
        GitObjectId::new(args.source_commit.clone())?,
        GitObjectId::new(args.source_tree.clone())?,
        args.source_tag.clone(),
        args.source_subdirectory.clone(),
        args.source_digest.parse::<Digest>()?,
    )?;
    let provenance = BuildProvenance::new(
        args.predicate_type.clone(),
        args.statement_digest.parse::<Digest>()?,
        MirrorUrl::new(args.builder_identity.clone())?,
        args.attestation_identity.clone(),
    )?;
    let options = PublishOptions::new(
        &args.artifact,
        index_id,
        index_base,
        coordinate,
        version,
        artifact_locations,
        publisher,
        source,
        provenance,
        args.runtime.clone(),
        args.abi.clone(),
        &args.output_dir,
    );
    let preflight = FilePreflight::new(&args.output_dir);
    let prepared = prepare(&options, &preflight).map_err(anyhow::Error::from)?;
    render_result(&prepared, args.dry_run, args.json)?;
    Ok(ExitCode::SUCCESS)
}

fn resolve_index(args: &PublishArgs) -> Result<(IndexId, MirrorUrl)> {
    match (
        args.index_id.as_deref(),
        args.index_base.as_deref(),
        args.index_source.as_deref(),
    ) {
        (Some(id), Some(base), None) => Ok((IndexId::new(id)?, MirrorUrl::new(base)?)),
        (None, None, Some(source_id)) => {
            let home = astrid_core::dirs::AstridHome::resolve()
                .context("resolve Astrid home for configured Index source")?;
            let store = crate::commands::index::IndexStore::from_home(home.root(), None);
            let source = store
                .load()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
                .into_iter()
                .find(|source| source.id == source_id)
                .ok_or_else(|| anyhow::anyhow!("configured Index source not found: {source_id}"))?;
            Ok((IndexId::new(source.id)?, MirrorUrl::new(source.base_url)?))
        },
        _ => bail!(
            "provide --index-id together with --index-base, or use exactly one --index-source"
        ),
    }
}

fn render_result(prepared: &PreparedPublication, dry_run: bool, json: bool) -> Result<()> {
    if dry_run {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "dry_run": true,
                    "classification": classification_label(prepared.classification()),
                    "output_path": prepared.output_path(),
                    "publication": serde_json::to_value(prepared.record())?,
                    "index_base": prepared.index_base(),
                })
            );
        } else {
            println!(
                "Dry run: {} ({}) -> {}",
                prepared.record().key(),
                classification_label(prepared.classification()),
                prepared.output_path().display()
            );
        }
        return Ok(());
    }
    let outcome = write_submission(prepared).map_err(anyhow::Error::from)?;
    if json {
        println!(
            "{}",
            serde_json::json!({
                "dry_run": false,
                "classification": classification_label(prepared.classification()),
                "outcome": write_outcome_label(&outcome),
                "output_path": prepared.output_path(),
                "publication": serde_json::to_value(prepared.record())?,
                "index_base": prepared.index_base(),
            })
        );
    } else {
        println!(
            "Prepared {} ({}) at {}",
            prepared.record().key(),
            write_outcome_label(&outcome),
            prepared.output_path().display()
        );
    }
    Ok(())
}

pub(super) fn classification_label(classification: PublicationClassification) -> &'static str {
    match classification {
        PublicationClassification::New => "new",
        PublicationClassification::Idempotent => "idempotent",
        PublicationClassification::Equivocation => "equivocation",
    }
}

fn write_outcome_label(outcome: &WriteOutcome) -> &'static str {
    match outcome {
        WriteOutcome::Written { .. } => "written",
        WriteOutcome::Idempotent { .. } => "idempotent",
    }
}
