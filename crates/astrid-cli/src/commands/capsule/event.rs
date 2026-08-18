//! Offline preparation of sealed Capsule Index lifecycle events.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use astrid_capsule_index::{
    ActorId, Digest, EventAuthorization, EventBody, EventEnvelope, IndexEvent, IndexId,
    IndexIdentity, IndexLedger, MirrorUrl, Namespace, PublicationKey, SchemaVersion,
    TrustRootFingerprint,
};
use clap::{Args, Subcommand};
use tempfile::NamedTempFile;

/// One offline lifecycle-event preparation request.
#[derive(Debug, Args)]
pub(crate) struct EventArgs {
    /// Explicit Index ID (requires `--index-base` and `--trust-root`).
    #[arg(long, conflicts_with = "index_source")]
    pub(crate) index_id: Option<String>,
    /// Explicit Index base URL (validated but never contacted).
    #[arg(long, conflicts_with = "index_source")]
    pub(crate) index_base: Option<String>,
    /// Explicit tagged trust-root fingerprint (`sha256:<hex>` or bare hex).
    #[arg(long, conflicts_with = "index_source")]
    pub(crate) trust_root: Option<String>,
    /// Read the configured Index identity without refreshing it.
    #[arg(long = "index-source", conflicts_with_all = ["index_id", "index_base", "trust_root"])]
    pub(crate) index_source: Option<String>,
    /// Namespace of the exact target publication.
    #[arg(long)]
    pub(crate) namespace: String,
    /// Capsule name of the exact target publication.
    #[arg(long)]
    pub(crate) name: String,
    /// Canonical `SemVer` of the exact target publication.
    #[arg(long)]
    pub(crate) version: String,
    /// Authorization actor identity.
    #[arg(long)]
    pub(crate) actor: String,
    /// Non-empty authorization evidence/reference.  Signature verification is
    /// delegated to the index/TUF layer and is not performed by the CLI.
    #[arg(long)]
    pub(crate) authorization_evidence: String,
    /// Tagged digest of the authorization evidence/signature.
    #[arg(long)]
    pub(crate) authorization_signature_digest: String,
    /// Canonical RFC3339 UTC timestamp; no wall-clock fallback is used.
    #[arg(long)]
    pub(crate) recorded_at: String,
    /// Explicit repository/output directory containing `records/` and
    /// append-only `events/*.json` envelope files.
    #[arg(long, value_name = "DIR")]
    pub(crate) output_dir: PathBuf,
    /// Print the sealed envelope without writing it.
    #[arg(long)]
    pub(crate) dry_run: bool,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub(crate) json: bool,
    /// Lifecycle action to prepare.
    #[command(subcommand)]
    pub(crate) action: EventAction,
}

/// Supported append-only publication event actions.
#[derive(Debug, Subcommand)]
pub(crate) enum EventAction {
    /// Exclude a publication from new resolution.
    Yank {
        /// Optional human-readable reason.
        #[arg(long)]
        reason: Option<String>,
    },
    /// Remove a prior yank.
    Unyank,
    /// Mark a publication deprecated, optionally naming its replacement.
    Deprecate {
        /// Replacement namespace (must be supplied with name and version).
        #[arg(long)]
        replacement_namespace: Option<String>,
        /// Replacement capsule name.
        #[arg(long)]
        replacement_name: Option<String>,
        /// Replacement version.
        #[arg(long)]
        replacement_version: Option<String>,
        /// Optional deprecation note.
        #[arg(long)]
        note: Option<String>,
    },
    /// Revoke a publication fail-closed.
    Revoke {
        /// Required reason.
        #[arg(long)]
        reason: String,
    },
    /// Tombstone a publication permanently.
    Tombstone {
        /// Required reason.
        #[arg(long)]
        reason: String,
    },
    /// Add an explicit HTTPS artifact mirror.
    AddMirror {
        /// Mirror URL.
        #[arg(long)]
        mirror: String,
    },
}

/// Run lifecycle event preparation and optional atomic append.
pub(crate) fn run(args: &EventArgs) -> Result<std::process::ExitCode> {
    let identity = resolve_identity(args)?;
    let target = PublicationKey::new(
        identity.id.clone(),
        astrid_capsule_index::Coordinate::new(
            Namespace::new(args.namespace.clone())?,
            astrid_capsule_index::CapsuleName::new(args.name.clone())?,
        ),
        args.version.parse()?,
    );
    let actor = ActorId::new(args.actor.clone())?;
    let authorization = EventAuthorization::new(
        actor.clone(),
        args.authorization_evidence.clone(),
        args.authorization_signature_digest.parse::<Digest>()?,
    )?;
    let event = action_to_event(&args.action, actor.clone(), target.clone(), &identity.id)?;
    let (mut ledger, envelopes, events_dir, last_event_path) =
        load_state(&identity, &args.output_dir)?;
    let length = u64::try_from(envelopes.len()).context("event sequence overflow")?;
    let sequence = length
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("event sequence overflow"))?;
    let prior = envelopes
        .last()
        .map(|envelope| envelope.event_digest().clone());
    let envelope = EventEnvelope::seal(
        SchemaVersion::event_v1(),
        identity.clone(),
        sequence,
        args.recorded_at.clone(),
        actor,
        authorization,
        prior,
        EventBody::Publication(event),
    )?;
    let idempotent = envelopes.last().is_some_and(|last| {
        last.body() == envelope.body()
            && last.actor() == envelope.actor()
            && last.authorization() == envelope.authorization()
    });
    if !idempotent {
        ledger.append_envelope(envelope.clone())?;
    }
    let target_path = if idempotent {
        last_event_path.unwrap_or_else(|| event_path(&events_dir, &envelope))
    } else {
        let target = event_path(&events_dir, &envelope);
        if !args.dry_run {
            append_envelope(&events_dir, &envelope)?;
        }
        target
    };
    render(&envelope, &target_path, idempotent, args.dry_run, args.json);
    Ok(std::process::ExitCode::SUCCESS)
}

fn resolve_identity(args: &EventArgs) -> Result<IndexIdentity> {
    match (
        args.index_id.as_deref(),
        args.index_base.as_deref(),
        args.trust_root.as_deref(),
        args.index_source.as_deref(),
    ) {
        (Some(id), Some(base), Some(root), None) => {
            let _ = MirrorUrl::new(base.to_owned())?;
            Ok(IndexIdentity::new(
                IndexId::new(id)?,
                TrustRootFingerprint::parse(root)?,
            ))
        },
        (None, None, None, Some(source_id)) => {
            let home = astrid_core::dirs::AstridHome::resolve()
                .context("resolve Astrid home for configured Index source")?;
            let store = crate::commands::index::IndexStore::from_home(home.root(), None);
            let source = store
                .load()
                .map_err(|error| anyhow::anyhow!(error.to_string()))?
                .into_iter()
                .find(|source| source.id == source_id)
                .ok_or_else(|| anyhow::anyhow!("configured Index source not found: {source_id}"))?;
            Ok(source
                .protocol_identity()
                .map_err(|error| anyhow::anyhow!("invalid configured Index identity: {error}"))?)
        },
        _ => bail!("provide --index-id/--index-base/--trust-root, or exactly one --index-source"),
    }
}

fn action_to_event(
    action: &EventAction,
    actor: ActorId,
    target: PublicationKey,
    index_id: &IndexId,
) -> Result<IndexEvent> {
    Ok(match action {
        EventAction::Yank { reason } => IndexEvent::yank(actor, target, reason.clone()),
        EventAction::Unyank => IndexEvent::unyank(actor, target),
        EventAction::Deprecate {
            replacement_namespace,
            replacement_name,
            replacement_version,
            note,
        } => {
            let replacement = match (replacement_namespace, replacement_name, replacement_version) {
                (None, None, None) => None,
                (Some(namespace), Some(name), Some(version)) => Some(PublicationKey::new(
                    index_id.clone(),
                    astrid_capsule_index::Coordinate::new(
                        Namespace::new(namespace.clone())?,
                        astrid_capsule_index::CapsuleName::new(name.clone())?,
                    ),
                    version.parse()?,
                )),
                _ => bail!("replacement namespace, name, and version must be supplied together"),
            };
            IndexEvent::deprecate(actor, target, replacement, note.clone())
        },
        EventAction::Revoke { reason } => IndexEvent::revoke(actor, target, reason.clone()),
        EventAction::Tombstone { reason } => IndexEvent::tombstone(actor, target, reason.clone()),
        EventAction::AddMirror { mirror } => {
            IndexEvent::add_mirror(actor, target, MirrorUrl::new(mirror.clone())?)
        },
    })
}

fn load_state(
    identity: &IndexIdentity,
    output_dir: &Path,
) -> Result<(IndexLedger, Vec<EventEnvelope>, PathBuf, Option<PathBuf>)> {
    let mut ledger = IndexLedger::new(identity.clone());
    let releases = select_records_dir(output_dir)?;
    if releases.exists() {
        for namespace in fs::read_dir(&releases)? {
            let namespace = namespace?;
            if !namespace.file_type()?.is_dir() {
                bail!(
                    "release namespace entry is not a directory: {}",
                    namespace.path().display()
                );
            }
            for capsule in fs::read_dir(namespace.path())? {
                let capsule = capsule?;
                if !capsule.file_type()?.is_dir() {
                    bail!(
                        "release capsule entry is not a directory: {}",
                        capsule.path().display()
                    );
                }
                for record_path in fs::read_dir(capsule.path())? {
                    let record_path = record_path?;
                    if record_path.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                        continue;
                    }
                    let record = serde_json::from_slice(&fs::read(record_path.path())?)?;
                    ledger.publish(record)?;
                }
            }
        }
    }
    let events_dir = output_dir.join("events");
    let mut event_files = Vec::new();
    match fs::symlink_metadata(&events_dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {},
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("events directory is a symlink: {}", events_dir.display());
        },
        Ok(metadata) if !metadata.file_type().is_dir() => {
            bail!("events path is not a directory: {}", events_dir.display());
        },
        Err(error) => return Err(error.into()),
        Ok(_) => {
            for entry in fs::read_dir(&events_dir)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_symlink() || !file_type.is_file() {
                    bail!(
                        "events directory contains a non-file entry: {}",
                        entry.path().display()
                    );
                }
                let name = entry.file_name();
                let name = name.to_str().ok_or_else(|| {
                    anyhow::anyhow!("events directory contains a non-UTF-8 filename")
                })?;
                let (sequence, digest_hex) = parse_event_filename(name)?;
                event_files.push((sequence, digest_hex, entry.path()));
            }
        },
    }
    event_files.sort_by_key(|(sequence, _, _)| *sequence);
    let mut envelopes = Vec::new();
    for (expected_sequence, expected_digest, path) in &event_files {
        let envelope: EventEnvelope = serde_json::from_slice(&fs::read(path)?)?;
        if envelope.sequence() != *expected_sequence
            || envelope.event_digest().hex() != *expected_digest
        {
            bail!(
                "event filename does not match sealed envelope: {}",
                path.display()
            );
        }
        let expected = u64::try_from(envelopes.len())
            .ok()
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| anyhow::anyhow!("event sequence overflow"))?;
        if *expected_sequence != expected {
            bail!("event sequence gap before {}", path.display());
        }
        ledger.append_envelope(envelope.clone())?;
        envelopes.push(envelope);
    }
    let last_event_path = event_files.last().map(|(_, _, path)| path.clone());
    Ok((ledger, envelopes, events_dir, last_event_path))
}

fn select_records_dir(output_dir: &Path) -> Result<PathBuf> {
    let canonical = output_dir.join("records");
    let legacy = output_dir.join("releases");
    for candidate in [&canonical, &legacy] {
        match fs::symlink_metadata(candidate) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Ok(metadata) if metadata.file_type().is_symlink() => {
                bail!("record directory is a symlink: {}", candidate.display());
            },
            Ok(metadata) if metadata.file_type().is_dir() => return Ok(candidate.clone()),
            Ok(_) => bail!("record path is not a directory: {}", candidate.display()),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(canonical)
}

fn parse_event_filename(name: &str) -> Result<(u64, String)> {
    let Some(stem) = name.strip_suffix(".json") else {
        bail!("event filename must end in .json: {name}");
    };
    let Some((sequence, digest)) = stem.split_once('-') else {
        bail!("event filename must be <sequence>-<digest>.json: {name}");
    };
    if sequence.len() != 20 || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("event filename has invalid sequence: {name}");
    }
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("event filename has invalid digest: {name}");
    }
    Ok((sequence.parse()?, digest.to_ascii_lowercase()))
}

fn event_path(events_dir: &Path, envelope: &EventEnvelope) -> PathBuf {
    events_dir.join(format!(
        "{:020}-{}.json",
        envelope.sequence(),
        envelope.event_digest().hex()
    ))
}

fn append_envelope(events_dir: &Path, envelope: &EventEnvelope) -> Result<()> {
    reject_output_symlinks(events_dir)?;
    fs::create_dir_all(events_dir)?;
    reject_output_symlinks(events_dir)?;
    let path = event_path(events_dir, envelope);
    let bytes = serde_json::to_vec_pretty(envelope)?;
    let mut temporary = NamedTempFile::new_in(events_dir)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(&path) {
        Ok(_) => {},
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            let existing: EventEnvelope = serde_json::from_slice(&fs::read(&path)?)?;
            if existing != *envelope {
                bail!(
                    "event output path is occupied by a different envelope: {}",
                    path.display()
                );
            }
        },
        Err(error) => return Err(error.error.into()),
    }
    File::open(events_dir)?.sync_all()?;
    Ok(())
}

fn reject_output_symlinks(path: &Path) -> Result<()> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if current == Path::new("/var") {
            continue;
        }
        if let Ok(metadata) = fs::symlink_metadata(&current)
            && metadata.file_type().is_symlink()
        {
            bail!(
                "output path contains symlink component {}",
                current.display()
            );
        }
    }
    Ok(())
}

fn render(envelope: &EventEnvelope, path: &Path, idempotent: bool, dry_run: bool, json: bool) {
    let outcome = if idempotent { "idempotent" } else { "written" };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "dry_run": dry_run,
                "outcome": outcome,
                "sequence": envelope.sequence(),
                "event_digest": envelope.event_digest(),
                "events_path": path,
                "envelope": envelope,
            })
        );
    } else {
        println!(
            "Prepared event sequence {} ({}) at {}",
            envelope.sequence(),
            if dry_run { "dry-run" } else { outcome },
            path.display()
        );
    }
}
