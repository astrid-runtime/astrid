//! `astrid keypair` — local ed25519 identity-key management.
//!
//! Generates, lists, and inspects ed25519 keypairs that operators bind
//! to a principal via `astrid invite redeem`. Multi-key from day one —
//! every key is name-addressed under
//! `$ASTRID_HOME/keys/local/<name>.{ed25519, pub.hex, meta.toml}` so
//! the same operator can hold separate keys per machine / per
//! deployment without manual file management.
//!
//! ## Trust shape
//!
//! Identity keys here are **operator-local**: file-system perms
//! (0700 on the parent directory, 0600 on the private file) gate
//! access to whichever OS account owns `$ASTRID_HOME`. Layered
//! passphrase encryption is intentionally NOT applied — the rest of
//! Astrid (the daemon's `runtime.ed25519`, `system.token`, capsule
//! secrets) follows the same posture, and asking for a passphrase
//! every time would break the "OS-user owns everything" model.
//!
//! `zeroize` clears secret bytes from memory the moment the
//! [`ed25519_dalek::SigningKey`] is dropped — guards against post-use
//! page reuse and core-dump leakage.
//!
//! ## Forward-compatibility
//!
//! `AuthMethod::HardwareKey` (TPM / Yubikey / Secure Enclave) is a
//! design-time slot for later — when it lands, the file format here
//! stays the same; only the `meta.toml` `backend` field changes from
//! `"file"` to `"hardware"` and the private bytes get replaced by an
//! opaque handle.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::SystemTime;

use anyhow::{Context, Result, bail};
use astrid_core::PrincipalId;
use astrid_core::dirs::AstridHome;
use astrid_crypto::{PublicKey, PublicKeyFingerprint};
use clap::{Args, Subcommand};
use colored::Colorize;
use ed25519_dalek::SigningKey;
use rand::{TryRng, rngs::SysRng};
use serde::{Deserialize, Serialize};

use crate::theme::Theme;

/// Maximum length for a keypair `name`. Generous but bounded so a
/// malformed argument can't produce a giant filename.
const MAX_NAME_LEN: usize = 64;

#[derive(Subcommand, Debug, Clone)]
pub(crate) enum KeypairCommand {
    /// Generate a new ed25519 keypair, write it to disk, and print
    /// the hex-encoded public key (ready to feed into
    /// `astrid invite redeem --public-key`).
    Generate(GenerateArgs),
    /// List local keypairs.
    List(ListArgs),
    /// Show details for a single keypair.
    Show(ShowArgs),
    /// Print just the public key (`hex` by default; `openssh` for
    /// `ssh-ed25519 AAAA...` format).
    Pubkey(PubkeyArgs),
    /// Delete a local keypair (private + public + metadata).
    Delete(DeleteArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct GenerateArgs {
    /// Short identifier for the key (a-z, 0-9, -). Defaults to a
    /// random `key-<8-hex>` slug.
    #[arg(long)]
    pub name: Option<String>,
    /// Operator-supplied note attached to the metadata sidecar.
    #[arg(long)]
    pub note: Option<String>,
    /// Overwrite an existing keypair with the same name.
    #[arg(long)]
    pub force: bool,
    /// Print only the public-key hex on stdout (no decoration).
    /// Suitable for piping into other commands.
    #[arg(long)]
    pub raw: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ListArgs {
    /// Emit JSON instead of a table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ShowArgs {
    /// Keypair name.
    pub name: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct PubkeyArgs {
    /// Keypair name.
    pub name: String,
    /// Output format. `hex` matches what `astrid invite redeem
    /// --public-key` expects; `openssh` produces `ssh-ed25519 AAAA…`
    /// for reuse with SSH-style tooling; `wire` produces the
    /// `ed25519:<base64>` form that `[distro.signing].pubkey`,
    /// `astrid distro seal`, and the trust store consume.
    #[arg(long, value_enum, default_value_t = PubkeyFormat::Hex)]
    pub format: PubkeyFormat,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DeleteArgs {
    /// Keypair name.
    pub name: String,
    /// Skip the interactive confirmation prompt.
    #[arg(long)]
    pub yes: bool,
}

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub(crate) enum PubkeyFormat {
    Hex,
    Openssh,
    /// `ed25519:<base64>` — the form `[distro.signing].pubkey`,
    /// `astrid distro seal`, and the distro trust store consume.
    Wire,
}

// ── Persistence model ─────────────────────────────────────────────

/// Metadata sidecar persisted alongside each keypair. The private
/// file holds raw 32 bytes; this TOML carries the user-visible
/// description plus tracking fields needed for rotation later.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyMeta {
    /// Schema version of the meta file. Bumped on incompatible
    /// changes to this struct so older `astrid` binaries can refuse
    /// keys they don't understand.
    schema_version: u32,
    /// Domain-separated BLAKE3 fingerprint of the public key. The kernel and
    /// audit log use the same derivation, so operators can correlate local
    /// key metadata with redeem and pairing events.
    fingerprint: String,
    /// Unix-epoch seconds the keypair was generated.
    created_at_epoch: u64,
    /// Storage backend. `"file"` today; placeholder for future
    /// `"hardware"` (TPM / Yubikey / Secure Enclave) without
    /// requiring a separate config schema then.
    backend: String,
    /// Optional operator note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    /// Principal id this key was last bound to via
    /// `astrid invite redeem --keypair`. `None` if the key has never
    /// been used to redeem.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bound_principal: Option<String>,
}

const META_SCHEMA_VERSION: u32 = 2;

/// Returns the directory `~/.astrid/keys/local/`, creating it if
/// missing with 0700 perms.
fn local_keys_dir() -> Result<PathBuf> {
    let home = AstridHome::resolve().context("resolve $ASTRID_HOME for keypair store")?;
    let dir = home.keys_dir().join("local");
    fs::create_dir_all(&dir).with_context(|| format!("create keypair dir at {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

/// On-disk layout for one keypair `name`.
struct KeyPaths {
    /// Raw 32-byte secret. 0600 perms.
    private: PathBuf,
    /// 64-hex-char public key, newline-terminated. 0644 perms.
    public_hex: PathBuf,
    /// TOML metadata sidecar. 0600 perms.
    meta: PathBuf,
}

impl KeyPaths {
    fn new(name: &str) -> Result<Self> {
        let dir = local_keys_dir()?;
        Ok(Self {
            private: dir.join(format!("{name}.ed25519")),
            public_hex: dir.join(format!("{name}.pub.hex")),
            meta: dir.join(format!("{name}.meta.toml")),
        })
    }

    fn exists_any(&self) -> bool {
        self.private.exists() || self.public_hex.exists() || self.meta.exists()
    }
}

// ── Command dispatch ─────────────────────────────────────────────

pub(crate) fn run(command: KeypairCommand) -> Result<ExitCode> {
    let _mutation = lock_key_store(&local_keys_dir()?)?;
    match command {
        KeypairCommand::Generate(args) => run_generate(args),
        KeypairCommand::List(args) => run_list(&args),
        KeypairCommand::Show(args) => run_show(&args),
        KeypairCommand::Pubkey(args) => run_pubkey(&args),
        KeypairCommand::Delete(args) => run_delete(&args),
    }
}

fn run_generate(args: GenerateArgs) -> Result<ExitCode> {
    let name = args.name.unwrap_or_else(default_name);
    validate_name(&name)?;
    let paths = KeyPaths::new(&name)?;
    if args.force && paths.meta.exists() && read_meta(&paths)?.bound_principal.is_some() {
        bail!(
            "delete the bound keypair before replacing it; its activated credential must be retired"
        );
    }
    if paths.exists_any() && !args.force {
        bail!(
            "keypair {name:?} already exists at {} — pass --force to overwrite",
            paths.private.display()
        );
    }

    // Generate from the OS CSPRNG. ed25519-dalek's `Zeroizing` drop
    // glue runs when `signing` falls out of scope, clearing the
    // secret bytes from RAM.
    let mut secret_bytes = [0u8; 32];
    SysRng
        .try_fill_bytes(&mut secret_bytes)
        .context("OS CSPRNG unavailable while generating keypair")?;
    let signing = SigningKey::from_bytes(&secret_bytes);
    secret_bytes = [0u8; 32]; // belt-and-suspenders; the SigningKey owns its own zeroizing copy
    let _ = secret_bytes;

    let verifying = signing.verifying_key();
    let pub_hex = hex::encode(verifying.to_bytes());
    let fingerprint = fingerprint_pubkey(&pub_hex)?;

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let meta = KeyMeta {
        schema_version: META_SCHEMA_VERSION,
        fingerprint: fingerprint.clone(),
        created_at_epoch: now,
        backend: "file".to_string(),
        note: args.note,
        bound_principal: None,
    };

    write_secret(&paths.private, signing.as_bytes())?;
    write_public(&paths.public_hex, &pub_hex)?;
    write_meta(&paths.meta, &meta)?;

    if args.raw {
        println!("{pub_hex}");
    } else {
        println!(
            "{} keypair {} (fingerprint: {})",
            Theme::success("generated"),
            name.bold(),
            fingerprint,
        );
        println!("  public key (hex): {pub_hex}");
        println!("  private path:     {}", paths.private.display());
        println!("  next step:        astrid invite redeem <TOKEN> --keypair {name}");
    }
    Ok(ExitCode::SUCCESS)
}

fn run_list(args: &ListArgs) -> Result<ExitCode> {
    let entries = scan_keys()?;
    if args.json {
        let serializable: Vec<_> = entries.iter().map(KeyEntry::to_summary).collect();
        println!("{}", serde_json::to_string_pretty(&serializable)?);
        return Ok(ExitCode::SUCCESS);
    }
    if entries.is_empty() {
        println!("{}", Theme::dimmed("no local keypairs"));
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{:<24} {:<71} {:<10}  BOUND PRINCIPAL",
        "NAME", "FINGERPRINT", "CREATED",
    );
    for entry in entries {
        let bound = entry.meta.bound_principal.as_deref().unwrap_or("-");
        println!(
            "{:<24} {:<71} {:<10}  {}",
            entry.name, entry.meta.fingerprint, entry.meta.created_at_epoch, bound,
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn run_show(args: &ShowArgs) -> Result<ExitCode> {
    validate_name(&args.name)?;
    let paths = KeyPaths::new(&args.name)?;
    if !paths.meta.exists() {
        bail!("keypair {:?} not found", args.name);
    }
    let meta = read_meta(&paths)?;
    let pub_hex = read_public(&paths.public_hex).unwrap_or_else(|_| "<missing>".to_string());
    println!("name:            {}", args.name);
    println!("fingerprint:     {}", meta.fingerprint);
    println!("created (epoch): {}", meta.created_at_epoch);
    println!("backend:         {}", meta.backend);
    if let Some(p) = &meta.bound_principal {
        println!("bound principal: {p}");
    }
    if let Some(n) = &meta.note {
        println!("note:            {n}");
    }
    println!("public key (hex): {pub_hex}");
    println!("private path:    {}", paths.private.display());
    Ok(ExitCode::SUCCESS)
}

fn run_pubkey(args: &PubkeyArgs) -> Result<ExitCode> {
    validate_name(&args.name)?;
    let paths = KeyPaths::new(&args.name)?;
    let pub_hex = read_public(&paths.public_hex)
        .with_context(|| format!("read public key for {:?}", args.name))?;
    match args.format {
        PubkeyFormat::Hex => println!("{pub_hex}"),
        PubkeyFormat::Openssh => {
            let bytes = hex::decode(pub_hex.trim()).context("decode public key hex")?;
            println!("{}", encode_openssh_ed25519(&bytes));
        },
        PubkeyFormat::Wire => println!("{}", pubkey_hex_to_wire(&pub_hex)?),
    }
    Ok(ExitCode::SUCCESS)
}

fn run_delete(args: &DeleteArgs) -> Result<ExitCode> {
    validate_name(&args.name)?;
    let paths = KeyPaths::new(&args.name)?;
    if !paths.exists_any() {
        bail!("keypair {:?} not found", args.name);
    }
    if !args.yes {
        eprintln!(
            "{} will delete keypair {:?}. Re-run with --yes to confirm.",
            Theme::warning("⚠"),
            args.name
        );
        return Ok(ExitCode::from(1));
    }
    if paths.meta.exists() {
        let meta = read_meta(&paths)?;
        remove_bound_key(&paths, &AstridHome::resolve()?, &meta)?;
    }
    // Best-effort remove every component — a partially-corrupt store
    // (missing pub but present priv) should still let the operator
    // recover by deleting whatever exists.
    for p in [&paths.private, &paths.public_hex, &paths.meta] {
        if p.exists() {
            fs::remove_file(p).with_context(|| format!("remove {}", p.display()))?;
        }
    }
    println!("{} keypair {:?}", Theme::success("deleted"), args.name);
    Ok(ExitCode::SUCCESS)
}

// ── Public helpers used by other CLI verbs ───────────────────────

/// Load the hex-encoded public key for `name`. Used by `astrid
/// invite redeem --keypair NAME`.
///
/// # Errors
/// Returns an error if the name is invalid or the public-key file is
/// missing / unreadable.
pub(crate) fn load_public_key_hex(name: &str) -> Result<String> {
    validate_name(name)?;
    let paths = KeyPaths::new(name)?;
    read_public(&paths.public_hex).with_context(|| format!("read public key for {name:?}"))
}

/// Record on a keypair's metadata that it has been bound to
/// `principal` via a successful redeem and activate the native credential.
/// Never replace a different credential. Failure cannot roll back redemption,
/// so the caller must report the consumed token and must not switch context.
pub(crate) fn record_binding(
    name: &str,
    principal: &PrincipalId,
    redeemed_key: &PublicKey,
) -> Result<()> {
    validate_name(name)?;
    let paths = KeyPaths::new(name)?;
    let home = AstridHome::resolve().context("resolve home for invited principal key")?;
    record_binding_at(&paths, &home, principal, redeemed_key)
}

fn record_binding_at(
    paths: &KeyPaths,
    home: &AstridHome,
    principal: &PrincipalId,
    redeemed_key: &PublicKey,
) -> Result<()> {
    record_binding_with_commit(paths, home, principal, redeemed_key, write_meta)
}

fn record_binding_with_commit(
    paths: &KeyPaths,
    home: &AstridHome,
    principal: &PrincipalId,
    redeemed_key: &PublicKey,
    commit: impl FnOnce(&Path, &KeyMeta) -> Result<()>,
) -> Result<()> {
    let _mutation = lock_key_store(paths.meta.parent().context("key metadata has no parent")?)?;
    let mut meta = read_meta(paths)?;
    if let Some(bound) = &meta.bound_principal
        && bound != principal.as_str()
    {
        bail!("local key is already bound to principal {bound}");
    }
    let secret =
        zeroize::Zeroizing::new(fs::read(&paths.private).context("read invited signing key")?);
    let key =
        astrid_crypto::KeyPair::from_secret_key(&secret).context("decode invited signing key")?;
    if key.export_public_key() != *redeemed_key {
        bail!("local signing key does not match the public key redeemed by the daemon");
    }
    let destination = home.keys_dir().join(format!("{principal}.key"));
    meta.bound_principal = Some(principal.to_string());
    // Persist recovery ownership before publishing a usable credential. A crash
    // or failed activation then leaves a deletable binding, never an untracked key.
    commit(&paths.meta, &meta)?;
    activate_invited_key(&destination, &secret)?;
    Ok(())
}

/// All cooperating CLI mutations share a stable lock inode. Never unlink it:
/// replacement would let two processes acquire locks on different inodes.
fn lock_key_store(directory: &Path) -> Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lock = options.open(directory.join(".mutation.lock"))?;
    if !lock.metadata()?.is_file() {
        bail!("key store mutation lock is not a regular file");
    }
    lock.try_lock()
        .context("key store is busy; retry after the other operation completes")?;
    Ok(lock)
}

fn remove_bound_key(paths: &KeyPaths, home: &AstridHome, meta: &KeyMeta) -> Result<()> {
    let Some(bound) = &meta.bound_principal else {
        return Ok(());
    };
    let principal = PrincipalId::new(bound.clone()).context("invalid bound key principal")?;
    let (secret, verify_metadata) = match fs::read(&paths.private) {
        Ok(secret) => (zeroize::Zeroizing::new(secret), false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Partial deletion may have removed the private sidecar already.
            // The persisted fingerprint still identifies the credential to retire.
            let destination = home.keys_dir().join(format!("{principal}.key"));
            match fs::symlink_metadata(&destination) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                Err(error) => return Err(error.into()),
                Ok(metadata) if !metadata.file_type().is_file() => {
                    bail!("activated credential is not a regular file")
                },
                Ok(_) => (),
            }
            (zeroize::Zeroizing::new(fs::read(destination)?), true)
        },
        Err(error) => return Err(error).context("read key being deleted"),
    };
    let key = astrid_crypto::KeyPair::from_secret_key(&secret)?;
    let public = key.export_public_key();
    if verify_metadata
        && PublicKeyFingerprint::from_public_key(&public).as_str() != meta.fingerprint
    {
        bail!("private credential does not match bound key metadata; refusing deletion");
    }
    remove_activated_key(home, &principal, &public)
}

/// Publish complete secret bytes without replacing another device's credential.
fn activate_invited_key(destination: &Path, secret: &[u8]) -> Result<()> {
    use std::io::Write;

    let parent = destination
        .parent()
        .context("principal key has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .context("create private invited-key staging file")?;
    temporary.write_all(secret)?;
    temporary.as_file().sync_all()?;
    match temporary.persist_noclobber(destination) {
        Ok(_) => {
            #[cfg(unix)]
            fs::File::open(parent)?.sync_all()?;
        },
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(destination)?;
            if !metadata.file_type().is_file() {
                bail!("existing principal signing key is not a regular file");
            }
            let existing = zeroize::Zeroizing::new(fs::read(destination)?);
            if existing.as_slice() != secret {
                bail!("principal already has a different local signing key; refusing replacement");
            }
        },
        Err(error) => return Err(error.error).context("activate invited principal signing key"),
    }
    Ok(())
}

/// Removing a named local key must not leave its activated credential usable.
fn remove_activated_key(
    home: &AstridHome,
    principal: &PrincipalId,
    public: &PublicKey,
) -> Result<()> {
    let destination = home.keys_dir().join(format!("{principal}.key"));
    let metadata = match fs::symlink_metadata(&destination) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("inspect activated credential"),
    };
    if !metadata.file_type().is_file() {
        bail!("activated credential is not a regular file");
    }
    let secret = zeroize::Zeroizing::new(fs::read(&destination)?);
    let key = astrid_crypto::KeyPair::from_secret_key(&secret)?;
    if key.export_public_key() != *public {
        bail!("activated credential changed; refusing to delete another key");
    }
    fs::remove_file(destination).context("remove activated credential")?;
    #[cfg(unix)]
    fs::File::open(home.keys_dir())?.sync_all()?;
    Ok(())
}

// ── Filesystem helpers ───────────────────────────────────────────

fn write_secret(path: &Path, bytes: &[u8; 32]) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path).inspect_err(|_| {
            let _ = fs::remove_file(&tmp);
        })?;
    }
    #[cfg(not(unix))]
    {
        fs::write(path, bytes)?;
    }
    Ok(())
}

fn write_public(path: &Path, hex: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&tmp, format!("{hex}\n").as_bytes())
        .with_context(|| format!("write public key to {}", tmp.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
    }
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })?;
    Ok(())
}

fn write_meta(path: &Path, meta: &KeyMeta) -> Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let text = toml::to_string_pretty(meta).context("serialise keypair meta")?;
    let parent = path.parent().context("key metadata has no parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(text.as_bytes())?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn read_public(path: &Path) -> Result<String> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let trimmed = raw.trim().to_string();
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("{} is not a 64-char hex public key", path.display());
    }
    Ok(trimmed)
}

fn read_meta(paths: &KeyPaths) -> Result<KeyMeta> {
    let text = fs::read_to_string(&paths.meta)
        .with_context(|| format!("read {}", paths.meta.display()))?;
    let meta: KeyMeta =
        toml::from_str(&text).with_context(|| format!("parse {}", paths.meta.display()))?;
    if meta.schema_version > META_SCHEMA_VERSION {
        bail!(
            "keypair {} was written by a newer astrid (schema {} > {})",
            paths.meta.display(),
            meta.schema_version,
            META_SCHEMA_VERSION
        );
    }
    if meta.schema_version < META_SCHEMA_VERSION {
        let public_hex = match read_public(&paths.public_hex) {
            Ok(public_hex) => public_hex,
            Err(error) => {
                tracing::warn!(
                    path = %paths.meta.display(),
                    %error,
                    "keypair fingerprint migration deferred until a valid public key is available"
                );
                return Ok(meta);
            },
        };
        let expected = fingerprint_pubkey(&public_hex)?;
        let migrated = KeyMeta {
            schema_version: META_SCHEMA_VERSION,
            fingerprint: expected,
            ..meta
        };
        write_meta(&paths.meta, &migrated)?;
        return Ok(migrated);
    }
    if let Ok(public_hex) = read_public(&paths.public_hex) {
        let expected = fingerprint_pubkey(&public_hex)?;
        if meta.fingerprint != expected {
            let repaired = KeyMeta {
                fingerprint: expected,
                ..meta
            };
            write_meta(&paths.meta, &repaired)?;
            return Ok(repaired);
        }
    }
    Ok(meta)
}

// ── Listing ──────────────────────────────────────────────────────

struct KeyEntry {
    name: String,
    meta: KeyMeta,
}

impl KeyEntry {
    fn to_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "fingerprint": self.meta.fingerprint,
            "created_at_epoch": self.meta.created_at_epoch,
            "backend": self.meta.backend,
            "note": self.meta.note,
            "bound_principal": self.meta.bound_principal,
        })
    }
}

fn scan_keys() -> Result<Vec<KeyEntry>> {
    let Ok(dir) = local_keys_dir() else {
        return Ok(Vec::new());
    };
    let read_dir = match fs::read_dir(&dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("list keypair dir"),
    };
    let mut out = Vec::new();
    for entry in read_dir.flatten() {
        let path = entry.path();
        let Some(name) = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(".meta.toml"))
        else {
            continue;
        };
        let name = name.to_owned();
        let paths = KeyPaths {
            private: dir.join(format!("{name}.ed25519")),
            public_hex: dir.join(format!("{name}.pub.hex")),
            meta: path,
        };
        match read_meta(&paths) {
            Ok(meta) => out.push(KeyEntry { name, meta }),
            Err(e) => {
                tracing::warn!(name = %name, error = %e, "skipping unreadable keypair meta");
            },
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

// ── Misc helpers ─────────────────────────────────────────────────

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("keypair name must not be empty");
    }
    if name.len() > MAX_NAME_LEN {
        bail!(
            "keypair name must be at most {MAX_NAME_LEN} chars (got {})",
            name.len()
        );
    }
    // Lowercase letters, digits, dash. Same posture as principal ids;
    // also avoids path-separator / shell-meta surprises.
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("keypair name {name:?} contains invalid chars; only a-z, 0-9, '-' are allowed");
    }
    Ok(())
}

fn default_name() -> String {
    let mut bytes = [0u8; 4];
    SysRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG unavailable while generating default keypair name");
    format!("key-{}", hex::encode(bytes))
}

fn fingerprint_pubkey(hex_pub: &str) -> Result<String> {
    PublicKeyFingerprint::from_ed25519_hex(hex_pub)
        .map(PublicKeyFingerprint::into_inner)
        .map_err(|e| anyhow::anyhow!("fingerprint Ed25519 public key: {e}"))
}

/// Convert a 64-char hex ed25519 public key into the `ed25519:<base64>`
/// wire form that `[distro.signing].pubkey`, `astrid distro seal`, and
/// the distro trust store consume. Reuses `astrid-crypto`'s encoder so
/// the base64 variant matches the verifier byte-for-byte.
fn pubkey_hex_to_wire(pub_hex: &str) -> Result<String> {
    let pk = astrid_crypto::PublicKey::from_hex(pub_hex.trim())
        .map_err(|e| anyhow::anyhow!("decode public key hex: {e}"))?;
    Ok(format!("ed25519:{}", pk.to_base64()))
}

/// Encode a 32-byte ed25519 public key in the `OpenSSH` wire format
/// (`ssh-ed25519 <base64>` — RFC 8709 §4). Lets operators paste the
/// same key into `authorized_keys` if they want to reuse it for SSH.
/// The body is a length-prefixed type tag followed by the key.
fn encode_openssh_ed25519(pubkey: &[u8]) -> String {
    use base64::Engine;
    let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
    let typ = b"ssh-ed25519";
    blob.extend_from_slice(&u32::try_from(typ.len()).unwrap_or(0).to_be_bytes());
    blob.extend_from_slice(typ);
    blob.extend_from_slice(&u32::try_from(pubkey.len()).unwrap_or(0).to_be_bytes());
    blob.extend_from_slice(pubkey);
    format!(
        "ssh-ed25519 {}",
        base64::engine::general_purpose::STANDARD.encode(&blob)
    )
}

#[cfg(test)]
mod tests;
