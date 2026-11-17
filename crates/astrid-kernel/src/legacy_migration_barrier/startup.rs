//! Gate interrupted projection recovery before ordinary host admission.

use std::{fs, io};

use astrid_storage::{ContentName, RuntimeProjectionRecovery};

use super::host_fs::missing_layout_provenance;
use super::{AstridHome, LayoutOrigin, MAX_BYTES, capture_layout_origin, ledger_path};
use super::{read_bounded_file, validate_complete_ledger};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupLayout {
    Ordinary(LayoutOrigin),
    RecoverRetiring,
}

impl StartupLayout {
    pub(crate) const fn origin(self) -> LayoutOrigin {
        match self {
            Self::Ordinary(origin) => origin,
            Self::RecoverRetiring => LayoutOrigin::ExistingV2,
        }
    }
}

pub(crate) fn classify_startup(home: &AstridHome) -> io::Result<StartupLayout> {
    let origin = capture_layout_origin(home)?;
    if origin == LayoutOrigin::Legacy {
        return Ok(StartupLayout::Ordinary(origin));
    }
    let ledger = read_bounded_file(&ledger_path(home), MAX_BYTES)?;
    // A present malformed ledger is never reinterpreted as an interrupted copy.
    let fresh = ledger
        .as_deref()
        .map(|bytes| validate_complete_ledger(home, bytes))
        .transpose()?;
    let needs_recovery = if origin == LayoutOrigin::ExistingV2 {
        match fresh {
            None => true,
            Some(fresh) => missing_layout_provenance(&home.migrations_dir(), fresh)?.is_some(),
        }
    } else {
        has_partial_unsentinelled_projection(home)?
    };
    if !needs_recovery {
        return Ok(StartupLayout::Ordinary(origin));
    }
    // This grants only permission to inspect a locked existing volume. The
    // callback still demands its same-root complete RETIRING inventory.
    astrid_core::platform_fs::validate_private_directory(home.root())?;
    astrid_core::platform_fs::validate_private_file(&home.storage_volume_path())?;
    Ok(StartupLayout::RecoverRetiring)
}

fn has_partial_unsentinelled_projection(home: &AstridHome) -> io::Result<bool> {
    if !home.storage_volume_path().try_exists()? || home.stopped_projection_recovery()?.is_some() {
        return Ok(false);
    }
    let entries = fs::read_dir(home.root())?.collect::<Result<Vec<_>, _>>()?;
    if entries.len() == 2
        && entries
            .iter()
            .all(|entry| matches!(entry.file_name().to_str(), Some("astrid.volume" | "run")))
    {
        // With no sentinel and only canonical media plus a possible singleton,
        // Core admission is read-only: it validates the exact private lock and
        // returns StoppedVolume before permission repair. Other run contents
        // fail there; no duplicated permission or identity predicate lives here.
        home.ensure()?;
        return Ok(false);
    }
    if entries
        .iter()
        .any(|entry| entry.file_name() != "astrid.volume")
    {
        return Ok(true);
    }
    Ok(false)
}

pub(crate) fn validate_recovery(
    home: &AstridHome,
    recovery: &RuntimeProjectionRecovery<'_>,
) -> io::Result<()> {
    let sentinel = required(recovery, "etc/layout-version", 2)?;
    if sentinel.as_slice() != astrid_core::dirs::LAYOUT_VERSION.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recovery inventory does not describe layout two",
        ));
    }
    let path = ledger_path(home);
    let relative = path.strip_prefix(home.root()).map_err(io::Error::other)?;
    let name = relative
        .to_str()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "migration ledger path is not UTF-8",
            )
        })?
        .replace('\\', "/");
    let fresh = validate_complete_ledger(home, &required(recovery, &name, MAX_BYTES)?)?;
    if !fresh {
        for name in ["layout-v1-to-v2.intent", "layout-v1-to-v2.complete"] {
            let path = home.migrations_dir().join(name);
            let relative = path.strip_prefix(home.root()).map_err(io::Error::other)?;
            let name = ContentName::new(relative.to_string_lossy().replace('\\', "/"))
                .map_err(io::Error::other)?;
            let descriptor = recovery
                .describe(&name)
                .map_err(io::Error::other)?
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("RETIRING inventory lacks {name}"),
                    )
                })?;
            if descriptor.logical_bytes() == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "recovered layout provenance is empty",
                ));
            }
        }
    }
    Ok(())
}

fn required(recovery: &RuntimeProjectionRecovery<'_>, name: &str, cap: u64) -> io::Result<Vec<u8>> {
    let name = ContentName::new(name).map_err(io::Error::other)?;
    recovery
        .read(&name, cap)
        .map_err(io::Error::other)?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("RETIRING inventory lacks required {name}"),
            )
        })
}
