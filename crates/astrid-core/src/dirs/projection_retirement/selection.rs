//! Selection is a validated plan, never authority to adopt newly seen names.

use super::CANONICAL_VOLUME;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::{Component, Path, PathBuf};

#[derive(Default)]
pub(super) struct SelectedDirectories {
    selected: bool,
    children: BTreeMap<OsString, Self>,
}

#[derive(Clone, Copy)]
pub(super) enum RetirementMode<'a> {
    Full,
    Empty,
    Partial(&'a SelectedDirectories),
    Keep,
}

impl SelectedDirectories {
    pub(super) fn parse(paths: &[PathBuf]) -> io::Result<Self> {
        let mut root = Self::default();
        for path in paths {
            let names = normal_components(path)?;
            let mut node = &mut root;
            for name in names {
                if node.selected {
                    return Err(invalid_selection());
                }
                node = node.children.entry(name).or_default();
            }
            if node.selected || !node.children.is_empty() {
                return Err(invalid_selection());
            }
            node.selected = true;
        }
        Ok(root)
    }

    pub(super) fn children(&self) -> impl Iterator<Item = (&OsString, &Self)> {
        self.children.iter()
    }

    pub(super) fn mode(&self) -> RetirementMode<'_> {
        if self.selected {
            RetirementMode::Empty
        } else {
            RetirementMode::Partial(self)
        }
    }
}

impl RetirementMode<'_> {
    pub(super) fn child(self, name: &OsStr) -> Self {
        match self {
            Self::Full | Self::Empty => self,
            Self::Partial(node) => node
                .children
                .get(name)
                .map_or(Self::Keep, SelectedDirectories::mode),
            Self::Keep => Self::Keep,
        }
    }
    pub(super) fn removes(self) -> bool {
        matches!(self, Self::Full | Self::Empty)
    }
    pub(super) fn empty(self) -> bool {
        matches!(self, Self::Empty)
    }
    pub(super) fn partial(self) -> bool {
        matches!(self, Self::Partial(_))
    }
    #[cfg(unix)]
    pub(super) fn full(self) -> bool {
        matches!(self, Self::Full)
    }
    // Absence may follow a failed final fence on a prior attempt. Commit it
    // through the nearest existing retained parent even when no unlink remains.
    pub(super) fn needs_fence(self, mut exists: impl FnMut(&OsStr) -> bool) -> bool {
        match self {
            Self::Partial(node) => node
                .children
                .iter()
                .any(|(name, child)| child.selected || !exists(name)),
            _ => false,
        }
    }
    pub(super) fn visits(self) -> bool {
        !matches!(self, Self::Keep)
    }
}

fn normal_components(path: &Path) -> io::Result<Vec<OsString>> {
    let names = path
        .components()
        .map(|part| match part {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(invalid_selection()),
        })
        .collect::<io::Result<Vec<_>>>()?;
    let abnormal = path
        .as_os_str()
        .as_encoded_bytes()
        .split(|byte| *byte == b'/' || cfg!(windows) && *byte == b'\\')
        .any(|part| {
            part.is_empty()
                || part == b"."
                || part == b".."
                || part.contains(&0)
                || cfg!(windows) && part.contains(&b':')
        });
    if names.is_empty()
        || abnormal
        || names.first().is_some_and(|name| {
            name.as_os_str() == OsStr::new(CANONICAL_VOLUME)
                || cfg!(windows)
                    && name
                        .to_string_lossy()
                        .eq_ignore_ascii_case(CANONICAL_VOLUME)
        })
    {
        return Err(invalid_selection());
    }
    Ok(names)
}

fn invalid_selection() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "retirement targets must be disjoint normal relative directories outside the canonical volume",
    )
}
