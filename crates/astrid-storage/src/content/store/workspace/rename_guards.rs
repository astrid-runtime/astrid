use std::collections::BTreeSet;

use crate::content::{ContentName, PrincipalContentError};
use crate::engine::PrincipalProjectionEngine;

use super::{
    CatalogRoot, FilesystemPath, WorkspaceBranchError, WorkspaceBranchStore, list_prefix, lookup,
    prefix_exists,
};

pub(super) struct RenamePlan<'a> {
    pub(super) moves: &'a [(ContentName, ContentName)],
    pub(super) replacements: &'a [ContentName],
    pub(super) source_prefix: Option<&'a str>,
    pub(super) destination_prefix: &'a str,
    pub(super) destination_name: &'a ContentName,
    pub(super) destination_parent: &'a FilesystemPath,
}

pub(super) enum RenameBatchOutcome {
    Committed,
    DestinationConflict,
    Replan,
}

impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// A rename plan may only commit against the subtree it enumerated.
    /// Root-conflict retries must replan if either namespace changed.
    pub(super) fn rename_membership_matches(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
        plan: &RenamePlan<'_>,
        sources: &BTreeSet<&ContentName>,
        replacements: &BTreeSet<&ContentName>,
    ) -> Result<bool, WorkspaceBranchError> {
        if let Some(prefix) = plan.source_prefix {
            let prefix =
                ContentName::new(prefix.to_owned()).map_err(PrincipalContentError::InvalidName)?;
            let current = list_prefix(root, &prefix, &mut |object| {
                self.content.load_required_for(owner, object)
            })?;
            if current
                .iter()
                .map(crate::content::ContentEntry::name)
                .collect::<BTreeSet<_>>()
                != *sources
            {
                return Ok(false);
            }
        }
        let prefix = ContentName::new(plan.destination_prefix.to_owned())
            .map_err(PrincipalContentError::InvalidName)?;
        let current = list_prefix(root, &prefix, &mut |object| {
            self.content.load_required_for(owner, object)
        })?;
        if current
            .iter()
            .any(|entry| !replacements.contains(entry.name()))
        {
            return Ok(false);
        }
        let destination_file = lookup(root, plan.destination_name, &mut |object| {
            self.content.load_required_for(owner, object)
        })?;
        if destination_file.is_some() && !replacements.contains(plan.destination_name) {
            return Ok(false);
        }
        if !plan.destination_parent.as_str().is_empty() {
            if lookup(root, &plan.destination_parent.file_name()?, &mut |object| {
                self.content.load_required_for(owner, object)
            })?
            .is_some()
            {
                return Ok(false);
            }
            let marker = lookup(
                root,
                &plan.destination_parent.directory_marker()?,
                &mut |object| self.content.load_required_for(owner, object),
            )?
            .is_some();
            let prefix = ContentName::new(plan.destination_parent.directory_prefix())
                .map_err(PrincipalContentError::InvalidName)?;
            let implied = prefix_exists(root, &prefix, &mut |object| {
                self.content.load_required_for(owner, object)
            })?;
            if !marker && !implied {
                return Ok(false);
            }
        }
        Ok(true)
    }
}
