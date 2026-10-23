//! Expected selector changes are computed from the authenticated prior state,
//! independently of the subsequent path-copy edits.

use super::{
    BTreeMap, BranchState, CatalogRoot, ContentName, ObjectId, ObjectRecord, PrincipalContentError,
    PrincipalProjectionEngine, WorkspaceBranchError, WorkspaceBranchStore, WorkspaceLayout,
    binding_key, decode_row, inventory_prefix, tree,
};

impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(super) fn plan_selectors(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
        records: &BTreeMap<ObjectId, ObjectRecord>,
        old: Option<&BranchState>,
        replacement: Option<(ObjectId, bool)>,
    ) -> Result<BTreeMap<ContentName, Option<ObjectId>>, WorkspaceBranchError> {
        let new = replacement
            .map(|(object, _)| {
                let (branch, _) = decode_row(
                    object,
                    &self.directory_load_pending(owner, object, records)?,
                )?;
                Ok::<_, WorkspaceBranchError>((branch, object))
            })
            .transpose()?;
        let new_binding = new
            .as_ref()
            .map(|(branch, _)| binding_key(branch))
            .transpose()?
            .flatten();
        let mut expected = BTreeMap::new();
        if let Some(old) = old
            && let Some(binding) = binding_key(old)?
        {
            let selected = self
                .directory_lookup_pending(owner, root, &binding, records)?
                .map(|value| value.file);
            let selected_id = selected
                .map(|object| {
                    decode_row(
                        object,
                        &self.directory_load_pending(owner, object, records)?,
                    )
                    .map(|(branch, _)| branch.id)
                })
                .transpose()?;
            let next = if new_binding.as_ref() == Some(&binding) {
                new.as_ref().map(|(_, object)| *object)
            } else if selected_id == Some(old.id) {
                self.remaining_selector(owner, root, records, old)?
            } else {
                selected
            };
            expected.insert(binding, next);
        }
        if let Some(binding) = new_binding {
            expected.insert(binding, new.map(|(_, object)| object));
        }
        Ok(expected)
    }

    fn remaining_selector(
        &self,
        owner: &P,
        root: Option<CatalogRoot>,
        records: &BTreeMap<ObjectId, ObjectRecord>,
        previous: &BranchState,
    ) -> Result<Option<ObjectId>, WorkspaceBranchError> {
        let Some(uid) = previous.binding_uid else {
            return Ok(None);
        };
        let prefix =
            ContentName::new(inventory_prefix(uid)).map_err(PrincipalContentError::InvalidName)?;
        let siblings =
            tree::list_prefix_with_layout::<WorkspaceLayout>(root, &prefix, &mut |object| {
                self.directory_load_pending(owner, object, records)
            })?;
        let mut candidate = None;
        for entry in siblings {
            let (branch, promoted) = decode_row(
                entry.file(),
                &self.directory_load_pending(owner, entry.file(), records)?,
            )?;
            if branch.id != previous.id
                && branch.target_prefix == previous.target_prefix
                && (candidate.is_none() || !promoted)
            {
                candidate = Some(entry.file());
                if !promoted {
                    break;
                }
            }
        }
        Ok(candidate)
    }
}
