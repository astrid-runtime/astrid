use super::{
    ContentEntry, ContentName, EngineIdentity, EngineSource, PrincipalContentError,
    PrincipalProjectionEngine, WorkspaceBranchError, WorkspaceBranchStore, WorkspaceUid,
    build_content, catalog_list_prefix, catalog_prefix_exists, list, lookup, map_read_error,
    open_content, read_opened_content, read_opened_content_range,
};

#[allow(clippy::missing_errors_doc)]
impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    /// Read one complete immutable branch file.
    pub fn read(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
    ) -> Result<Option<Vec<u8>>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        let Some(value) = lookup(branch.working, name, &mut |object| {
            self.content.load_required_for(owner, object)
        })?
        else {
            return Ok(None);
        };
        let source = EngineSource::<P, E>::new(self.content.engine.as_ref(), owner);
        let opened = open_content(&source, value.file).map_err(map_read_error)?;
        read_opened_content(&source, opened)
            .map(Some)
            .map_err(map_read_error)
    }

    /// Read an exact range from one immutable branch file.
    pub fn read_range(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
        offset: u64,
        length: u64,
    ) -> Result<Option<Vec<u8>>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        let Some(value) = lookup(branch.working, name, &mut |object| {
            self.content.load_required_for(owner, object)
        })?
        else {
            return Ok(None);
        };
        let source = EngineSource::<P, E>::new(self.content.engine.as_ref(), owner);
        let opened = open_content(&source, value.file).map_err(map_read_error)?;
        read_opened_content_range(&source, opened, offset, length)
            .map(Some)
            .map_err(map_read_error)
    }

    /// List all named values in a branch's current immutable catalog.
    pub fn list(
        &self,
        owner: &P,
        id: WorkspaceUid,
    ) -> Result<Vec<ContentEntry>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        list(branch.working, &mut |object| {
            self.content.load_required_for(owner, object)
        })
        .map_err(Into::into)
    }

    /// Describe one named value in a branch without listing the catalog.
    pub fn describe_name(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
    ) -> Result<Option<ContentEntry>, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        Ok(lookup(branch.working, name, &mut |object| {
            self.content.load_required_for(owner, object)
        })?
        .map(|value| ContentEntry::new(name.clone(), value.file, value.logical_bytes)))
    }

    /// List names in a branch that begin with `prefix`.
    pub fn list_prefix(
        &self,
        owner: &P,
        id: WorkspaceUid,
        prefix: &str,
    ) -> Result<Vec<ContentEntry>, WorkspaceBranchError> {
        if prefix.is_empty() {
            return self.list(owner, id);
        }
        let prefix =
            ContentName::new(prefix.to_owned()).map_err(PrincipalContentError::InvalidName)?;
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        catalog_list_prefix(branch.working, &prefix, &mut |object| {
            self.content.load_required_for(owner, object)
        })
        .map_err(Into::into)
    }

    /// Return whether any branch name begins with `prefix`.
    pub fn prefix_exists(
        &self,
        owner: &P,
        id: WorkspaceUid,
        prefix: &str,
    ) -> Result<bool, WorkspaceBranchError> {
        if prefix.is_empty() {
            let header = self.content.header(owner)?;
            let branch = self.branch(owner, &header, id)?;
            return Ok(branch
                .working
                .is_some_and(|catalog| catalog.summary.entries > 0));
        }
        let prefix =
            ContentName::new(prefix.to_owned()).map_err(PrincipalContentError::InvalidName)?;
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        catalog_prefix_exists(branch.working, &prefix, &mut |object| {
            self.content.load_required_for(owner, object)
        })
        .map_err(Into::into)
    }

    /// Publish complete file bytes into a branch view.
    pub fn write(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
        bytes: &[u8],
    ) -> Result<(), WorkspaceBranchError> {
        let built = build_content(
            &EngineIdentity::<P, E>::new(self.content.engine.as_ref()),
            crate::content_dag::ChunkingProfile::ASTRID_V1,
            bytes,
        )?;
        let file = built.descriptor().file();
        let logical_bytes = built.descriptor().logical_bytes();
        self.mutate_catalog(owner, id, Some(&built), |root, records| {
            let mutation = super::super::insert(
                root,
                name,
                super::super::CatalogValue {
                    file,
                    logical_bytes,
                },
                &mut |object| self.content.load_required_for(owner, object),
                &|record| self.content.engine.identify_object(record),
            )?;
            records.extend(mutation.records);
            Ok(mutation.root)
        })
    }

    /// Publish streamed bytes after branch quota authorization.
    ///
    /// # Errors
    ///
    /// Returns source, content, quota, or branch publication errors.
    pub fn write_streaming<R: std::io::Read>(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
        source: R,
    ) -> Result<(), WorkspaceBranchError> {
        // Defer admission until the existing branch transaction checks quota.
        let profile = crate::content_dag::ChunkingProfile::ASTRID_V1;
        let (verified, staged) =
            if let Some((bound, limit)) = self.content.quota_staging_bound(owner)? {
                self.content
                    .stage_deferred_bounded(source, profile, bound, limit)?
            } else {
                self.content.stage_deferred(source, profile)?
            };
        let descriptor = verified.descriptor();
        self.mutate_catalog(owner, id, None, |root, records| {
            let mutation = super::super::insert(
                root,
                name,
                super::super::CatalogValue {
                    file: descriptor.file(),
                    logical_bytes: descriptor.logical_bytes(),
                },
                &mut |object| self.content.load_required_for(owner, object),
                &|record| self.content.engine.identify_object(record),
            )?;
            records.extend(
                staged
                    .iter()
                    .cloned()
                    .map(|record| (self.content.engine.identify_object(&record), record)),
            );
            records.extend(mutation.records);
            Ok(mutation.root)
        })
    }

    /// Remove one named file from a branch.  Directory markers are treated as
    /// ordinary named values by this lower-level API; the filesystem wrapper
    /// enforces directory semantics.
    pub fn remove_name(
        &self,
        owner: &P,
        id: WorkspaceUid,
        name: &ContentName,
    ) -> Result<bool, WorkspaceBranchError> {
        let header = self.content.header(owner)?;
        let branch = self.branch(owner, &header, id)?;
        let exists = lookup(branch.working, name, &mut |object| {
            self.content.load_required_for(owner, object)
        })?
        .is_some();
        if !exists {
            return Ok(false);
        }
        self.mutate_catalog(owner, id, None, |root, records| {
            let mutation = super::super::delete(
                root,
                name,
                &mut |object| self.content.load_required_for(owner, object),
                &|record| self.content.engine.identify_object(record),
            )?;
            records.extend(mutation.records);
            Ok(mutation.root)
        })?;
        Ok(true)
    }
}
