//! Native header reads and workspace attempts used by the checked retry loop.
use std::sync::Arc;

use super::retry::{self, Backend, Step};
use super::{
    ContentHeader, PrincipalProjectionEngine, WorkspaceBranchError, WorkspaceBranchStore,
    WorkspaceUid,
};

struct Attempts<'a, P: Ord, E, F> {
    branches: &'a WorkspaceBranchStore<P, E>,
    attempt: F,
}

impl<P, E, T, F> Backend<P, WorkspaceUid, Arc<ContentHeader>, T, WorkspaceBranchError>
    for Attempts<'_, P, E, F>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
    F: Fn(&P, WorkspaceUid, Arc<ContentHeader>) -> Result<Step<T>, WorkspaceBranchError>,
{
    fn read(&mut self, owner: &P) -> Result<Arc<ContentHeader>, WorkspaceBranchError> {
        Ok(self.branches.content.header(owner)?)
    }

    fn apply(
        &mut self,
        owner: &P,
        id: WorkspaceUid,
        header: Arc<ContentHeader>,
    ) -> Result<Step<T>, WorkspaceBranchError> {
        (self.attempt)(owner, id, header)
    }
}

impl<P, E> WorkspaceBranchStore<P, E>
where
    P: Clone + Ord + Send + Sync,
    E: PrincipalProjectionEngine<P>,
{
    pub(super) fn retry_with_header<T>(
        &self,
        owner: &P,
        id: WorkspaceUid,
        attempt: impl Fn(&P, WorkspaceUid, Arc<ContentHeader>) -> Result<Step<T>, WorkspaceBranchError>,
    ) -> Result<T, WorkspaceBranchError> {
        retry::run(
            &mut Attempts {
                branches: self,
                attempt,
            },
            owner,
            id,
        )
    }
}
