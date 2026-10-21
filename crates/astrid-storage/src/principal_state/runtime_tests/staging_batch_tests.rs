//! Native staging-batch publication boundaries.

use std::io::Write as _;

use super::super::content_staging_tests::volume_file_len;
use super::*;

#[tokio::test]
async fn duplicate_names_fail_before_physical_publication() {
    let directory = tempfile::tempdir().unwrap();
    let home = AstridHome::from_path(directory.path());
    let store = open_runtime_principal_store(&home, unlimited_quota())
        .await
        .unwrap();
    let owner = test_owner("alice");
    let name = ContentName::new("workspace/repeated.txt").unwrap();
    let mut staged = Vec::new();
    for value in [b"first version".as_slice(), b"second version".as_slice()] {
        let mut writer = store
            .staging()
            .begin(owner, name.clone(), ChunkingProfile::ASTRID_V1)
            .unwrap();
        writer.write_all(value).unwrap();
        staged.push(writer.seal().unwrap());
    }
    let volume_before = volume_file_len(&home);

    let error = store
        .publish_staged_batch(staged.clone())
        .await
        .unwrap_err();

    assert!(error.to_string().contains("repeats content name"));
    assert_eq!(volume_file_len(&home), volume_before);
    assert_eq!(store.staging().ready().unwrap(), staged);
    assert_eq!(store.content().describe(&owner, &name).unwrap(), None);
}
