use super::inspect_while_fenced;
use std::fs::OpenOptions;
use std::sync::Arc;

#[test]
fn inspection_excludes_stop_and_releases_fence_before_approval() {
    for fail_inspection in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("start-fence");
        let owner = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        owner.lock().unwrap();
        let stop = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();

        let result = inspect_while_fenced(Arc::new(owner), || {
            assert!(
                stop.try_lock().is_err(),
                "stop could retire the inspected projection"
            );
            if fail_inspection {
                anyhow::bail!("inspection failure");
            }
            Ok("original-runtime-identity")
        });
        assert_eq!(result.is_err(), fail_inspection);
        stop.try_lock()
            .expect("approval or error must not retain the fence");
    }
}
