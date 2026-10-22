//! Fail-closed completion for mounts that never reached the durable registry.

use anyhow::{Result, bail};

pub(crate) fn preserve_launch_error(
    launch_error: anyhow::Error,
    rollback: Result<()>,
) -> anyhow::Error {
    match rollback {
        Ok(()) => launch_error,
        Err(rollback_error) => anyhow::anyhow!(
            "{launch_error:#}; failed to fully roll back unregistered FUSE mount: {rollback_error:#}"
        ),
    }
}

pub(crate) fn finish_cleanup(
    mut failures: Vec<String>,
    detach: Result<()>,
    cleanup: impl FnOnce() -> Result<()>,
) -> Result<()> {
    match detach {
        Ok(()) => {
            if let Err(error) = cleanup() {
                failures.push(format!("remove service artifacts: {error:#}"));
            }
        },
        Err(error) => failures.push(format!("detach mountpoint: {error:#}")),
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("{}", failures.join("; "))
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;

    #[test]
    fn failed_detach_retains_artifacts_and_preserves_every_failure() {
        let cleanup_called = Cell::new(false);
        let rollback = finish_cleanup(
            vec![
                "control unmount: refused".to_owned(),
                "revoke mount lease: denied".to_owned(),
            ],
            Err(anyhow::anyhow!("busy")),
            || {
                cleanup_called.set(true);
                Ok(())
            },
        );
        assert!(!cleanup_called.get());

        let failure = preserve_launch_error(
            anyhow::anyhow!("child exited").context("start detached FUSE service"),
            rollback,
        );
        let message = failure.to_string();
        for expected in [
            "start detached FUSE service: child exited",
            "control unmount: refused",
            "revoke mount lease: denied",
            "detach mountpoint: busy",
        ] {
            assert!(message.contains(expected), "missing {expected:?} in {message:?}");
        }
    }

    #[test]
    fn successful_detach_runs_cleanup_and_reports_its_failure() {
        let cleanup_called = Cell::new(false);
        let error = finish_cleanup(Vec::new(), Ok(()), || {
            cleanup_called.set(true);
            Err(anyhow::anyhow!("socket retained"))
        })
        .expect_err("artifact cleanup failure must remain visible");

        assert!(cleanup_called.get());
        assert!(
            error
                .to_string()
                .contains("remove service artifacts: socket retained")
        );
    }
}
