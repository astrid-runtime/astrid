//! Admission diagnostics before volume-backed logging policy is available.

use std::future::Future;

use tracing::instrument::WithSubscriber;

pub(super) async fn trace_admission<F: Future>(verbose: bool, admission: F) -> F::Output {
    // Poll-local dispatch does not claim the global subscriber or create host
    // files before restore. The admitted policy can configure logging once
    // afterwards. A thread-local guard held across await would misattribute
    // diagnostics when Tokio moves this future to another worker.
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    let subscriber = tracing_subscriber::fmt()
        .compact()
        .with_max_level(level)
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .finish();
    admission.with_subscriber(subscriber).await
}

#[cfg(test)]
mod tests {
    use super::trace_admission;

    #[tokio::test]
    async fn admission_verbose_filter_survives_a_yield_without_global_initialization() {
        for verbose in [false, true] {
            trace_admission(verbose, async {
                assert!(tracing::enabled!(tracing::Level::INFO));
                assert_eq!(tracing::enabled!(tracing::Level::DEBUG), verbose);
                tokio::task::yield_now().await;
                assert!(tracing::enabled!(tracing::Level::INFO));
                assert_eq!(tracing::enabled!(tracing::Level::DEBUG), verbose);
            })
            .await;
        }
    }
}
