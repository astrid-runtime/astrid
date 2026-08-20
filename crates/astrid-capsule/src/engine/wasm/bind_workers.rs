//! Run-loop `bind_workers` resolution for loopback TCP server capsules.
//!
//! `bind_workers` grants no authority — it only parameterises an already-
//! granted TCP `net_bind`. Unix-only capsules, interceptors, and
//! `host_process` capsules stay at one worker.

use crate::manifest::CapabilitiesDef;

/// True when `net_bind` includes at least one TCP allowlist entry.
///
/// Unix socket entries (`unix:*`, `unix:///tmp/sock`, …) never qualify.
/// Empty strings are malformed and ignored. A mixed unix+TCP allowlist
/// still qualifies because a TCP bind is possible.
pub(crate) fn has_tcp_net_bind(net_bind: &[String]) -> bool {
    net_bind
        .iter()
        .any(|entry| !entry.is_empty() && !entry.starts_with("unix:"))
}

/// How many dedicated run-loop worker Stores to instantiate.
///
/// Returns 1 unless the capsule is a run-loop TCP server with no
/// `host_process` and no interceptors. Requested `bind_workers` is clamped
/// to `[1, instance_pool_size]`.
///
/// That ceiling is the interceptor-pool max, reused on purpose until a
/// dedicated `bind_workers` knob exists in `astrid-config`. A second silent
/// ceiling would lie.
pub(crate) fn resolve_run_loop_worker_count(
    capsule: &str,
    has_run_export: bool,
    capabilities: &CapabilitiesDef,
    has_interceptors: bool,
    instance_pool_size: usize,
) -> usize {
    if !has_run_export
        || !capabilities.host_process.is_empty()
        || !has_tcp_net_bind(&capabilities.net_bind)
    {
        return 1;
    }
    // Intentional clamp onto interceptor `instance_pool_size` until a
    // dedicated bind_workers knob exists. Do not invent a second silent
    // ceiling beside this one.
    let requested = capabilities
        .bind_workers
        .unwrap_or(1)
        .clamp(1, instance_pool_size);
    if requested > 1 && has_interceptors {
        tracing::warn!(
            capsule = %capsule,
            requested,
            "bind_workers > 1 ignored: capsule declares interceptors (N subscriptions would double-process events); using 1 worker"
        );
        1
    } else {
        requested
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(
        net_bind: &[&str],
        bind_workers: Option<usize>,
        host_process: &[&str],
    ) -> CapabilitiesDef {
        CapabilitiesDef {
            net_bind: net_bind.iter().map(|entry| (*entry).to_string()).collect(),
            bind_workers,
            host_process: host_process
                .iter()
                .map(|entry| (*entry).to_string())
                .collect(),
            ..CapabilitiesDef::default()
        }
    }

    #[test]
    fn unix_only_net_bind_stays_at_one_worker() {
        for net_bind in [
            caps(&["unix:*"], Some(4), &[]),
            caps(&["unix:///tmp/sock"], Some(8), &[]),
        ] {
            assert_eq!(
                resolve_run_loop_worker_count("cli", true, &net_bind, false, 16),
                1
            );
        }
    }

    #[test]
    fn interceptor_clamp_stays_at_one_worker() {
        let capabilities = caps(&["127.0.0.1:8799"], Some(4), &[]);
        assert_eq!(
            resolve_run_loop_worker_count("svc", true, &capabilities, true, 16),
            1
        );
    }

    #[test]
    fn tcp_run_loop_honours_requested_workers() {
        let capabilities = caps(&["127.0.0.1:8799"], Some(4), &[]);
        assert_eq!(
            resolve_run_loop_worker_count("svc", true, &capabilities, false, 16),
            4
        );
    }

    #[test]
    fn mixed_unix_and_tcp_still_qualifies() {
        let capabilities = caps(&["unix:*", "127.0.0.1:8799"], Some(3), &[]);
        assert_eq!(
            resolve_run_loop_worker_count("svc", true, &capabilities, false, 16),
            3
        );
    }

    #[test]
    fn empty_or_malformed_net_bind_is_not_tcp() {
        assert!(!has_tcp_net_bind(&[]));
        assert!(!has_tcp_net_bind(&[String::new(), "unix:*".into()]));
        assert!(has_tcp_net_bind(&["127.0.0.1:*".into()]));
    }

    #[test]
    fn host_process_or_missing_run_export_stays_at_one() {
        let tcp = caps(&["127.0.0.1:8799"], Some(4), &["/bin/true"]);
        assert_eq!(
            resolve_run_loop_worker_count("svc", true, &tcp, false, 16),
            1
        );
        let tcp = caps(&["127.0.0.1:8799"], Some(4), &[]);
        assert_eq!(
            resolve_run_loop_worker_count("svc", false, &tcp, false, 16),
            1
        );
    }

    #[test]
    fn instance_pool_size_is_the_intentional_ceiling() {
        let capabilities = caps(&["127.0.0.1:8799"], Some(99), &[]);
        assert_eq!(
            resolve_run_loop_worker_count("svc", true, &capabilities, false, 8),
            8
        );
    }
}
