//! Capability-gated control plane for generic core-Wasm compute workers.

use async_trait::async_trait;
use wasmtime::component::Resource;
use wasmtime_wasi::p2::{DynPollable, Pollable, subscribe};

use crate::HostAuditOutcome;
use crate::engine::wasm::bindings::astrid::compute::host::{
    self as compute, Accounting, ErrorCode, ExecutionMode, GroupInfo, GroupRequest, JobResult,
    JobState, JobStatus, Parallelism, WorkDescriptor,
};
use crate::engine::wasm::host_state::HostState;

const MAX_CONTROL_TRANSFER_BYTES: usize = 1024 * 1024;

fn audit_compute(state: &HostState, operation: &str, worker: &str, outcome: HostAuditOutcome<'_>) {
    if let Some(sink) = state.audit_sink.as_ref() {
        sink.record_compute(
            &state.effective_principal(),
            state.capsule_id.as_str(),
            operation,
            worker,
            outcome,
        );
    }
}

fn map_error(error: astrid_compute::ComputeError) -> ErrorCode {
    match error {
        astrid_compute::ComputeError::InvalidInput(detail) => ErrorCode::InvalidInput(detail),
        astrid_compute::ComputeError::WorkerInvalid(detail) => ErrorCode::WorkerInvalid(detail),
        astrid_compute::ComputeError::Quota => ErrorCode::Quota,
        astrid_compute::ComputeError::Busy => ErrorCode::Busy,
        astrid_compute::ComputeError::Cancelled => ErrorCode::Cancelled,
        astrid_compute::ComputeError::WorkerFailed(detail) => ErrorCode::WorkerFailed(detail),
        astrid_compute::ComputeError::Closed => ErrorCode::Closed,
    }
}

fn principal_compute_limits(
    quotas: &astrid_core::Quotas,
    resource_exempt: bool,
) -> astrid_compute::PrincipalComputeLimits {
    if resource_exempt {
        return astrid_compute::PrincipalComputeLimits::default();
    }
    astrid_compute::PrincipalComputeLimits {
        max_workers: (quotas.max_compute_workers != 0).then_some(quotas.max_compute_workers),
        max_memory_bytes: Some(quotas.max_memory_bytes),
        max_job_fuel: None,
        max_fuel_per_sec: (quotas.max_cpu_fuel_per_sec != 0).then_some(quotas.max_cpu_fuel_per_sec),
    }
}

fn execution_mode(mode: ExecutionMode) -> astrid_compute::ExecutionMode {
    match mode {
        ExecutionMode::Deterministic => astrid_compute::ExecutionMode::Deterministic,
        ExecutionMode::Parallel => astrid_compute::ExecutionMode::Parallel,
    }
}

fn parallelism(value: Parallelism) -> astrid_compute::Parallelism {
    match value {
        Parallelism::Auto => astrid_compute::Parallelism::Auto,
        Parallelism::Exact(count) => astrid_compute::Parallelism::Exact(count),
        Parallelism::AtMost(count) => astrid_compute::Parallelism::AtMost(count),
    }
}

fn job_state(state: astrid_compute::JobState) -> JobState {
    match state {
        astrid_compute::JobState::Queued => JobState::Queued,
        astrid_compute::JobState::Running => JobState::Running,
        astrid_compute::JobState::Completed => JobState::Completed,
        astrid_compute::JobState::Cancelled => JobState::Cancelled,
        astrid_compute::JobState::Failed => JobState::Failed,
    }
}

fn job_result(result: astrid_compute::JobResult) -> JobResult {
    JobResult {
        state: job_state(result.state),
        worker_index: result.worker_index,
        worker_status: result.worker_status,
        fuel_consumed: result.fuel_consumed,
        elapsed_ns: u64::try_from(result.elapsed.as_nanos()).unwrap_or(u64::MAX),
    }
}

fn accounting(value: astrid_compute::GroupAccounting) -> Accounting {
    Accounting {
        workers_reserved: value.workers_reserved,
        memory_bytes_current: value.memory_bytes_current,
        memory_bytes_peak: value.memory_bytes_peak,
        jobs_submitted: value.jobs_submitted,
        jobs_completed: value.jobs_completed,
        jobs_cancelled: value.jobs_cancelled,
        jobs_failed: value.jobs_failed,
        fuel_consumed: value.fuel_consumed,
    }
}

fn group_for_principal<'a>(
    state: &'a HostState,
    resource: &Resource<astrid_compute::ComputeGroup>,
    operation: &str,
) -> Result<&'a astrid_compute::ComputeGroup, ErrorCode> {
    let group = state
        .resource_table
        .get(resource)
        .map_err(|_| ErrorCode::Closed)?;
    if group.principal() != &state.effective_principal() {
        audit_compute(
            state,
            operation,
            group.worker_id(),
            HostAuditOutcome::Denied("compute group belongs to another principal"),
        );
        return Err(ErrorCode::CapabilityDenied);
    }
    Ok(group)
}

fn job_for_principal<'a>(
    state: &'a HostState,
    resource: &Resource<astrid_compute::ComputeJob>,
    operation: &str,
) -> Result<&'a astrid_compute::ComputeJob, ErrorCode> {
    let job = state
        .resource_table
        .get(resource)
        .map_err(|_| ErrorCode::Closed)?;
    if job.principal() != &state.effective_principal() {
        audit_compute(
            state,
            operation,
            job.worker_id(),
            HostAuditOutcome::Denied("compute job belongs to another principal"),
        );
        return Err(ErrorCode::CapabilityDenied);
    }
    Ok(job)
}

struct JobReadiness {
    job: astrid_compute::ComputeJob,
}

#[async_trait]
impl Pollable for JobReadiness {
    async fn ready(&mut self) {
        while matches!(
            self.job.state(),
            astrid_compute::JobState::Queued | astrid_compute::JobState::Running
        ) {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

impl compute::Host for HostState {
    fn open(
        &mut self,
        request: GroupRequest,
    ) -> Result<Resource<astrid_compute::ComputeGroup>, ErrorCode> {
        if !self.capability_names.iter().any(|name| name == "compute") {
            audit_compute(
                self,
                "open",
                &request.worker,
                HostAuditOutcome::Denied("no declared compute-worker capability"),
            );
            return Err(ErrorCode::CapabilityDenied);
        }
        let Some(runtime) = self.compute_runtime.as_ref() else {
            audit_compute(
                self,
                "open",
                &request.worker,
                HostAuditOutcome::Denied("compute runtime unavailable"),
            );
            return Err(ErrorCode::CapabilityDenied);
        };
        let Some(artifact) = self.compute_workers.get(&request.worker) else {
            audit_compute(
                self,
                "open",
                &request.worker,
                HostAuditOutcome::Denied("worker object capability not held"),
            );
            return Err(ErrorCode::NoSuchWorker);
        };
        let principal = self.effective_principal();
        let principal_limits = principal_compute_limits(
            &self.effective_profile().quotas,
            self.invocation_resource_exempt,
        );
        let group = match runtime.open_group_with_limits(
            &principal,
            artifact,
            astrid_compute::GroupRequest {
                mode: execution_mode(request.mode),
                parallelism: parallelism(request.parallelism),
                initial_memory_pages: request.initial_memory_pages,
                maximum_memory_pages: request.maximum_memory_pages,
            },
            principal_limits,
        ) {
            Ok(group) => group,
            Err(error) => {
                let detail = error.to_string();
                audit_compute(
                    self,
                    "open",
                    &request.worker,
                    HostAuditOutcome::Failed(&detail),
                );
                return Err(map_error(error));
            },
        };
        tracing::debug!(
            target: "astrid.audit.compute",
            %principal,
            capsule = %self.capsule_id,
            worker = %request.worker,
            workers = group.parallelism(),
            "compute group opened"
        );
        match self.resource_table.push(group) {
            Ok(resource) => {
                audit_compute(self, "open", &request.worker, HostAuditOutcome::Allowed);
                Ok(resource)
            },
            Err(error) => {
                let detail = error.to_string();
                audit_compute(
                    self,
                    "open",
                    &request.worker,
                    HostAuditOutcome::Failed(&detail),
                );
                Err(ErrorCode::Unknown(detail))
            },
        }
    }
}

impl compute::HostComputeGroup for HostState {
    fn info(
        &mut self,
        self_: Resource<astrid_compute::ComputeGroup>,
    ) -> Result<GroupInfo, ErrorCode> {
        let group = group_for_principal(self, &self_, "info")?;
        Ok(GroupInfo {
            worker: group.worker_id().to_owned(),
            mode: match group.mode() {
                astrid_compute::ExecutionMode::Deterministic => ExecutionMode::Deterministic,
                astrid_compute::ExecutionMode::Parallel => ExecutionMode::Parallel,
            },
            parallelism: group.parallelism(),
            memory_pages: group.memory_pages(),
            maximum_memory_pages: group.maximum_memory_pages(),
            queued_jobs: group.queued_jobs(),
            running_jobs: group.running_jobs(),
            usage: accounting(group.accounting()),
        })
    }

    fn read(
        &mut self,
        self_: Resource<astrid_compute::ComputeGroup>,
        offset: u64,
        length: u32,
    ) -> Result<Vec<u8>, ErrorCode> {
        if usize::try_from(length).map_err(|_| ErrorCode::TooLarge)? > MAX_CONTROL_TRANSFER_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        group_for_principal(self, &self_, "read")?
            .read(offset, length)
            .map_err(map_error)
    }

    fn write(
        &mut self,
        self_: Resource<astrid_compute::ComputeGroup>,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<(), ErrorCode> {
        if data.len() > MAX_CONTROL_TRANSFER_BYTES {
            return Err(ErrorCode::TooLarge);
        }
        group_for_principal(self, &self_, "write")?
            .write(offset, &data)
            .map_err(map_error)
    }

    fn grow(
        &mut self,
        self_: Resource<astrid_compute::ComputeGroup>,
        delta_pages: u32,
    ) -> Result<u32, ErrorCode> {
        group_for_principal(self, &self_, "grow")?
            .grow(delta_pages)
            .map_err(map_error)
    }

    fn submit(
        &mut self,
        self_: Resource<astrid_compute::ComputeGroup>,
        descriptor: WorkDescriptor,
    ) -> Result<Resource<astrid_compute::ComputeJob>, ErrorCode> {
        let group = group_for_principal(self, &self_, "submit")?;
        let worker = group.worker_id().to_owned();
        let job = match group.submit(astrid_compute::WorkDescriptor {
            offset: descriptor.offset,
            length: descriptor.length,
            tag: descriptor.tag,
            worker_index: descriptor.worker_index,
            fuel: descriptor.fuel,
        }) {
            Ok(job) => job,
            Err(error) => {
                let detail = error.to_string();
                audit_compute(self, "submit", &worker, HostAuditOutcome::Failed(&detail));
                return Err(map_error(error));
            },
        };
        match self.resource_table.push(job) {
            Ok(resource) => {
                audit_compute(self, "submit", &worker, HostAuditOutcome::Allowed);
                Ok(resource)
            },
            Err(error) => {
                let detail = error.to_string();
                audit_compute(self, "submit", &worker, HostAuditOutcome::Failed(&detail));
                Err(ErrorCode::Unknown(format!(
                    "store compute job resource: {detail}"
                )))
            },
        }
    }

    fn cancel(&mut self, self_: Resource<astrid_compute::ComputeGroup>) -> Result<(), ErrorCode> {
        let worker = {
            let group = group_for_principal(self, &self_, "cancel")?;
            group.cancel();
            group.worker_id().to_owned()
        };
        audit_compute(self, "cancel", &worker, HostAuditOutcome::Allowed);
        Ok(())
    }

    fn drop(&mut self, rep: Resource<astrid_compute::ComputeGroup>) -> wasmtime::Result<()> {
        let borrowed = Resource::new_borrow(rep.rep());
        let Ok(group) = group_for_principal(self, &borrowed, "drop") else {
            return Ok(());
        };
        let worker = group.worker_id().to_owned();
        let deleted = self
            .resource_table
            .delete::<astrid_compute::ComputeGroup>(Resource::new_own(rep.rep()))
            .is_ok();
        if deleted {
            audit_compute(self, "drop", &worker, HostAuditOutcome::Allowed);
        }
        Ok(())
    }
}

impl compute::HostJob for HostState {
    fn status(
        &mut self,
        self_: Resource<astrid_compute::ComputeJob>,
    ) -> Result<JobStatus, ErrorCode> {
        let job = job_for_principal(self, &self_, "job-status")?;
        Ok(JobStatus {
            state: job_state(job.state()),
            worker_index: job.worker_index(),
        })
    }

    fn subscribe(&mut self, self_: Resource<astrid_compute::ComputeJob>) -> Resource<DynPollable> {
        let Ok(job) = job_for_principal(self, &self_, "job-subscribe").cloned() else {
            return super::stubs::always_ready_pollable(&mut self.resource_table);
        };
        let Ok(readiness) = self.resource_table.push(JobReadiness { job }) else {
            return super::stubs::always_ready_pollable(&mut self.resource_table);
        };
        subscribe(&mut self.resource_table, readiness)
            .unwrap_or_else(|_| super::stubs::always_ready_pollable(&mut self.resource_table))
    }

    async fn join(
        &mut self,
        self_: Resource<astrid_compute::ComputeJob>,
    ) -> Result<JobResult, ErrorCode> {
        let job = job_for_principal(self, &self_, "job-join")?.clone();
        tokio::task::spawn_blocking(move || job.join())
            .await
            .map_err(|error| ErrorCode::WorkerFailed(error.to_string()))?
            .map(job_result)
            .map_err(map_error)
    }

    fn cancel(&mut self, self_: Resource<astrid_compute::ComputeJob>) -> Result<(), ErrorCode> {
        job_for_principal(self, &self_, "job-cancel")?.cancel();
        Ok(())
    }

    fn drop(&mut self, rep: Resource<astrid_compute::ComputeJob>) -> wasmtime::Result<()> {
        let borrowed = Resource::new_borrow(rep.rep());
        if job_for_principal(self, &borrowed, "job-drop").is_err() {
            return Ok(());
        }
        let _ = self
            .resource_table
            .delete::<astrid_compute::ComputeJob>(Resource::new_own(rep.rep()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::wasm::test_fixtures::minimal_host_state;

    fn worker() -> astrid_compute::WorkerArtifact {
        let bytes = wat::parse_str(
            r#"(module
                (memory (import "astrid_compute" "memory") 1 32 shared)
                (func (export "astrid_compute_abi_version") (result i32)
                    i32.const 1)
                (func (export "astrid_compute_run")
                    (param i32 i64 i64 i64) (result i32)
                    i32.const 42)
            )"#,
        )
        .expect("worker WAT parses");
        let digest = format!("blake3:{}", blake3::hash(&bytes).to_hex());
        astrid_compute::WorkerArtifact::from_bytes("cpu", bytes, &digest)
            .expect("worker digest matches")
    }

    fn request(worker: &str) -> GroupRequest {
        GroupRequest {
            worker: worker.to_owned(),
            mode: ExecutionMode::Deterministic,
            parallelism: Parallelism::Auto,
            initial_memory_pages: 1,
            maximum_memory_pages: 32,
        }
    }

    #[test]
    fn profile_compute_worker_quota_delegates_or_clamps() {
        let mut quotas = astrid_core::Quotas::default();
        assert_eq!(principal_compute_limits(&quotas, false).max_workers, None);
        quotas.max_compute_workers = 3;
        let bounded = principal_compute_limits(&quotas, false);
        assert_eq!(bounded.max_workers, Some(3));
        assert_eq!(bounded.max_memory_bytes, Some(quotas.max_memory_bytes));
        assert_eq!(bounded.max_fuel_per_sec, None);
        quotas.max_cpu_fuel_per_sec = 9000;
        assert_eq!(
            principal_compute_limits(&quotas, false).max_fuel_per_sec,
            Some(9000)
        );
        assert_eq!(
            principal_compute_limits(&quotas, true),
            astrid_compute::PrincipalComputeLimits::default()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn host_boundary_is_capability_gated_and_executes_declared_worker() {
        let mut state = minimal_host_state(tokio::runtime::Handle::current());
        state.principal = astrid_core::PrincipalId::new("alice").expect("valid principal");
        assert!(matches!(
            <HostState as compute::Host>::open(&mut state, request("cpu")),
            Err(ErrorCode::CapabilityDenied)
        ));

        state.capability_names.push("compute".to_owned());
        state.compute_runtime = Some(std::sync::Arc::new(
            astrid_compute::ComputeRuntime::new(
                astrid_compute::ComputeLedger::default(),
                astrid_compute::ComputeLimits::default(),
            )
            .expect("compute runtime starts"),
        ));
        std::sync::Arc::make_mut(&mut state.compute_workers).insert("cpu".to_owned(), worker());

        assert!(matches!(
            <HostState as compute::Host>::open(&mut state, request("missing")),
            Err(ErrorCode::NoSuchWorker)
        ));
        let group = <HostState as compute::Host>::open(&mut state, request("cpu"))
            .expect("declared worker opens");
        assert!(matches!(
            <HostState as compute::HostComputeGroup>::write(
                &mut state,
                Resource::new_borrow(group.rep()),
                astrid_compute::ABI_HEADER_BYTES,
                vec![0; MAX_CONTROL_TRANSFER_BYTES + 1],
            ),
            Err(ErrorCode::TooLarge)
        ));
        let job = <HostState as compute::HostComputeGroup>::submit(
            &mut state,
            Resource::new_borrow(group.rep()),
            WorkDescriptor {
                offset: astrid_compute::ABI_HEADER_BYTES,
                length: 0,
                tag: 7,
                worker_index: None,
                fuel: Some(1_000_000),
            },
        )
        .expect("job submits");
        let result =
            <HostState as compute::HostJob>::join(&mut state, Resource::new_borrow(job.rep()))
                .await
                .expect("job completes");
        assert_eq!(result.worker_status, 42);
        assert!(matches!(result.state, JobState::Completed));

        // A retained Store is shared by sequential invocations, but its live
        // compute handles are not: every operation rechecks the opening
        // principal at the host boundary. A malicious controller cannot use or
        // destroy Alice's group/job while serving Bob.
        state.principal = astrid_core::PrincipalId::new("bob").expect("valid principal");
        assert!(matches!(
            <HostState as compute::HostComputeGroup>::info(
                &mut state,
                Resource::new_borrow(group.rep()),
            ),
            Err(ErrorCode::CapabilityDenied)
        ));
        assert!(matches!(
            <HostState as compute::HostJob>::status(&mut state, Resource::new_borrow(job.rep()),),
            Err(ErrorCode::CapabilityDenied)
        ));
        <HostState as compute::HostComputeGroup>::drop(&mut state, Resource::new_own(group.rep()))
            .expect("cross-principal drop is safely ignored");

        state.principal = astrid_core::PrincipalId::new("alice").expect("valid principal");
        assert!(
            <HostState as compute::HostComputeGroup>::info(
                &mut state,
                Resource::new_borrow(group.rep()),
            )
            .is_ok(),
            "Alice's group must remain live after Bob's denied drop"
        );
    }
}
