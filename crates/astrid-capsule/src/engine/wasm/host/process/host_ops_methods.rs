macro_rules! host_ops_methods {
    () => {
        fn attach(&mut self, id: String) -> Result<Resource<ProcessHandle>, ErrorCode> {
            if !self.invocation_authority_active() {
                return Err(ErrorCode::CapabilityDenied);
            }
            // Deferred: materialising a `process-handle` resource over a registry
            // entry needs dual-typed dispatch in the resource table. The id-keyed
            // free functions below ARE the documented `attach(id)?.method()`
            // equivalents, so the persistent tier is fully usable without it.
            let result: Result<Resource<ProcessHandle>, ErrorCode> = Err(ErrorCode::Unknown(
                "attach: resource-handle materialisation pending — use the id-keyed ops"
                    .to_string(),
            ));
            audit_process_id(self, "astrid:process/host.attach", &id, &result);
            result
        }

        fn list_processes(
            &mut self,
            label_filter: Option<String>,
        ) -> Result<Vec<ProcessInfo>, ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let result = Ok(self.persistent_processes.list(
                &principal,
                &capsule_id,
                label_filter.as_deref(),
            ));
            // Not id-keyed: audit the op + (non-secret) label filter, no id.
            audit_process(
                self,
                "astrid:process/host.list-processes",
                label_filter.as_deref().unwrap_or("*"),
                &result,
            );
            result
        }

        fn status(&mut self, id: String) -> Result<ProcessInfo, ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let result = self
                .persistent_processes
                .status(&id, &principal, &capsule_id);
            audit_process_id(self, "astrid:process/host.status", &id, &result);
            result
        }

        fn status_many(&mut self, ids: Vec<String>) -> Result<Vec<ProcessInfo>, ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let result = Ok(self
                .persistent_processes
                .status_many(&ids, &principal, &capsule_id));
            audit_process(
                self,
                "astrid:process/host.status-many",
                &format!("{} ids", ids.len()),
                &result,
            );
            result
        }

        fn read_logs(&mut self, id: String) -> Result<ReadLogsResult, ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let result = self
                .persistent_processes
                .read_logs(&id, &principal, &capsule_id);
            audit_process_id(self, "astrid:process/host.read-logs", &id, &result);
            result
        }

        fn read_since(
            &mut self,
            id: String,
            which_stream: LogStream,
            cursor: LogCursor,
            max_bytes: u32,
        ) -> Result<LogChunk, ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let result = self.persistent_processes.read_since(
                &id,
                &principal,
                &capsule_id,
                which_stream,
                &cursor,
                max_bytes,
            );
            audit_process_id(self, "astrid:process/host.read-since", &id, &result);
            result
        }

        fn write_stdin(&mut self, id: String, data: Vec<u8>) -> Result<u32, ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let handle = self.runtime_handle.clone();
            let semaphore = self.io_semaphore.clone();
            let registry = self.persistent_processes.clone();
            let id_for_audit = id.clone();
            let result = util::bounded_block_on(&handle, &semaphore, async move {
                registry
                    .write_stdin(&id, &principal, &capsule_id, &data)
                    .await
            });
            audit_process_id(
                self,
                "astrid:process/host.write-stdin",
                &id_for_audit,
                &result,
            );
            result
        }

        fn close_stdin(&mut self, id: String) -> Result<(), ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let result = self
                .persistent_processes
                .close_stdin(&id, &principal, &capsule_id);
            audit_process_id(self, "astrid:process/host.close-stdin", &id, &result);
            result
        }

        fn signal(&mut self, id: String, sig: ProcessSignal) -> Result<(), ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let result = self
                .persistent_processes
                .signal(&id, &principal, &capsule_id, sig);
            audit_process_id(self, "astrid:process/host.signal", &id, &result);
            result
        }

        fn wait(&mut self, id: String, timeout_ms: u64) -> Result<ExitInfo, ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let handle = self.runtime_handle.clone();
            let semaphore = self.blocking_semaphore.clone();
            let cancel = self.effective_cancel_token();
            let registry = self.persistent_processes.clone();
            let timeout = std::time::Duration::from_millis(timeout_ms);
            let id_for_audit = id.clone();
            let result =
                util::bounded_block_on_cancellable(&handle, &semaphore, &cancel, async move {
                    registry.wait(&id, &principal, &capsule_id, timeout).await
                })
                .unwrap_or(Err(ErrorCode::Cancelled));
            audit_process_id(self, "astrid:process/host.wait", &id_for_audit, &result);
            result
        }

        fn stop(&mut self, id: String, grace_ms: Option<u64>) -> Result<ExitInfo, ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let handle = self.runtime_handle.clone();
            let semaphore = self.blocking_semaphore.clone();
            let cancel = self.effective_cancel_token();
            let registry = self.persistent_processes.clone();
            let grace = grace_ms.map(std::time::Duration::from_millis);
            let id_for_audit = id.clone();
            let result =
                util::bounded_block_on_cancellable(&handle, &semaphore, &cancel, async move {
                    registry.stop(&id, &principal, &capsule_id, grace).await
                })
                .unwrap_or(Err(ErrorCode::Cancelled));
            audit_process_id(self, "astrid:process/host.stop", &id_for_audit, &result);
            result
        }

        fn release_process(&mut self, id: String) -> Result<(), ErrorCode> {
            let principal = self.effective_principal();
            let capsule_id = self.capsule_id.as_str().to_owned();
            let result = self
                .persistent_processes
                .release(&id, &principal, &capsule_id);
            audit_process_id(self, "astrid:process/host.release-process", &id, &result);
            result
        }

        fn watch(&mut self, id: String, _suffix: Option<String>) -> Result<(), ErrorCode> {
            // Deferred by design: host-published lifecycle events raise an OPEN
            // publish-authority question (manifest `[publish]` vs kernel-authored
            // topic class) tracked in RFC host_abi. `status` + bounded `wait` is
            // the working polling alternative until that resolves.
            let result: Result<(), ErrorCode> = Err(ErrorCode::Unknown(
                "watch: host lifecycle events deferred (publish-authority — RFC host_abi)"
                    .to_string(),
            ));
            audit_process_id(self, "astrid:process/host.watch", &id, &result);
            result
        }

        fn unwatch(&mut self, id: String) -> Result<(), ErrorCode> {
            // Idempotent: nothing is armed while `watch` is deferred.
            let result: Result<(), ErrorCode> = Ok(());
            audit_process_id(self, "astrid:process/host.unwatch", &id, &result);
            result
        }
    };
}
