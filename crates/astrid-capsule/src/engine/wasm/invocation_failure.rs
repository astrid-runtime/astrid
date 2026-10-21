//! Stable host-owned trap classifications; never reflect guest arguments.

pub(super) fn reason(error: &wasmtime::Error) -> &'static str {
    match error.downcast_ref::<wasmtime::Trap>() {
        Some(wasmtime::Trap::OutOfFuel) => "interceptor exhausted its fuel budget",
        Some(wasmtime::Trap::Interrupt) => "interceptor exceeded its execution deadline",
        Some(wasmtime::Trap::UnreachableCodeReached) => {
            "interceptor execution failed: wasm unreachable instruction executed"
        },
        // Panics and allocator failures may trap; no completed guest decision
        // means no permission. Do not leak arbitrary host error-chain details.
        _ => "interceptor execution failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unreachable_is_actionable_without_host_or_guest_error_reflection() {
        let error = wasmtime::Error::new(wasmtime::Trap::UnreachableCodeReached);
        assert!(reason(&error).contains("unreachable"));
        assert_eq!(
            reason(&wasmtime::Error::msg("secret host path")),
            "interceptor execution failed"
        );
    }
}
