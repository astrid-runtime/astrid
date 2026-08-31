//! Exact machine-visible domain lifecycle assertions.

use serde_json::Value;

use super::{
    all_bools, bool_field, check, count_named, ev_name, exact_pairs, exact_triples, named_events,
    relations_projection_holds, string_field, u64_field,
};

/// Slot 0 handles the entry, invalid-opcode, fault, quota, hostile, and clean
/// scenarios. Slot 1 proves peer preservation twice. Releases increment each
/// slot generation, so these exact values reject stale-handle reuse.
const DOMAIN_STARTS: &[(u64, u64, u64)] = &[
    (1, 1, 0),
    (1, 2, 5),
    (1, 3, 1),
    (1, 4, 2),
    (2, 2, 0),
    (1, 5, 3),
    (1, 6, 0),
    (1, 7, 6),
    (2, 3, 7),
    (1, 8, 6),
    (2, 4, 8),
    (1, 9, 10),
    (1, 10, 11),
];
const DOMAIN_ADMISSION_COUNT: usize = DOMAIN_STARTS.len() + 1;
const DOMAIN_ENTERED: &[(u64, u64)] = &[
    (1, 1),
    (1, 2),
    (1, 3),
    (1, 4),
    (2, 2),
    (1, 5),
    (1, 6),
    (1, 7),
    (2, 3),
    (1, 8),
    (2, 4),
    (1, 9),
    (1, 10),
];
const DOMAIN_REGISTERS: &[(u64, u64, u64)] = &[
    (1, 1, 0),
    (1, 2, 5),
    (1, 3, 1),
    (1, 4, 2),
    (2, 2, 0),
    (1, 5, 3),
    (1, 6, 0),
    (2, 3, 0),
    (2, 4, 0),
    (1, 9, 0),
];
const STOP_DOMAIN: (u64, u64) = (1, 10);
const DOMAIN_RECLAIMS: &[(u64, u64)] = &[
    (1, 1),
    (1, 2),
    (1, 3),
    (2, 1),
    (1, 4),
    (2, 2),
    (1, 5),
    (1, 6),
    (2, 3),
    (1, 7),
    (2, 4),
    (1, 8),
    (1, 9),
    (1, 10),
];
const DOMAIN_CANCEL_REJECTS: &[(&str, u64, u64)] = &[("stale_handle", 1, 1)];
const DOMAIN_CANCEL_IDENTITIES: &[(u64, u64)] = &[(2, 1)];
const KERNEL_CR3_ROOT: &str = "0x101000";
const KERNEL_CR3_FLAGS: u64 = 0;
const DOMAIN_CONTEXT_FLAGS: u64 = 0;
const SLOT_CONTEXT_ROOTS: [&str; 2] = ["0xfe01000", "0xfe17000"];
const DOMAIN_OUTCOMES: &[(u64, u64, &str, u64, u64, &str, u64)] = &[
    (1, 1, "clean_exit", 3, 0, "0x0", 3),
    (1, 2, "invalid_instruction", 6, 0, "0x0", 3),
    (1, 3, "page_fault", 14, 6, "0x0", 3),
    (2, 1, "cancelled", 0, 0, "0x0", 0),
    (1, 4, "quota_exhausted", 32, 0, "0x0", 3),
    (2, 2, "clean_exit", 3, 0, "0x0", 3),
    (1, 5, "page_fault", 14, 6, HOSTILE_PEER_FAULT_ADDRESS, 3),
    (1, 6, "clean_exit", 3, 0, "0x0", 3),
    (2, 3, "clean_exit", 3, 0, "0x0", 3),
    (2, 4, "page_fault", 14, 6, HOSTILE_IPC_FAULT_ADDRESS, 3),
    (1, 9, "clean_exit", 3, 0, "0x0", 3),
    (1, 10, "cancelled", 32, 0, "0x0", 3),
];
const STOP_TAKEN: &[(u64, u64, u64, u64)] = &[(1, 10, 32, 0)];
pub(crate) const HOSTILE_IPC_FAULT_ADDRESS: &str = "0x328000002000";
const IPC_RECLAIMS: &[(u64, u64, u64, u64, u64)] = &[
    (2, 3, 1, 0, 0),
    (1, 7, 1, 1, 0),
    (2, 4, 1, 0, 0),
    (1, 8, 1, 1, 0),
    (1, 9, 1, 1, 0),
];
const IPC_OPS: &[(u64, u64, &str, &str)] = &[
    (1, 7, "endpoint_create", "ok"),
    (2, 3, "send", "malformed"),
    (2, 3, "send", "malformed"),
    (2, 3, "send", "malformed"),
    (2, 3, "endpoint_create", "ok"),
    (2, 3, "cap_revoke", "ok"),
    (2, 3, "send", "malformed"),
    (2, 3, "send", "malformed"),
    (2, 3, "send", "malformed"),
    (1, 7, "send", "ok"),
    (1, 8, "endpoint_create", "ok"),
    (1, 9, "endpoint_create", "ok"),
    (1, 9, "cancel", "ok"),
];
pub(crate) const HOSTILE_PEER_FAULT_ADDRESS: &str = "0x328000001000";

/// Bind the domain claim to its complete machine-visible lifecycle: exact
/// starts, ring-3 entries, guest registers, outcomes, CR3 restoration, and
/// frame reclamation. Generation values must strictly advance on each reuse.
pub(super) fn domain_lifecycle_holds(events: &[Value]) -> bool {
    let starts_ok = exact_triples(
        events,
        "domain.start",
        "id",
        "generation",
        "scenario",
        DOMAIN_STARTS,
    );
    let entries_ok = exact_pairs(events, "domain.entered", "id", "generation", DOMAIN_ENTERED)
        && named_events(events, "domain.entered")
            .into_iter()
            .all(|event| u64_field(event, "cpl") == Some(3));
    let registers_ok = exact_triples(
        events,
        "domain.registers",
        "id",
        "generation",
        "rdi",
        DOMAIN_REGISTERS,
    ) && named_events(events, "domain.registers")
        .into_iter()
        .all(|event| {
            let entry_contract =
                u64_field(event, "id") == Some(1) && u64_field(event, "generation") == Some(1);
            let guest_cancel_contract =
                u64_field(event, "id") == Some(1) && u64_field(event, "generation") == Some(9);
            let guest_cancel_ok = !guest_cancel_contract || u64_field(event, "rax") == Some(7);
            let zero_gpr = !entry_contract
                || (u64_field(event, "rax") == Some(0)
                    && [
                        "rbx", "rcx", "rdx", "rsi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13",
                        "r14", "r15",
                    ]
                    .iter()
                    .all(|name| u64_field(event, name) == Some(0)));
            string_field(event, "rsp").is_some_and(|rsp| rsp.starts_with("0x"))
                && u64_field(event, "cpl") == Some(3)
                && zero_gpr
                && guest_cancel_ok
        });
    let kernel_cr3 = named_events(events, "kernel.cr3").first().copied();
    let kernel_cr3_ok = kernel_cr3.is_some_and(|event| {
        string_field(event, "root") == Some(KERNEL_CR3_ROOT)
            && u64_field(event, "flags") == Some(KERNEL_CR3_FLAGS)
    });
    let start_identities: Vec<(u64, u64)> = DOMAIN_STARTS
        .iter()
        .map(|(id, generation, _)| (*id, *generation))
        .collect();
    let context_identities: Vec<(u64, u64)> = named_events(events, "domain.context")
        .into_iter()
        .map(|event| {
            (
                u64_field(event, "id").unwrap_or_default(),
                u64_field(event, "generation").unwrap_or_default(),
            )
        })
        .collect();
    let contexts_ok = context_identities == start_identities
        && named_events(events, "domain.context")
            .into_iter()
            .all(|event| {
                let expected_root = match u64_field(event, "id") {
                    Some(1) => SLOT_CONTEXT_ROOTS[0],
                    Some(2) => SLOT_CONTEXT_ROOTS[1],
                    _ => "",
                };
                string_field(event, "root") == Some(expected_root)
                    && u64_field(event, "flags") == Some(DOMAIN_CONTEXT_FLAGS)
                    && u64_field(event, "cpl") == Some(3)
                    && u64_field(event, "fs") == Some(0)
                    && u64_field(event, "gs") == Some(0)
            });
    let observed_outcomes: Vec<(u64, u64, &str, u64, u64, &str, u64)> =
        named_events(events, "domain.outcome")
            .into_iter()
            .map(|event| {
                (
                    u64_field(event, "id").unwrap_or_default(),
                    u64_field(event, "generation").unwrap_or_default(),
                    string_field(event, "kind").unwrap_or_default(),
                    u64_field(event, "vector").unwrap_or_default(),
                    u64_field(event, "error_code").unwrap_or_default(),
                    string_field(event, "fault_address").unwrap_or_default(),
                    u64_field(event, "cpl").unwrap_or_default(),
                )
            })
            .collect();
    let outcomes_ok = observed_outcomes.len() == DOMAIN_OUTCOMES.len()
        && observed_outcomes
            .iter()
            .zip(DOMAIN_OUTCOMES)
            .all(|(observed, expected)| {
                observed.0 == expected.0
                    && observed.1 == expected.1
                    && observed.2 == expected.2
                    && observed.3 == expected.3
                    && observed.4 == expected.4
                    && (observed.5 == expected.5 || expected.5 == "*")
                    && observed.6 == expected.6
            });
    let stop_staged_ok = exact_triples(
        events,
        "domain.stop.staged",
        "id",
        "generation",
        "scenario",
        &[(STOP_DOMAIN.0, STOP_DOMAIN.1, 11)],
    );
    let stop_armed_ok = exact_pairs(
        events,
        "domain.stop.armed",
        "id",
        "generation",
        &[STOP_DOMAIN],
    );
    let stop_taken_ok = named_events(events, "domain.stop.taken")
        .into_iter()
        .map(|event| {
            (
                u64_field(event, "id").unwrap_or_default(),
                u64_field(event, "generation").unwrap_or_default(),
                u64_field(event, "vector").unwrap_or_default(),
                u64_field(event, "cpl").unwrap_or_default(),
            )
        })
        .eq(STOP_TAKEN.iter().copied());
    let control_returned_ok = exact_pairs(
        events,
        "domain.control.returned",
        "id",
        "generation",
        &[STOP_DOMAIN],
    ) && named_events(events, "domain.control.returned")
        .into_iter()
        .all(|event| {
            u64_field(event, "cpl") == Some(3) && bool_field(event, "terminal") == Some(false)
        });
    let control_requested_ok = exact_pairs(
        events,
        "domain.stop.request",
        "id",
        "generation",
        &[STOP_DOMAIN],
    );
    let stop_tail_ok = all_bools(events, "domain.stop.relation-retired", "ok", true)
        && all_bools(events, "domain.stop.admission-released", "ok", true)
        && all_bools(events, "domain.stop.completed", "ok", true)
        && exact_pairs(
            events,
            "domain.stop.current-inactive",
            "id",
            "generation",
            &[STOP_DOMAIN],
        );
    let reclaims_ok = exact_pairs(
        events,
        "domain.reclaim",
        "id",
        "generation",
        DOMAIN_RECLAIMS,
    ) && named_events(events, "domain.reclaim")
        .into_iter()
        .all(|event| {
            let expected = u64_field(event, "expected");
            expected.is_some_and(|expected| {
                expected > 0
                    && u64_field(event, "freed") == Some(expected)
                    && u64_field(event, "swept") == Some(expected)
                    && u64_field(event, "blocked") == Some(0)
            })
        });
    let restores_ok = exact_pairs(
        events,
        "domain.restore",
        "id",
        "generation",
        DOMAIN_RECLAIMS,
    ) && all_bools(events, "domain.restore", "ok", true);
    let restores_ok = kernel_cr3_ok
        && restores_ok
        && named_events(events, "domain.restore")
            .into_iter()
            .all(|event| {
                string_field(event, "root") == Some(KERNEL_CR3_ROOT)
                    && u64_field(event, "flags") == Some(KERNEL_CR3_FLAGS)
            });
    let audits_ok = named_events(events, "domain.audit").len() == 2 * DOMAIN_ADMISSION_COUNT
        && named_events(events, "domain.audit")
            .into_iter()
            .all(|event| {
                u64_field(event, "frames").is_some_and(|frames| frames > 0)
                    && bool_field(event, "wx_ok") == Some(true)
                    && bool_field(event, "kernel_excluded") == Some(true)
                    && bool_field(event, "peer_excluded") == Some(true)
            });
    let exclusions_ok = named_events(events, "domain.exclusion").len() == DOMAIN_ADMISSION_COUNT
        && named_events(events, "domain.exclusion")
            .into_iter()
            .all(|event| {
                bool_field(event, "alias_excluded") == Some(true)
                    && bool_field(event, "kernel_excluded") == Some(true)
                    && bool_field(event, "peer_excluded") == Some(true)
            });
    let policies_ok = named_events(events, "domain.policy").len() == DOMAIN_ADMISSION_COUNT
        && all_bools(events, "domain.policy", "audit_ok", true)
        && all_bools(events, "domain.policy", "stack_zeroed", true)
        && all_bools(events, "domain.policy", "probe_zeroed", true);
    let cancel_rejects_ok = named_events(events, "domain.cancel.reject")
        .into_iter()
        .map(|event| {
            (
                string_field(event, "reason").unwrap_or_default(),
                u64_field(event, "id").unwrap_or_default(),
                u64_field(event, "generation").unwrap_or_default(),
            )
        })
        .eq(DOMAIN_CANCEL_REJECTS.iter().copied());
    let cancel_identities_ok = exact_pairs(
        events,
        "domain.cancel.request",
        "id",
        "generation",
        DOMAIN_CANCEL_IDENTITIES,
    ) && exact_pairs(
        events,
        "domain.cancelled",
        "id",
        "generation",
        DOMAIN_CANCEL_IDENTITIES,
    );
    let accounting_ok = count_named(events, "domain.accounting") == 0;
    let ipc_ops_ok = named_events(events, "ipc.op")
        .into_iter()
        .map(|event| {
            (
                u64_field(event, "id").unwrap_or_default(),
                u64_field(event, "generation").unwrap_or_default(),
                string_field(event, "op").unwrap_or_default(),
                string_field(event, "status").unwrap_or_default(),
            )
        })
        .eq(IPC_OPS.iter().copied());
    let ipc_reclaims_ok = named_events(events, "ipc.reclaim")
        .into_iter()
        .map(|event| {
            (
                u64_field(event, "id").unwrap_or_default(),
                u64_field(event, "generation").unwrap_or_default(),
                u64_field(event, "capabilities").unwrap_or_default(),
                u64_field(event, "endpoints").unwrap_or_default(),
                u64_field(event, "queued").unwrap_or_default(),
            )
        })
        .eq(IPC_RECLAIMS.iter().copied());
    let ipc_flow_ok = count_named(events, "ipc.park") == 4
        && count_named(events, "ipc.wake") == 2
        && count_named(events, "ipc.resume") == 2;
    let relations_ok = relations_projection_holds(events);
    let tamper_events = named_events(events, "domain.auth.reject")
        .into_iter()
        .filter(|event| string_field(event, "reason") == Some("tampered_component_rejected"))
        .count();
    let tamper_ok = tamper_events == 1;
    let auth_pass = events.iter().position(|event| {
        ev_name(event) == "test.pass"
            && string_field(event, "name") == Some("authenticated_nonempty_component_binds_payload")
    });
    let tamper = events.iter().position(|event| {
        ev_name(event) == "domain.auth.reject"
            && string_field(event, "reason") == Some("tampered_component_rejected")
    });
    let tamper_order_ok =
        tamper.is_some_and(|tamper| auth_pass.is_some_and(|auth_pass| tamper < auth_pass));
    let harness_ok = count_named(events, "domain.harness") == 1
        && named_events(events, "domain.harness")
            .into_iter()
            .all(|event| bool_field(event, "outcome") == Some(true));
    let terminal: Vec<&str> = events.iter().rev().take(3).map(ev_name).collect();
    let terminal_ok = terminal == ["halt", "domain.harness", "test.pass"];
    let mut ok = true;
    ok &= check("exact domain starts and monotonic generations", starts_ok);
    ok &= check("exact ring-3 domain entries", entries_ok);
    ok &= check("exact guest registers and CPL", registers_ok);
    ok &= check(
        "context identity, flags, and start/kernel-CR3 relation",
        contexts_ok,
    );
    ok &= check("exact domain outcomes and fault addresses", outcomes_ok);
    ok &= check(
        "exact running-stop staging and arming",
        stop_staged_ok && stop_armed_ok,
    );
    ok &= check(
        "exact returned-control quiescence and request",
        control_returned_ok && control_requested_ok,
    );
    ok &= check("exact returned-stop consumption", stop_taken_ok);
    ok &= check("running-stop terminal completion order", stop_tail_ok);
    ok &= check("exact reclaim generations and accounting", reclaims_ok);
    ok &= check("restores accompany every reclaim", restores_ok);
    ok &= check("domain page-table audits", audits_ok);
    ok &= check("domain exclusion evidence", exclusions_ok);
    ok &= check("zero-on-admission policy", policies_ok);
    ok &= check("exact active and stale cancel rejection", cancel_rejects_ok);
    ok &= check(
        "exact cancel request/cancelled identities",
        cancel_identities_ok,
    );
    ok &= check("exact private-IPC operations", ipc_ops_ok);
    ok &= check("exact private-IPC reclaim evidence", ipc_reclaims_ok);
    ok &= check("exact private-IPC park/wake/resume flow", ipc_flow_ok);
    ok &= check("same-lock IPC relation projection", relations_ok);
    ok &= check("no domain accounting leaks", accounting_ok);
    ok &= check(
        "tampered component rejection before auth success",
        tamper_ok,
    );
    ok &= check("tamper rejection ordering", tamper_order_ok);
    ok &= check("domain harness success", harness_ok);
    ok &= check("domain terminal ordering", terminal_ok);
    ok
}
