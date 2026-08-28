//! Parse JSONL serial events and assert the combined boot evidence contract.
//!
//! One sequence covers boot, both closure identities/floors, bound, M1
//! milestones, and terminal halt. Sequence numbers must be contiguous and
//! strictly increasing from 0. `halt` is terminal. Any `test.fail`, including
//! unknown future names, fails. Required events must appear exactly once.
//! Reordered closure/M1 events fail.

use serde_json::Value;

const REQUIRED_ONCE: &[&str] = &[
    "boot.entry",
    "idt.ready",
    "component.bound",
    "handoff.bound",
    "closure.kernel",
    "closure.sysgen",
    "closure.bound",
    "mem.map",
    "paging.wx",
    "heap.ready",
    "kernel.cr3",
    "halt",
];

const REQUIRED_PASSES: &[&str] = &[
    "int3_handled",
    "wx_rodata_write",
    "nx_data_exec",
    "heap_exhaustion",
    "frame_unique",
    "frame_exhaustion",
];

const DOMAIN_REQUIRED_PASSES: &[&str] = &[
    "authenticated_nonempty_component_binds_payload",
    "ring3_entry_return",
    "real_invalid_opcode_is_domain_scoped",
    "per_domain_page_table_exclusion",
    "quota_preempts_infinite_loop_and_preserves_peer",
    "fault_is_domain_scoped",
    "reclaim_exactly_once_under_fault_kill_cancel",
    "hostile_first_then_clean_second_domain",
];

const EXTRA_REQUIRED_PASSES: &[&str] = &[
    "guest_gp_fs_gs_entry_contract",
    "active_domain_lifecycle_exclusion",
    "stale_handle_rejection",
    "generation_overflow_is_fail_closed",
    "exact_kernel_cr3_restore",
];
#[cfg(test)]
pub(crate) const OVERFLOW_GATE: &str = EXTRA_REQUIRED_PASSES[3];

#[cfg(test)]
pub(crate) const ENTRY_STATE_GATE: &str = "guest_gp_fs_gs_entry_contract";
#[cfg(test)]
pub(crate) const RESTORE_GATE: &str = "exact_kernel_cr3_restore";
#[cfg(test)]
pub(crate) const ACTIVE_GUARD_GATE: &str = "active_domain_lifecycle_exclusion";
#[cfg(test)]
pub(crate) const STALE_GATE: &str = "stale_handle_rejection";
#[cfg(test)]
pub(crate) const QUOTA_GATE: &str = "quota_preempts_infinite_loop_and_preserves_peer";
#[cfg(test)]
pub(crate) const PAGING_GATE: &str = "per_domain_page_table_exclusion";
#[cfg(test)]
pub(crate) const FAULT_GATE: &str = "fault_is_domain_scoped";
#[cfg(test)]
pub(crate) const RECLAIM_GATE: &str = "reclaim_exactly_once_under_fault_kill_cancel";
#[cfg(test)]
pub(crate) const CLEAN_RESTART_GATE: &str = "hostile_first_then_clean_second_domain";

const SUCCESS_BOUND_EVENTS: &[&str] = &[
    "component.bound",
    "handoff.bound",
    "closure.kernel",
    "closure.sysgen",
    "closure.bound",
];

const CLOSURE_SUCCESS_BOUND_EVENTS: &[&str] = &[
    "handoff.bound",
    "closure.kernel",
    "closure.sysgen",
    "closure.bound",
];

const RING0_REJECT_ORDER: &[&str] = &["boot.entry", "idt.ready", "closure.reject", "halt"];

/// A strict name-only walker first, so every field assertion below operates
/// on a trace whose event kinds are already in the machine's exact order.
#[derive(Clone, Copy)]
enum SequenceStep {
    One(&'static str),
    Pass(&'static str),
    Many(&'static [&'static str]),
    Repeated(&'static str, usize),
}

impl SequenceStep {
    fn name(&self, index: usize) -> &'static str {
        match self {
            Self::One(name) => name,
            Self::Pass(_) => "test.pass",
            Self::Many(names) => names[index],
            Self::Repeated(name, _) => name,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Pass(_) => 1,
            Self::Many(names) => names.len(),
            Self::Repeated(_, count) => *count,
        }
    }
}

fn walk_sequence(events: &[Value], pattern: &[SequenceStep]) -> bool {
    first_sequence_mismatch(events, pattern).is_none()
}

fn first_sequence_mismatch(
    events: &[Value],
    pattern: &[SequenceStep],
) -> Option<(usize, &'static str)> {
    let mut cursor = 0usize;
    for step in pattern {
        for index in 0..step.len() {
            let Some(event) = events.get(cursor) else {
                return Some((cursor, step.name(index)));
            };
            if ev_name(event) != step.name(index) {
                return Some((cursor, step.name(index)));
            }
            if let SequenceStep::Pass(expected_name) = step
                && string_field(event, "name") != Some(expected_name)
            {
                return Some((cursor, expected_name));
            }
            cursor += 1;
        }
    }
    (cursor < events.len()).then(|| {
        let last = pattern.last();
        (cursor, last.map_or("trace-end", |step| step.name(0)))
    })
}

const PREPARE_EVENTS: &[&str] = &[
    "domain.exclusion",
    "domain.audit",
    "domain.policy",
    "domain.audit",
];
const START_EVENT: &str = "domain.start";
const GUEST_ENTRY_EVENTS: &[&str] = &["domain.entered", "domain.context"];
const GUEST_REGISTER_EVENT: &str = "domain.registers";
const GUEST_TAIL_EVENTS: &[&str] = &["domain.outcome", "domain.restore", "domain.reclaim"];
const CANCEL_TAIL_EVENTS: &[&str] = &[
    "domain.cancel.request",
    "domain.restore",
    "domain.reclaim",
    "domain.cancelled",
    "domain.outcome",
];
const BOOT_MILESTONE_EVENTS: &[&str] = &[
    "boot.entry",
    "idt.ready",
    "component.bound",
    "handoff.bound",
    "closure.kernel",
    "closure.sysgen",
    "closure.bound",
    "mem.map",
    "paging.wx",
    "heap.ready",
    "apic.timer.start",
];
fn push_guest_terminal(pattern: &mut Vec<SequenceStep>, quota: bool) {
    pattern.push(SequenceStep::Many(GUEST_ENTRY_EVENTS));
    if quota {
        pattern.push(SequenceStep::One("domain.quota"));
    }
    pattern.push(SequenceStep::One(GUEST_REGISTER_EVENT));
    pattern.push(SequenceStep::Many(GUEST_TAIL_EVENTS));
}

fn full_sequence() -> Vec<SequenceStep> {
    let mut pattern = vec![
        SequenceStep::Many(BOOT_MILESTONE_EVENTS),
        SequenceStep::Repeated("apic.timer.tick", 8),
        SequenceStep::One("entropy.seeded"),
        SequenceStep::One("fault"),
        SequenceStep::Pass(REQUIRED_PASSES[0]),
        SequenceStep::One("fault"),
        SequenceStep::Pass(REQUIRED_PASSES[1]),
        SequenceStep::One("fault"),
        SequenceStep::Pass(REQUIRED_PASSES[2]),
        SequenceStep::Pass(REQUIRED_PASSES[3]),
        SequenceStep::Pass(REQUIRED_PASSES[4]),
        SequenceStep::Pass(REQUIRED_PASSES[5]),
        SequenceStep::One("kernel.cr3"),
        SequenceStep::Pass(EXTRA_REQUIRED_PASSES[3]),
        SequenceStep::One("domain.auth.reject"),
        SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[0]),
    ];
    let push_started = |pattern: &mut Vec<SequenceStep>| {
        pattern.push(SequenceStep::Many(PREPARE_EVENTS));
        pattern.push(SequenceStep::One(START_EVENT));
    };

    push_started(&mut pattern);
    push_guest_terminal(&mut pattern, false);
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[1]));
    pattern.push(SequenceStep::Pass(EXTRA_REQUIRED_PASSES[0]));
    push_started(&mut pattern);
    push_guest_terminal(&mut pattern, false);
    pattern.extend([
        SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[2]),
        SequenceStep::Pass(EXTRA_REQUIRED_PASSES[4]),
        SequenceStep::Many(PREPARE_EVENTS),
        SequenceStep::Pass(EXTRA_REQUIRED_PASSES[1]),
        SequenceStep::One("domain.cancel.reject"),
        SequenceStep::Pass(EXTRA_REQUIRED_PASSES[2]),
    ]);

    pattern.push(SequenceStep::Many(PREPARE_EVENTS));
    pattern.push(SequenceStep::One(START_EVENT));
    push_guest_terminal(&mut pattern, false);
    pattern.push(SequenceStep::Many(CANCEL_TAIL_EVENTS));
    pattern.push(SequenceStep::Many(PREPARE_EVENTS));
    pattern.push(SequenceStep::Many(PREPARE_EVENTS));
    pattern.push(SequenceStep::One(START_EVENT));
    push_guest_terminal(&mut pattern, true);
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[4]));
    pattern.push(SequenceStep::One("domain.start"));
    push_guest_terminal(&mut pattern, false);
    push_started(&mut pattern);
    push_guest_terminal(&mut pattern, false);
    pattern.extend([
        SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[3]),
        SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[5]),
        SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[6]),
    ]);
    push_started(&mut pattern);
    push_guest_terminal(&mut pattern, false);
    pattern.extend([
        SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[7]),
        SequenceStep::One("domain.harness"),
        SequenceStep::One("halt"),
    ]);
    pattern
}

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
];
const DOMAIN_ADMISSION_COUNT: usize = DOMAIN_STARTS.len() + 1;
const DOMAIN_ENTERED: &[(u64, u64)] = &[(1, 1), (1, 2), (1, 3), (1, 4), (2, 2), (1, 5), (1, 6)];
const DOMAIN_REGISTERS: &[(u64, u64, u64)] = &[
    (1, 1, 0),
    (1, 2, 5),
    (1, 3, 1),
    (1, 4, 2),
    (2, 2, 0),
    (1, 5, 3),
    (1, 6, 0),
];
const DOMAIN_RECLAIMS: &[(u64, u64)] = &[
    (1, 1),
    (1, 2),
    (1, 3),
    (2, 1),
    (1, 4),
    (2, 2),
    (1, 5),
    (1, 6),
];
const DOMAIN_CANCEL_REJECTS: &[(&str, u64, u64)] = &[("stale_handle", 1, 1)];
const DOMAIN_OUTCOMES: &[(u64, u64, &str, u64, u64, &str, u64)] = &[
    (1, 1, "clean_exit", 3, 0, "0x0", 3),
    (1, 2, "invalid_instruction", 6, 0, "0x0", 3),
    (1, 3, "page_fault", 14, 6, "0x0", 3),
    (2, 1, "cancelled", 0, 0, "0x0", 0),
    (1, 4, "quota_exhausted", 32, 0, "0x0", 3),
    (2, 2, "clean_exit", 3, 0, "0x0", 3),
    (1, 5, "page_fault", 14, 6, HOSTILE_PEER_FAULT_ADDRESS, 3),
    (1, 6, "clean_exit", 3, 0, "0x0", 3),
];
const HOSTILE_PEER_FAULT_ADDRESS: &str = "0x328000001000";

/// `isa-debug-exit` maps the ring-0 failure value `0x11` to process exit 35.
pub const RING0_REJECT_EXIT_CODE: i32 = 35;

/// Loader-measured identities and independent floors expected on serial.
pub struct ExpectedClosures<'a> {
    pub policy_generation: u64,
    pub kernel_image_hex: &'a str,
    pub closure_table_hex: &'a str,
    pub kernel_id_hex: &'a str,
    pub sysgen_id_hex: &'a str,
    pub kernel_floor: u64,
    pub sysgen_floor: u64,
}

pub fn parse_events(serial: &str) -> Vec<Value> {
    serial
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with('{') {
                return None;
            }
            serde_json::from_str::<Value>(trimmed)
                .ok()
                .filter(|v| v.get("ev").is_some())
        })
        .collect()
}

pub fn ev_name(v: &Value) -> &str {
    v.get("ev").and_then(Value::as_str).unwrap_or("")
}

fn seq_of(v: &Value) -> Option<u64> {
    v.get("seq").and_then(Value::as_u64)
}

fn count_named(events: &[Value], name: &str) -> usize {
    events.iter().filter(|e| ev_name(e) == name).count()
}

/// Contiguous strictly increasing `seq` values starting at 0.
pub fn contiguous_seq_from_zero(events: &[Value]) -> bool {
    if events.is_empty() {
        return false;
    }
    let mut expected = 0u64;
    for ev in events {
        match seq_of(ev) {
            Some(seq) if seq == expected => {
                expected = match expected.checked_add(1) {
                    Some(n) => n,
                    None => return false,
                };
            },
            _ => return false,
        }
    }
    true
}

pub fn halt_is_terminal(events: &[Value]) -> bool {
    events.last().is_some_and(|e| ev_name(e) == "halt") && count_named(events, "halt") == 1
}

pub fn any_test_fail(events: &[Value]) -> bool {
    count_named(events, "test.fail") > 0
}

/// A rejected generation must never emit success-bound evidence. This is
/// intentionally independent of the happy-path assertions so a reject trace
/// cannot be made to look accepted by retaining stale closure events.
pub fn rejected_without_success_bound_events(events: &[Value]) -> bool {
    count_named(events, "closure.reject") > 0
        && CLOSURE_SUCCESS_BOUND_EVENTS
            .iter()
            .all(|name| count_named(events, name) == 0)
}

fn u64_field(event: &Value, name: &str) -> Option<u64> {
    event.get(name).and_then(Value::as_u64)
}

fn bool_field(event: &Value, name: &str) -> Option<bool> {
    event.get(name).and_then(Value::as_bool)
}

fn string_field<'a>(event: &'a Value, name: &str) -> Option<&'a str> {
    event.get(name).and_then(Value::as_str)
}

fn named_events<'a>(events: &'a [Value], name: &str) -> Vec<&'a Value> {
    events
        .iter()
        .filter(|event| ev_name(event) == name)
        .collect()
}

fn exact_pairs(
    events: &[Value],
    name: &str,
    first: &str,
    second: &str,
    expected: &[(u64, u64)],
) -> bool {
    let observed: Vec<(u64, u64)> = named_events(events, name)
        .into_iter()
        .map(|event| {
            (
                u64_field(event, first).unwrap_or_default(),
                u64_field(event, second).unwrap_or_default(),
            )
        })
        .collect();
    observed == expected
}

fn exact_triples(
    events: &[Value],
    name: &str,
    first: &str,
    second: &str,
    third: &str,
    expected: &[(u64, u64, u64)],
) -> bool {
    let observed: Vec<(u64, u64, u64)> = named_events(events, name)
        .into_iter()
        .map(|event| {
            (
                u64_field(event, first).unwrap_or_default(),
                u64_field(event, second).unwrap_or_default(),
                u64_field(event, third).unwrap_or_default(),
            )
        })
        .collect();
    observed == expected
}

fn all_bools(events: &[Value], name: &str, field: &str, expected: bool) -> bool {
    !named_events(events, name).is_empty()
        && named_events(events, name)
            .into_iter()
            .all(|event| bool_field(event, field) == Some(expected))
}

/// Bind the domain claim to its complete machine-visible lifecycle: exact
/// starts, ring-3 entries, guest registers, outcomes, CR3 restoration, and
/// frame reclamation. Generation values must strictly advance on each reuse.
fn domain_lifecycle_holds(events: &[Value]) -> bool {
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
            let zero_gpr = !entry_contract
                || [
                    "rax", "rbx", "rcx", "rdx", "rsi", "rbp", "r8", "r9", "r10", "r11", "r12",
                    "r13", "r14", "r15",
                ]
                .iter()
                .all(|name| u64_field(event, name) == Some(0));
            string_field(event, "rsp").is_some_and(|rsp| rsp.starts_with("0x"))
                && u64_field(event, "cpl") == Some(3)
                && zero_gpr
        });
    let contexts_ok = named_events(events, "domain.context")
        .into_iter()
        .all(|event| {
            string_field(event, "root").is_some_and(|root| root.starts_with("0x"))
                && u64_field(event, "cpl") == Some(3)
                && u64_field(event, "fs") == Some(0)
                && u64_field(event, "gs") == Some(0)
        });
    let outcomes_ok = named_events(events, "domain.outcome")
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
        .eq(DOMAIN_OUTCOMES.iter().copied());
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
    let accounting_ok = count_named(events, "domain.accounting") == 0;
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
    ok &= check("ring-3 context and FS/GS entry state", contexts_ok);
    ok &= check("exact domain outcomes and fault addresses", outcomes_ok);
    ok &= check("exact reclaim generations and accounting", reclaims_ok);
    ok &= check("restores accompany every reclaim", restores_ok);
    ok &= check("domain page-table audits", audits_ok);
    ok &= check("domain exclusion evidence", exclusions_ok);
    ok &= check("zero-on-admission policy", policies_ok);
    ok &= check("exact active and stale cancel rejection", cancel_rejects_ok);
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

/// Assert the executable ring-0 system-generation rejection contract.
///
/// The image used by this assertion has a canonical, correctly signed
/// descriptor whose plan identity differs from compiled `TrustedInput`. It
/// must therefore pass loader/table binding and reach the kernel before
/// `verify_manifest` emits `plan_mismatch`. A synthetic serial fixture alone
/// cannot establish that ordering; callers must supply a real QEMU trace.
pub fn assert_ring0_plan_mismatch(events: &[Value], exit_code: Option<i32>) -> bool {
    println!("\n== ring-0 plan-mismatch rejection assertions ==");
    let mut ok = true;
    ok &= check(
        "seq contiguous strictly increasing from 0",
        contiguous_seq_from_zero(events),
    );
    ok &= check(
        "exact ring-0 reject event sequence",
        walk_sequence(events, &[SequenceStep::Many(RING0_REJECT_ORDER)]),
    );
    ok &= check(
        "exactly one event for each ring-0 rejection milestone",
        events.len() == RING0_REJECT_ORDER.len()
            && RING0_REJECT_ORDER
                .iter()
                .all(|name| count_named(events, name) == 1),
    );
    ok &= check(
        "closure.reject reason=plan_mismatch",
        events.iter().any(|event| {
            ev_name(event) == "closure.reject"
                && event.get("reason").and_then(Value::as_str) == Some("plan_mismatch")
        }),
    );
    ok &= check(
        "no success-bound closure events",
        rejected_without_success_bound_events(events),
    );
    ok &= check(
        "no later init/test success",
        [
            "mem.map",
            "paging.wx",
            "heap.ready",
            "apic.timer.start",
            "apic.timer.tick",
            "entropy.seeded",
            "entropy.unavailable",
            "test.pass",
            "test.fail",
        ]
        .iter()
        .all(|name| count_named(events, name) == 0),
    );
    ok &= check("halt is terminal", halt_is_terminal(events));
    ok &= check(
        "halt outcome=fault",
        events.last().is_some_and(|event| {
            ev_name(event) == "halt"
                && event.get("outcome").and_then(Value::as_str) == Some("fault")
        }),
    );
    ok &= check(
        &format!("QEMU exit code == {RING0_REJECT_EXIT_CODE}"),
        exit_code == Some(RING0_REJECT_EXIT_CODE),
    );
    ok
}

fn required_events_once(events: &[Value]) -> bool {
    REQUIRED_ONCE
        .iter()
        .all(|name| count_named(events, name) == 1)
}

fn test_pass_count(events: &[Value], name: &str) -> usize {
    events
        .iter()
        .filter(|e| {
            ev_name(e) == "test.pass" && e.get("name").and_then(Value::as_str) == Some(name)
        })
        .count()
}

/// Combined boot + dual-closure + M1 assertion. Returns true iff all pass.
pub fn assert_boot(
    events: &[Value],
    exit_code: Option<i32>,
    expect_exit: i32,
    closures: &ExpectedClosures<'_>,
) -> bool {
    println!("\n== assertions ==");
    let mut ok = true;
    let sequence_mismatch =
        first_sequence_mismatch(events, &full_sequence()).map(|(index, expected)| {
            let observed = events
                .get(index)
                .map_or_else(|| "end-of-trace".to_string(), |event| event.to_string());
            format!(" (first mismatch at event {index}, expected {expected}: {observed})")
        });
    ok &= check(
        "seq contiguous strictly increasing from 0",
        contiguous_seq_from_zero(events),
    );
    ok &= check(
        "required events present exactly once",
        required_events_once(events),
    );
    ok &= check(
        "boot.entry is first kernel event",
        events.first().map(ev_name) == Some("boot.entry"),
    );
    ok &= check(
        &format!("exact full event sequence{sequence_mismatch:?}"),
        sequence_mismatch.is_none(),
    );
    ok &= check("halt is terminal", halt_is_terminal(events));
    ok &= check(
        "paging.wx rodata_nx_w=false && text_w=false",
        wx_holds(events),
    );
    let ticks = count_named(events, "apic.timer.tick");
    ok &= check(
        &format!("exactly 8 apic.timer.tick (got {ticks})"),
        ticks == 8,
    );
    ok &= check(
        "no test.fail (including unknown names)",
        !any_test_fail(events),
    );
    ok &= self_tests_hold(events);
    ok &= check("domain lifecycle evidence", domain_lifecycle_holds(events));
    let halt_ok = events.last().is_some_and(|e| {
        ev_name(e) == "halt" && e.get("outcome").and_then(Value::as_str) == Some("ok")
    });
    ok &= check("halt outcome=ok", halt_ok);
    ok &= check(
        &format!("QEMU exit code == {expect_exit}"),
        exit_code == Some(expect_exit),
    );
    ok &= closure_holds(events, closures);
    ok
}

fn closure_holds(events: &[Value], closures: &ExpectedClosures<'_>) -> bool {
    let mut ok = true;
    ok &= check(
        "one event for each success-bound milestone",
        SUCCESS_BOUND_EVENTS
            .iter()
            .all(|name| count_named(events, name) == 1),
    );
    ok &= check(
        "no closure.reject",
        count_named(events, "closure.reject") == 0,
    );
    let kernel_ev = events.iter().find(|e| ev_name(e) == "closure.kernel");
    let sysgen_ev = events.iter().find(|e| ev_name(e) == "closure.sysgen");
    let bound_ev = events.iter().find(|e| ev_name(e) == "closure.bound");
    let handoff_ev = events.iter().find(|e| ev_name(e) == "handoff.bound");
    ok &= check(
        "handoff.bound generation and measurements match loader",
        handoff_ev.is_some_and(|e| {
            e.get("policy_generation").and_then(Value::as_u64) == Some(closures.policy_generation)
                && e.get("kernel_image").and_then(Value::as_str) == Some(closures.kernel_image_hex)
                && e.get("closure_table").and_then(Value::as_str)
                    == Some(closures.closure_table_hex)
        }),
    );
    ok &= check(
        "closure.kernel kind, floor, and id match loader",
        kernel_ev.is_some_and(|e| {
            e.get("kind").and_then(Value::as_str) == Some("kernel-bootstrap")
                && e.get("floor").and_then(Value::as_u64) == Some(closures.kernel_floor)
                && e.get("id").and_then(Value::as_str) == Some(closures.kernel_id_hex)
        }),
    );
    ok &= check(
        "closure.sysgen non-empty descriptor, floor, and id match loader",
        sysgen_ev.is_some_and(|e| {
            e.get("kind").and_then(Value::as_str) == Some("system-generation")
                && e.get("empty") == Some(&Value::Bool(false))
                && e.get("floor").and_then(Value::as_u64) == Some(closures.sysgen_floor)
                && e.get("id").and_then(Value::as_str) == Some(closures.sysgen_id_hex)
        }),
    );
    ok &= check(
        "closure.bound keeps independent floors and distinct identities",
        bound_ev.is_some_and(|e| {
            e.get("kernel_floor").and_then(Value::as_u64) == Some(closures.kernel_floor)
                && e.get("sysgen_floor").and_then(Value::as_u64) == Some(closures.sysgen_floor)
                && e.get("kernel_id").and_then(Value::as_str) == Some(closures.kernel_id_hex)
                && e.get("sysgen_id").and_then(Value::as_str) == Some(closures.sysgen_id_hex)
                && closures.kernel_id_hex != closures.sysgen_id_hex
                && e.get("floor").is_none()
        }),
    );
    ok
}

fn check(label: &str, pass: bool) -> bool {
    println!("  [{}] {label}", if pass { "PASS" } else { "FAIL" });
    pass
}

fn wx_holds(events: &[Value]) -> bool {
    events
        .iter()
        .find(|e| ev_name(e) == "paging.wx")
        .is_some_and(|e| {
            e.get("rodata_nx_w") == Some(&Value::Bool(false))
                && e.get("text_w") == Some(&Value::Bool(false))
        })
}

fn self_tests_hold(events: &[Value]) -> bool {
    let mut ok = true;
    for name in REQUIRED_PASSES
        .iter()
        .chain(DOMAIN_REQUIRED_PASSES)
        .chain(EXTRA_REQUIRED_PASSES)
    {
        let n = test_pass_count(events, name);
        ok &= check(&format!("exactly one test.pass {name} (got {n})"), n == 1);
    }
    ok
}

#[cfg(test)]
mod tests;
