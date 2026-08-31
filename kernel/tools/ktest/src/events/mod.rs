//! Parse JSONL serial events and assert the combined boot evidence contract.
//!
//! One sequence covers boot, both closure identities/floors, bound, M1
//! milestones, and terminal halt. Sequence numbers must be contiguous and
//! strictly increasing from 0. `halt` is terminal. Any `test.fail`, including
//! unknown future names, fails. Required events must appear exactly once.
//! Reordered closure/M1 events fail.

use serde_json::Value;

mod closure;
mod lifecycle;
mod relations_gate;
mod sequence;

use lifecycle::domain_lifecycle_holds;
#[cfg(test)]
use lifecycle::{HOSTILE_IPC_FAULT_ADDRESS, HOSTILE_PEER_FAULT_ADDRESS};
use sequence::{SequenceStep, first_sequence_mismatch, full_sequence, walk_sequence};

use {closure::closure_holds, relations_gate::relations_projection_holds};
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
    "authenticated_domains_exchange_bounded_capability_message",
    "peer_fault_wakes_blocked_recv_with_typed_status",
    "cancel_reclaims_blocked_ipc_exactly_once",
    "returned_control_stop_reclaims_exactly_once",
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
    "component.bound",
    "handoff.bound",
    "closure.kernel",
    "closure.sysgen",
    "closure.bound",
];

const RING0_REJECT_ORDER: &[&str] = &["boot.entry", "idt.ready", "closure.reject", "halt"];

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

pub(super) fn check(label: &str, pass: bool) -> bool {
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
