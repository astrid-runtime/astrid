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
    "halt",
];

const COMBINED_ORDER: &[&str] = &[
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

const SUCCESS_BOUND_EVENTS: &[&str] = &[
    "handoff.bound",
    "closure.kernel",
    "closure.sysgen",
    "closure.bound",
];

const RING0_REJECT_ORDER: &[&str] = &["boot.entry", "idt.ready", "closure.reject", "halt"];

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
        && SUCCESS_BOUND_EVENTS
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

fn domain_outcomes_hold(events: &[Value]) -> bool {
    let counts = [
        ("clean_exit", 3),
        ("invalid_instruction", 1),
        ("page_fault", 2),
        ("quota_exhausted", 1),
        ("cancelled", 1),
    ];
    let mut ok = true;
    for (kind, expected) in counts {
        let observed = named_events(events, "domain.outcome")
            .into_iter()
            .filter(|event| string_field(event, "kind") == Some(kind))
            .count();
        ok &= observed == expected;
    }
    let page_fault_addresses: Vec<&str> = named_events(events, "domain.outcome")
        .into_iter()
        .filter(|event| string_field(event, "kind") == Some("page_fault"))
        .filter_map(|event| string_field(event, "fault_address"))
        .collect();
    ok &= page_fault_addresses == ["0x0", HOSTILE_PEER_FAULT_ADDRESS];
    ok
}

fn domain_audits_hold(events: &[Value]) -> bool {
    named_events(events, "domain.audit")
        .into_iter()
        .all(|event| {
            u64_field(event, "frames").is_some_and(|frames| frames > 0)
                && bool_field(event, "wx_ok") == Some(true)
                && bool_field(event, "kernel_excluded") == Some(true)
                && bool_field(event, "peer_excluded") == Some(true)
        })
}

fn domain_exclusions_hold(events: &[Value]) -> bool {
    named_events(events, "domain.exclusion")
        .into_iter()
        .all(|event| {
            bool_field(event, "alias_excluded") == Some(true)
                && bool_field(event, "kernel_excluded") == Some(true)
                && bool_field(event, "peer_excluded") == Some(true)
        })
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
            string_field(event, "rsp").is_some_and(|rsp| rsp.starts_with("0x"))
                && u64_field(event, "cpl") == Some(3)
        });
    let outcomes_ok = domain_outcomes_hold(events);
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
    let restores_ok = named_events(events, "domain.restore").len() == DOMAIN_RECLAIMS.len()
        && all_bools(events, "domain.restore", "ok", true);
    let audits_ok = domain_audits_hold(events);
    let exclusions_ok = domain_exclusions_hold(events);
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
    ok &= check("exact domain outcomes and fault addresses", outcomes_ok);
    ok &= check("exact reclaim generations and accounting", reclaims_ok);
    ok &= check("restores accompany every reclaim", restores_ok);
    ok &= check("domain page-table audits", audits_ok);
    ok &= check("domain exclusion evidence", exclusions_ok);
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
        "boot.entry<idt.ready<closure.reject<halt",
        ordered(events, RING0_REJECT_ORDER),
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
        "boot.entry<idt.ready<handoff.bound<closure.kernel<closure.sysgen<closure.bound<mem.map<paging.wx<heap.ready<halt",
        ordered(events, COMBINED_ORDER),
    );
    ok &= check("halt is terminal", halt_is_terminal(events));
    ok &= check(
        "paging.wx rodata_nx_w=false && text_w=false",
        wx_holds(events),
    );
    let ticks = count_named(events, "apic.timer.tick");
    ok &= check(&format!(">=8 apic.timer.tick (got {ticks})"), ticks >= 8);
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
    for name in REQUIRED_PASSES.iter().chain(DOMAIN_REQUIRED_PASSES) {
        let n = test_pass_count(events, name);
        ok &= check(&format!("exactly one test.pass {name} (got {n})"), n == 1);
    }
    ok
}

fn ordered(events: &[Value], names: &[&str]) -> bool {
    let mut last = -1i64;
    for name in names {
        match events.iter().position(|e| ev_name(e) == *name) {
            Some(idx) if (idx as i64) > last => last = idx as i64,
            _ => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const KERNEL_IMAGE_ID: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const CLOSURE_TABLE_ID: &str =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    fn kernel_id() -> String {
        "aa".repeat(32)
    }

    fn sysgen_id() -> String {
        "bb".repeat(32)
    }

    fn expected() -> ExpectedClosures<'static> {
        ExpectedClosures {
            policy_generation: 1,
            kernel_image_hex: KERNEL_IMAGE_ID,
            closure_table_hex: CLOSURE_TABLE_ID,
            kernel_id_hex: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            sysgen_id_hex: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            kernel_floor: 1,
            sysgen_floor: 1,
        }
    }

    fn passing_serial() -> String {
        passing_serial_with(&kernel_id(), &sysgen_id(), 1, 1)
    }

    fn passing_serial_with(kernel: &str, sysgen: &str, kfloor: u64, sfloor: u64) -> String {
        let mut seq = 0u64;
        let mut out = String::new();
        let mut ev = |payload: String| {
            out.push_str(&format!("{{\"seq\":{seq},{payload}}}\n"));
            seq += 1;
        };
        ev("\"ev\":\"boot.entry\"".into());
        ev("\"ev\":\"idt.ready\",\"vectors\":32".into());
        ev("\"ev\":\"component.bound\",\"empty\":false".into());
        ev(format!(
            "\"ev\":\"handoff.bound\",\"policy_generation\":1,\"kernel_image\":\"{}\",\"closure_table\":\"{}\"",
            "cc".repeat(32),
            "dd".repeat(32),
        ));
        ev(format!(
            "\"ev\":\"closure.kernel\",\"kind\":\"kernel-bootstrap\",\"floor\":{kfloor},\"id\":\"{kernel}\""
        ));
        ev(format!(
            "\"ev\":\"closure.sysgen\",\"kind\":\"system-generation\",\"floor\":{sfloor},\"id\":\"{sysgen}\",\"empty\":false"
        ));
        ev(format!(
            "\"ev\":\"closure.bound\",\"kernel_floor\":{kfloor},\"sysgen_floor\":{sfloor},\"kernel_id\":\"{kernel}\",\"sysgen_id\":\"{sysgen}\""
        ));
        ev("\"ev\":\"mem.map\",\"usable_regions\":1,\"usable_bytes\":1".into());
        ev("\"ev\":\"paging.wx\",\"rodata_nx_w\":false,\"text_w\":false".into());
        ev("\"ev\":\"heap.ready\",\"bytes\":1048576".into());
        for n in 1..=8 {
            ev(format!("\"ev\":\"apic.timer.tick\",\"n\":{n}"));
        }
        ev("\"ev\":\"domain.auth.reject\",\"reason\":\"tampered_component_rejected\"".into());
        for name in REQUIRED_PASSES {
            ev(format!("\"ev\":\"test.pass\",\"name\":\"{name}\""));
        }
        for name in &DOMAIN_REQUIRED_PASSES[..DOMAIN_REQUIRED_PASSES.len() - 1] {
            ev(format!("\"ev\":\"test.pass\",\"name\":\"{name}\""));
        }
        for (id, generation, scenario) in DOMAIN_STARTS {
            ev(format!(
                "\"ev\":\"domain.start\",\"id\":{id},\"generation\":{generation},\"scenario\":{scenario}"
            ));
        }
        for (id, generation) in DOMAIN_ENTERED {
            ev(format!(
                "\"ev\":\"domain.entered\",\"id\":{id},\"generation\":{generation},\"cpl\":3"
            ));
        }
        for (id, generation, rdi) in DOMAIN_REGISTERS {
            ev(format!(
                "\"ev\":\"domain.registers\",\"id\":{id},\"generation\":{generation},\"cpl\":3,\"rdi\":{rdi},\"rsp\":\"0x1000\""
            ));
        }
        for (kind, vector, error, address) in [
            ("clean_exit", 3, 0, "0x0"),
            ("invalid_instruction", 6, 0, "0x0"),
            ("page_fault", 14, 4, "0x0"),
            ("cancelled", 0, 0, "0x0"),
            ("quota_exhausted", 32, 0, "0x0"),
            ("clean_exit", 3, 0, "0x0"),
            ("page_fault", 14, 4, HOSTILE_PEER_FAULT_ADDRESS),
            ("clean_exit", 3, 0, "0x0"),
        ] {
            ev(format!(
                "\"ev\":\"domain.outcome\",\"kind\":\"{kind}\",\"vector\":{vector},\"error_code\":{error},\"fault_address\":\"{address}\",\"rip\":\"0x0\",\"cpl\":3"
            ));
        }
        for _ in DOMAIN_RECLAIMS {
            ev("\"ev\":\"domain.restore\",\"ok\":true".into());
        }
        for (id, generation) in DOMAIN_RECLAIMS {
            ev(format!(
                "\"ev\":\"domain.reclaim\",\"id\":{id},\"generation\":{generation},\"expected\":16,\"freed\":16,\"swept\":16,\"blocked\":0"
            ));
        }
        for _ in DOMAIN_RECLAIMS {
            ev("\"ev\":\"domain.audit\",\"frames\":16,\"wx_ok\":true,\"kernel_excluded\":true,\"peer_excluded\":true".into());
            ev("\"ev\":\"domain.exclusion\",\"alias_excluded\":true,\"kernel_excluded\":true,\"peer_excluded\":true".into());
        }
        ev(format!(
            "\"ev\":\"test.pass\",\"name\":\"{}\"",
            DOMAIN_REQUIRED_PASSES[DOMAIN_REQUIRED_PASSES.len() - 1]
        ));
        ev("\"ev\":\"domain.harness\",\"outcome\":true".into());
        ev("\"ev\":\"halt\",\"outcome\":\"ok\"".into());
        out
    }

    fn assert_ok(serial: &str) -> bool {
        assert_boot(&parse_events(serial), Some(33), 33, &expected())
    }

    #[test]
    fn parses_jsonl_and_skips_firmware_noise() {
        let serial = "Welcome to EDK2\n{\"seq\":0,\"ev\":\"boot.entry\"}\nnot json\n";
        let events = parse_events(serial);
        assert_eq!(events.len(), 1);
        assert_eq!(ev_name(&events[0]), "boot.entry");
    }

    #[test]
    fn combined_fixture_passes() {
        assert!(assert_ok(&passing_serial()));
    }

    #[test]
    fn mixed_floors_on_bound_are_independent() {
        let kernel = kernel_id();
        let sysgen = sysgen_id();
        let serial = passing_serial_with(&kernel, &sysgen, 1, 2);
        let closures = ExpectedClosures {
            policy_generation: 1,
            kernel_image_hex: KERNEL_IMAGE_ID,
            closure_table_hex: CLOSURE_TABLE_ID,
            kernel_id_hex: &kernel,
            sysgen_id_hex: &sysgen,
            kernel_floor: 1,
            sysgen_floor: 2,
        };
        assert!(assert_boot(&parse_events(&serial), Some(33), 33, &closures));
    }

    #[test]
    fn collapsed_bound_floor_fails() {
        let serial =
            passing_serial().replace("\"kernel_floor\":1,\"sysgen_floor\":1", "\"floor\":1");
        assert!(!assert_ok(&serial));
    }

    #[test]
    fn wx_violation_fails() {
        let serial = passing_serial().replace("\"rodata_nx_w\":false", "\"rodata_nx_w\":true");
        assert!(!assert_ok(&serial));
    }

    #[test]
    fn sequence_gap_reorder_or_duplicate_fails() {
        let gap = passing_serial().replacen("\"seq\":5,", "\"seq\":50,", 1);
        let duplicate = passing_serial().replacen("\"seq\":5,", "\"seq\":4,", 1);
        let reorder = passing_serial().replacen("\"seq\":5,", "\"seq\":7,", 1);
        let reorder = reorder.replacen("\"seq\":6,", "\"seq\":5,", 1);
        assert!(!assert_ok(&gap), "gap must fail");
        assert!(!assert_ok(&duplicate), "duplicate seq must fail");
        assert!(!assert_ok(&reorder), "reordered seq must fail");
    }

    #[test]
    fn post_halt_event_fails() {
        let mut serial = passing_serial();
        serial.push_str(r#"{"seq":99,"ev":"apic.timer.tick","n":9}"#);
        serial.push('\n');
        assert!(!assert_ok(&serial));
    }

    #[test]
    fn test_fail_future_gate_fails() {
        let serial = passing_serial().replace(
            "\"ev\":\"halt\",\"outcome\":\"ok\"",
            "\"ev\":\"test.fail\",\"name\":\"future_gate\"}\n{\"seq\":99,\"ev\":\"halt\",\"outcome\":\"ok\"",
        );
        assert!(serial.contains("future_gate"));
        assert!(!assert_ok(&serial));
    }

    #[test]
    fn missing_or_duplicate_domain_gate_fails() {
        let missing = passing_serial().replacen(
            "\"ev\":\"test.pass\",\"name\":\"fault_is_domain_scoped\"}\n",
            "",
            1,
        );
        assert!(!assert_ok(&missing), "missing domain gate must fail");

        let duplicate = passing_serial().replace(
            "\"ev\":\"halt\",\"outcome\":\"ok\"",
            "\"ev\":\"test.pass\",\"name\":\"fault_is_domain_scoped\"}\n{\"seq\":99,\"ev\":\"halt\",\"outcome\":\"ok\"",
        );
        assert!(!assert_ok(&duplicate), "duplicate domain gate must fail");
    }

    #[test]
    fn duplicate_or_missing_required_event_fails() {
        let duplicate_boot =
            passing_serial().replacen("\"ev\":\"mem.map\"", "\"ev\":\"boot.entry\"", 1);
        let missing_map =
            passing_serial().replacen("\"ev\":\"mem.map\"", "\"ev\":\"apic.timer.start\"", 1);
        assert!(!assert_ok(&duplicate_boot));
        assert!(!assert_ok(&missing_map));
    }

    #[test]
    fn reordered_closure_and_m1_events_fail() {
        let serial = passing_serial().replace("handoff.bound", "tmp.handoff");
        let serial = serial.replace("closure.kernel", "handoff.bound");
        let serial = serial.replace("tmp.handoff", "closure.kernel");
        assert!(
            !assert_ok(&serial),
            "handoff.bound after closure.kernel must fail"
        );
        let serial = passing_serial().replace("closure.bound", "tmp.bound");
        let serial = serial.replace("mem.map", "closure.bound");
        let serial = serial.replace("tmp.bound", "mem.map");
        assert!(!assert_ok(&serial), "closure.bound after mem.map must fail");
        let serial = passing_serial().replace("closure.kernel", "tmp.kernel");
        let serial = serial.replace("paging.wx", "closure.kernel");
        let serial = serial.replace("tmp.kernel", "paging.wx");
        assert!(
            !assert_ok(&serial),
            "closure.kernel after paging.wx must fail"
        );
    }

    #[test]
    fn dual_closure_reject_or_mismatch_fails() {
        let events = parse_events(&passing_serial());
        let swapped = ExpectedClosures {
            policy_generation: 1,
            kernel_image_hex: expected().kernel_image_hex,
            closure_table_hex: expected().closure_table_hex,
            kernel_id_hex: expected().sysgen_id_hex,
            sysgen_id_hex: expected().kernel_id_hex,
            kernel_floor: 1,
            sysgen_floor: 1,
        };
        assert!(!assert_boot(&events, Some(33), 33, &swapped));
        let rejected = passing_serial().replace("closure.bound", "closure.reject");
        assert!(!assert_ok(&rejected));
    }

    #[test]
    fn rejected_sysgen_emits_no_success_bound_events() {
        let serial = concat!(
            "{\"seq\":0,\"ev\":\"boot.entry\"}\n",
            "{\"seq\":1,\"ev\":\"idt.ready\",\"vectors\":32}\n",
            "{\"seq\":2,\"ev\":\"closure.reject\",\"reason\":\"binding\"}\n",
            "{\"seq\":3,\"ev\":\"halt\",\"outcome\":\"fail\"}\n",
        );
        let events = parse_events(serial);
        assert!(rejected_without_success_bound_events(&events));

        let contaminated = format!("{serial}{{\"seq\":4,\"ev\":\"handoff.bound\"}}\n");
        assert!(!rejected_without_success_bound_events(&parse_events(
            &contaminated
        )));
    }

    #[test]
    fn ring0_plan_mismatch_trace_requires_kernel_rejection_shape() {
        let serial = concat!(
            "{\"seq\":0,\"ev\":\"boot.entry\"}\n",
            "{\"seq\":1,\"ev\":\"idt.ready\",\"vectors\":32}\n",
            "{\"seq\":2,\"ev\":\"closure.reject\",\"reason\":\"plan_mismatch\"}\n",
            "{\"seq\":3,\"ev\":\"halt\",\"outcome\":\"fault\"}\n",
        );
        assert!(assert_ring0_plan_mismatch(&parse_events(serial), Some(35)));

        let loader_reject = serial.replace("plan_mismatch", "binding");
        assert!(!assert_ring0_plan_mismatch(
            &parse_events(&loader_reject),
            Some(35)
        ));
        let contaminated = format!("{}{{\"seq\":4,\"ev\":\"handoff.bound\"}}\n", serial);
        assert!(!assert_ring0_plan_mismatch(
            &parse_events(&contaminated),
            Some(35)
        ));
        let success_exit = serial.replace("\"outcome\":\"fault\"", "\"outcome\":\"ok\"");
        assert!(!assert_ring0_plan_mismatch(
            &parse_events(&success_exit),
            Some(33)
        ));
    }

    #[test]
    fn dual_closure_missing_bound_fails() {
        let serial =
            passing_serial().replace("\"ev\":\"closure.bound\"", "\"ev\":\"closure.kernel\"");
        assert!(!assert_ok(&serial));
    }
}
