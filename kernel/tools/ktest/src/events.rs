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
    for name in REQUIRED_PASSES {
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
        for name in REQUIRED_PASSES {
            ev(format!("\"ev\":\"test.pass\",\"name\":\"{name}\""));
        }
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
    fn dual_closure_missing_bound_fails() {
        let serial =
            passing_serial().replace("\"ev\":\"closure.bound\"", "\"ev\":\"closure.kernel\"");
        assert!(!assert_ok(&serial));
    }
}
