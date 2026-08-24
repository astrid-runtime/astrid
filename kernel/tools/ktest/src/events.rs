//! Parse JSONL serial events and assert the M1 evidence contract.
//!
//! Sequence numbers must be contiguous and strictly increasing from 0.
//! `halt` is terminal. Any `test.fail`, including unknown future names, fails.
//! Required M1 events must appear exactly once.

use serde_json::Value;

const REQUIRED_ONCE: &[&str] = &[
    "boot.entry",
    "mem.map",
    "paging.wx",
    "heap.ready",
    "idt.ready",
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

/// Assert M1 boot/W^X/timer/self-test evidence. Returns true iff all pass.
pub fn assert_m1(events: &[Value], exit_code: Option<i32>, expect_exit: i32) -> bool {
    let mut ok = true;
    println!("\n== assertions ==");
    ok &= check(
        "seq contiguous strictly increasing from 0",
        contiguous_seq_from_zero(events),
    );
    ok &= check(
        "required M1 events present exactly once",
        required_events_once(events),
    );
    ok &= check(
        "boot.entry is first kernel event",
        events.first().map(ev_name) == Some("boot.entry"),
    );
    ok &= check(
        "boot.entry<mem.map<paging.wx<heap.ready<idt.ready<halt",
        ordered(
            events,
            &[
                "boot.entry",
                "mem.map",
                "paging.wx",
                "heap.ready",
                "idt.ready",
                "halt",
            ],
        ),
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

    fn passing_serial() -> String {
        let mut out = String::from(
            r#"{"seq":0,"ev":"boot.entry"}
{"seq":1,"ev":"mem.map","usable_regions":1,"usable_bytes":1}
{"seq":2,"ev":"paging.wx","rodata_nx_w":false,"text_w":false}
{"seq":3,"ev":"heap.ready","bytes":1048576}
{"seq":4,"ev":"idt.ready","vectors":32}
"#,
        );
        for n in 1..=8 {
            out.push_str(&format!(
                "{{\"seq\":{},\"ev\":\"apic.timer.tick\",\"n\":{n}}}\n",
                4 + n
            ));
        }
        let mut seq = 13u64;
        for name in REQUIRED_PASSES {
            out.push_str(&format!(
                "{{\"seq\":{seq},\"ev\":\"test.pass\",\"name\":\"{name}\"}}\n"
            ));
            seq += 1;
        }
        out.push_str(&format!(
            "{{\"seq\":{seq},\"ev\":\"halt\",\"outcome\":\"ok\"}}\n"
        ));
        out
    }

    fn passing_events() -> Vec<Value> {
        parse_events(&passing_serial())
    }

    #[test]
    fn parses_jsonl_and_skips_firmware_noise() {
        let serial = "Welcome to EDK2\n{\"seq\":0,\"ev\":\"boot.entry\"}\nnot json\n";
        let events = parse_events(serial);
        assert_eq!(events.len(), 1);
        assert_eq!(ev_name(&events[0]), "boot.entry");
    }

    #[test]
    fn m1_fixture_passes() {
        assert!(assert_m1(&passing_events(), Some(33), 33));
    }

    #[test]
    fn wx_violation_fails() {
        let serial = r#"{"seq":0,"ev":"boot.entry"}
{"seq":1,"ev":"mem.map","usable_regions":1,"usable_bytes":1}
{"seq":2,"ev":"paging.wx","rodata_nx_w":true,"text_w":false}
{"seq":3,"ev":"heap.ready","bytes":1}
{"seq":4,"ev":"idt.ready","vectors":32}
{"seq":5,"ev":"halt","outcome":"ok"}"#;
        let events = parse_events(serial);
        assert!(!assert_m1(&events, Some(33), 33));
    }

    #[test]
    fn sequence_gap_reorder_or_duplicate_fails() {
        let gap = passing_serial().replacen("\"seq\":5,", "\"seq\":50,", 1);
        let duplicate = passing_serial().replacen("\"seq\":5,", "\"seq\":4,", 1);
        let reorder = passing_serial().replacen("\"seq\":5,", "\"seq\":7,", 1);
        let reorder = reorder.replacen("\"seq\":6,", "\"seq\":5,", 1);
        assert!(
            !assert_m1(&parse_events(&gap), Some(33), 33),
            "gap must fail"
        );
        assert!(
            !assert_m1(&parse_events(&duplicate), Some(33), 33),
            "duplicate seq must fail"
        );
        assert!(
            !assert_m1(&parse_events(&reorder), Some(33), 33),
            "reordered seq must fail"
        );
    }

    #[test]
    fn post_halt_event_fails() {
        let mut serial = passing_serial();
        serial.push_str(r#"{"seq":20,"ev":"apic.timer.tick","n":9}"#);
        serial.push('\n');
        assert!(!assert_m1(&parse_events(&serial), Some(33), 33));
    }

    #[test]
    fn test_fail_future_gate_fails() {
        let halt = "{\"seq\":19,\"ev\":\"halt\",\"outcome\":\"ok\"}\n";
        let injected = concat!(
            "{\"seq\":19,\"ev\":\"test.fail\",\"name\":\"future_gate\"}\n",
            "{\"seq\":20,\"ev\":\"halt\",\"outcome\":\"ok\"}\n",
        );
        let serial = passing_serial().replace(halt, injected);
        assert!(serial.contains("future_gate"));
        assert!(!assert_m1(&parse_events(&serial), Some(33), 33));
    }

    #[test]
    fn duplicate_or_missing_required_event_fails() {
        let duplicate_boot = passing_serial().replacen(
            "{\"seq\":1,\"ev\":\"mem.map\"",
            "{\"seq\":1,\"ev\":\"boot.entry\"",
            1,
        );
        let missing_map = passing_serial().replacen(
            "{\"seq\":1,\"ev\":\"mem.map\",\"usable_regions\":1,\"usable_bytes\":1}",
            "{\"seq\":1,\"ev\":\"apic.timer.start\"}",
            1,
        );
        assert!(!assert_m1(&parse_events(&duplicate_boot), Some(33), 33));
        assert!(!assert_m1(&parse_events(&missing_map), Some(33), 33));
    }
}
