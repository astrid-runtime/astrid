//! Exact event-order pattern for the full positive boot trace.

use serde_json::Value;

use super::{
    DOMAIN_REQUIRED_PASSES, EXTRA_REQUIRED_PASSES, REQUIRED_PASSES, ev_name, string_field,
};

/// A strict name-only walker first, so every field assertion below operates
/// on a trace whose event kinds are already in the machine's exact order.
#[derive(Clone, Copy)]
pub(super) enum SequenceStep {
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

pub(super) fn walk_sequence(events: &[Value], pattern: &[SequenceStep]) -> bool {
    first_sequence_mismatch(events, pattern).is_none()
}

pub(super) fn first_sequence_mismatch(
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
const IPC_PARK_EVENT: &str = "ipc.park";
const IPC_SERVER_RESUME_TAIL_EVENTS: &[&str] = &["ipc.wake", "ipc.resume", "ipc.op", "ipc.park"];
const IPC_PARK_TAIL_EVENTS: &[&str] = &["relations.projection", "ipc.op", "ipc.park"];
const IPC_CLIENT_RESUME_TAIL_EVENTS: &[&str] = &[
    "ipc.wake",
    "ipc.resume",
    "domain.registers",
    "domain.outcome",
    "ipc.reclaim",
    "domain.restore",
    "domain.reclaim",
];
const IPC_SERVER_PEER_RELEASE_TAIL_EVENTS: &[&str] =
    &["ipc.reclaim", "domain.restore", "domain.reclaim"];
const IPC_FAULT_CLIENT_TAIL_EVENTS: &[&str] = &[
    "domain.registers",
    "domain.outcome",
    "ipc.reclaim",
    "domain.restore",
    "domain.reclaim",
];
const IPC_CANCEL_GUEST_OPS: &[&str] = &["relations.projection", "ipc.op", "ipc.op"];
const IPC_CLIENT_OPS: &[&str] = &[
    "ipc.op",
    "ipc.op",
    "ipc.op",
    "relations.projection",
    "ipc.op",
    "ipc.op",
    "ipc.op",
    "ipc.op",
    "ipc.op",
];
const IPC_CANCEL_GUEST_TAIL_EVENTS: &[&str] = &[
    "domain.registers",
    "domain.outcome",
    "ipc.reclaim",
    "domain.restore",
    "domain.reclaim",
];
const RUNNING_STOP_TAIL_EVENTS: &[&str] = &[
    "domain.control.returned",
    "domain.stop.request",
    "domain.stop.taken",
    "domain.outcome",
    "domain.stop.relation-retired",
    "domain.restore",
    "domain.reclaim",
    "domain.stop.admission-released",
    "domain.stop.current-inactive",
    "domain.stop.completed",
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

pub(super) fn full_sequence() -> Vec<SequenceStep> {
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
    push_started(&mut pattern);
    pattern.push(SequenceStep::Many(GUEST_ENTRY_EVENTS));
    pattern.push(SequenceStep::Many(IPC_PARK_TAIL_EVENTS));
    push_started(&mut pattern);
    pattern.push(SequenceStep::Many(GUEST_ENTRY_EVENTS));
    pattern.push(SequenceStep::Many(IPC_CLIENT_OPS));
    pattern.push(SequenceStep::One(IPC_PARK_EVENT));
    pattern.push(SequenceStep::Many(IPC_SERVER_RESUME_TAIL_EVENTS));
    pattern.push(SequenceStep::Many(IPC_CLIENT_RESUME_TAIL_EVENTS));
    pattern.push(SequenceStep::Many(IPC_SERVER_PEER_RELEASE_TAIL_EVENTS));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[8]));
    push_started(&mut pattern);
    pattern.push(SequenceStep::Many(GUEST_ENTRY_EVENTS));
    pattern.push(SequenceStep::Many(IPC_PARK_TAIL_EVENTS));
    push_started(&mut pattern);
    pattern.push(SequenceStep::Many(GUEST_ENTRY_EVENTS));
    pattern.push(SequenceStep::Many(IPC_FAULT_CLIENT_TAIL_EVENTS));
    pattern.push(SequenceStep::Many(IPC_SERVER_PEER_RELEASE_TAIL_EVENTS));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[9]));
    push_started(&mut pattern);
    pattern.push(SequenceStep::Many(GUEST_ENTRY_EVENTS));
    pattern.push(SequenceStep::Many(IPC_CANCEL_GUEST_OPS));
    pattern.push(SequenceStep::Many(IPC_CANCEL_GUEST_TAIL_EVENTS));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[10]));
    pattern.push(SequenceStep::Many(PREPARE_EVENTS));
    pattern.push(SequenceStep::One("domain.stop.staged"));
    pattern.push(SequenceStep::One("domain.stop.armed"));
    pattern.push(SequenceStep::One(START_EVENT));
    pattern.push(SequenceStep::Many(GUEST_ENTRY_EVENTS));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[12]));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[13]));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[14]));
    pattern.push(SequenceStep::Many(RUNNING_STOP_TAIL_EVENTS));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[11]));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[15]));
    pattern.push(SequenceStep::Pass(DOMAIN_REQUIRED_PASSES[7]));
    pattern.extend([
        SequenceStep::One("domain.harness"),
        SequenceStep::One("halt"),
    ]);
    pattern
}
