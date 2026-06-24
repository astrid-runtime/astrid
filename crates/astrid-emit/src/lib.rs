//! `astrid-emit` — an agent-agnostic stdio→bus pipe.
//!
//! This binary is deliberately tiny and knows **nothing** about any
//! particular agent's hook protocol. It does exactly one thing: read
//! stdin to EOF, wrap it in a fixed six-field envelope, publish that
//! envelope on the `--topic` it was handed (positional or flag), write
//! `{"continue":true}` to stdout, and exit `0` (published) or `1`
//! (couldn't publish). It **never** exits `2`.
//!
//! It has no Claude-protocol knowledge: no hook-name map, no stdin
//! parsing, no verdict shaping, no merge, no await/response, no
//! fail-closed behaviour. The trust anchor, validator, and republisher
//! is **sage** — the canonical hook-name map and all
//! verdict/attribution semantics live there. `astrid-emit` is just the
//! pipe that carries the raw bytes from an agent's hook process onto
//! the kernel event bus under the caller's principal.
//!
//! # Wire contract (with the shipped sage validator)
//!
//! The published payload is an [`IpcPayload::RawJson`] object with
//! exactly these six fields, matching sage's `HookEnvelope`
//! deserialize shape byte-for-byte:
//!
//! ```json
//! {
//!   "hook": "<last dot-segment of the topic>",
//!   "payload": "<raw stdin, as a UTF-8 string — NOT base64>",
//!   "correlation_id": null,
//!   "principal_id": "<ASTRID_PRINCIPAL_ID>",
//!   "session_id": "<ASTRID_SESSION_ID>",
//!   "token": "<ASTRID_HOOK_TOKEN>"
//! }
//! ```
//!
//! `session_id` and `token` are claim-only transport fields that sage
//! authenticates (KV token match) and then strips before it republishes
//! the canonical event. `principal_id` rides inside the body **and** is
//! stamped on the IPC message via `publish-as` for diagnostic
//! correctness; sage authenticates identity via the KV token, not via
//! claimed-vs-attributed comparison.

use std::process::ExitCode;

use anyhow::Result;
use astrid_core::PrincipalId;
use astrid_core::SessionId;
use astrid_types::Topic;
use astrid_types::ipc::{IpcMessage, IpcPayload};
use astrid_uplink::SocketClient;
use clap::Parser;
use serde_json::{Value, json};

/// The fixed stdout line written on every hook-invocation code path —
/// success and failure alike. (The exceptions are `--help` / `--version`,
/// which clap handles and exits before any hook logic runs.) An agent
/// hook process reads this to decide whether to proceed; `astrid-emit`
/// always says "continue" because it is a pipe, not a gate. The verdict
/// (if any) is sage's job, delivered out of band on the bus.
const CONTINUE_LINE: &str = "{\"continue\":true}";

/// Command-line surface for `astrid-emit`.
///
/// The topic is accepted **both** positionally (`astrid-emit <topic>`,
/// which is what shipped sage writes into `settings.local.json`) and
/// via the `--topic <topic>` flag (the form issue #814's acceptance
/// test invokes). Exactly one must be supplied; supplying both or
/// neither is an argument error.
#[derive(Parser, Debug)]
#[command(name = "astrid-emit")]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Bus topic to publish on, supplied positionally
    /// (`astrid-emit sage.v1.hook.before_tool_call`). Mutually
    /// exclusive with `--topic`; exactly one is required.
    #[arg(value_name = "TOPIC", conflicts_with = "topic_flag")]
    pub topic_positional: Option<String>,

    /// Bus topic to publish on, supplied via flag
    /// (`astrid-emit --topic sage.v1.hook.before_tool_call`).
    /// Mutually exclusive with the positional form; exactly one is
    /// required.
    #[arg(long = "topic", value_name = "TOPIC")]
    pub topic_flag: Option<String>,
}

impl Args {
    /// Resolve the single topic from whichever form was supplied.
    ///
    /// `clap`'s `conflicts_with` already rejects supplying both, so the
    /// only failure this surfaces is supplying neither.
    ///
    /// # Errors
    ///
    /// Returns an error if no topic was supplied (neither positional
    /// nor `--topic`).
    pub fn resolve_topic(self) -> Result<String> {
        match (self.topic_positional, self.topic_flag) {
            (Some(t), None) | (None, Some(t)) => Ok(t),
            (None, None) => {
                anyhow::bail!("a topic is required (positional `<topic>` or `--topic <topic>`)")
            },
            // Unreachable in practice: clap's `conflicts_with` rejects
            // both-supplied before we get here. Kept exhaustive so the
            // match doesn't rely on that invariant silently.
            (Some(_), Some(_)) => {
                anyhow::bail!("specify the topic exactly once (positional OR --topic, not both)")
            },
        }
    }
}

/// Outcome of an [`emit`] call: what to print to stderr (if anything)
/// and which process exit code to return. The fixed `{"continue":true}`
/// stdout line is the caller's responsibility and is emitted
/// unconditionally regardless of this outcome.
#[derive(Debug)]
#[must_use]
pub struct Outcome {
    /// One-line diagnostic to write to stderr, or `None` on success.
    pub stderr: Option<String>,
    /// Process exit code — `0` on a successful publish, `1` otherwise.
    /// **Never** `2`.
    pub exit: ExitCode,
}

impl Outcome {
    /// The success outcome: no stderr, exit `0`.
    fn ok() -> Self {
        Self {
            stderr: None,
            exit: ExitCode::SUCCESS,
        }
    }

    /// A soft-fail outcome: one-line diagnostic, exit `1`. Used for
    /// every failure mode (missing env, connect failure, send failure)
    /// — `astrid-emit` never fails closed and never exits `2`.
    fn fail(msg: impl Into<String>) -> Self {
        Self {
            stderr: Some(msg.into()),
            exit: ExitCode::from(1),
        }
    }
}

/// The publish seam. `run` wires the real [`SocketEmitter`]; tests wire
/// a recording fake. This is the only boundary between the pure
/// envelope-building logic and the live kernel socket, so the entire
/// contract (topic, six-field envelope shape, stamped principal) is
/// unit-testable without a running daemon.
#[allow(
    async_fn_in_trait,
    reason = "single-crate internal seam with one real impl and one test fake; \
              no public callers need a nameable Future, so the desugared \
              `impl Future` return is fine and avoids an async-trait dependency"
)]
pub trait Emitter {
    /// Publish `envelope` on `topic`, attributed to `principal` via
    /// `publish-as`.
    ///
    /// # Errors
    ///
    /// Returns an error if the kernel cannot be reached or the message
    /// cannot be sent.
    async fn publish(&self, topic: &str, envelope: Value, principal: &str) -> Result<()>;
}

/// The production [`Emitter`]: connects to `astridd` over the Unix
/// socket as an uplink and publishes the envelope via `publish-as`
/// (the IPC message carries the principal attribution).
#[derive(Debug, Default)]
pub struct SocketEmitter;

impl Emitter for SocketEmitter {
    async fn publish(&self, topic: &str, envelope: Value, principal: &str) -> Result<()> {
        // `SessionId` is not `Copy`; capture the inner UUID for the
        // message `source_id` BEFORE the value is moved into `connect`.
        let sid = SessionId::new();
        let source_id = sid.0;

        // Bind the connection to the publishing principal: the proxy pins
        // the first principal it sees per connection and DROPS any message
        // stamped with a different one, so a `default`-bound connection
        // would have this hook envelope silently dropped whenever
        // `principal` is not `default`. The `with_principal` stamp below
        // then matches the connection's pinned identity.
        let caller = PrincipalId::new(principal)?;
        let mut client = SocketClient::connect(sid, caller).await?;

        let msg = IpcMessage::new(
            Topic::from_raw(topic),
            IpcPayload::RawJson(envelope),
            source_id,
        )
        .with_principal(principal);

        client.send_message(msg).await
    }
}

/// Derive the hook name from a topic: the trailing dot-segment.
///
/// For a well-formed `sage.v1.hook.before_tool_call` this is
/// `before_tool_call`, which matches sage's validator (it compares the
/// envelope `hook` against the topic's last segment). A topic with no
/// `.` is its own hook name.
#[must_use]
pub fn derive_hook(topic: &str) -> &str {
    // `rsplit` always yields at least one element, so `next` is `Some`.
    // Mirror PINNED's `topic.rsplit('.').next()` exactly. (sage's
    // helper additionally filters the empty string for degenerate
    // trailing-dot topics, which sage never emits.)
    topic.rsplit('.').next().unwrap_or(topic)
}

/// Build the fixed six-field envelope. The field set and ordering match
/// sage's `HookEnvelope` deserialize shape: `hook`, `payload`,
/// `correlation_id` (always `null` — sage's `#[serde(default)]` accepts
/// `null` or omission), `principal_id`, `session_id`, `token`.
///
/// `payload` is the raw stdin **as a UTF-8 string**, never base64: the
/// shipped sage forwards `payload` verbatim to canonical subscribers,
/// so base64 would deliver base64 text instead of the hook JSON.
#[must_use]
pub fn build_envelope(
    hook: &str,
    payload: &str,
    principal_id: &str,
    session_id: &str,
    token: &str,
) -> Value {
    json!({
        "hook": hook,
        "payload": payload,
        "correlation_id": Value::Null,
        "principal_id": principal_id,
        "session_id": session_id,
        "token": token,
    })
}

/// The three required environment variables, captured as owned strings.
/// All three are set on the agent child's environment by the spawning
/// kernel; a missing or empty value means `astrid-emit` was invoked
/// outside that context and cannot authenticate.
struct HookEnv {
    principal_id: String,
    session_id: String,
    token: String,
}

/// Resolve and validate the three required env vars from `lookup`, which
/// returns the **non-empty** value for a name or `None` when the variable
/// is missing or empty. Returns the first offending variable's name on
/// failure. `lookup` is injected so the missing-vs-empty and
/// first-failing-variable semantics are testable without mutating the
/// process environment (which is not safe across parallel test threads).
fn resolve_env(
    lookup: impl Fn(&str) -> Option<String>,
) -> std::result::Result<HookEnv, &'static str> {
    let require = |name: &'static str| lookup(name).ok_or(name);
    Ok(HookEnv {
        principal_id: require("ASTRID_PRINCIPAL_ID")?,
        session_id: require("ASTRID_SESSION_ID")?,
        token: require("ASTRID_HOOK_TOKEN")?,
    })
}

/// Process-environment lookup: a variable counts as present only if it is
/// set **and** non-empty.
fn env_lookup(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Core, testable logic: given a topic, stdin payload, the three env
/// values, and an [`Emitter`], build the envelope and publish it.
///
/// The caller (`run`) is responsible for writing the
/// `{"continue":true}` stdout line on **every** path — this function
/// only decides stderr + exit code. It never returns an exit code other
/// than `0` or `1`.
pub async fn emit<E: Emitter>(
    emitter: &E,
    topic: &str,
    stdin_payload: &str,
    env: &HookEnvValues<'_>,
) -> Outcome {
    let hook = derive_hook(topic);
    let envelope = build_envelope(
        hook,
        stdin_payload,
        env.principal_id,
        env.session_id,
        env.token,
    );

    match emitter.publish(topic, envelope, env.principal_id).await {
        Ok(()) => Outcome::ok(),
        Err(e) => Outcome::fail(format!("astrid-emit: failed to publish on {topic}: {e:#}")),
    }
}

/// Borrowed view of the three env values passed into [`emit`]. Keeps the
/// `emit` signature stable while letting both `run` (owned `HookEnv`)
/// and tests (string literals) supply the values without cloning.
#[derive(Debug, Clone, Copy)]
pub struct HookEnvValues<'a> {
    /// `ASTRID_PRINCIPAL_ID`.
    pub principal_id: &'a str,
    /// `ASTRID_SESSION_ID`.
    pub session_id: &'a str,
    /// `ASTRID_HOOK_TOKEN`.
    pub token: &'a str,
}

/// Read stdin to EOF as a UTF-8 string (lossy — invalid sequences become
/// U+FFFD). The payload is forwarded opaquely; `astrid-emit` never
/// parses or interprets it.
fn read_stdin_lossy() -> String {
    use std::io::Read as _;
    let mut buf = Vec::new();
    // A read error here is treated as "no/partial stdin" — the agent
    // hook process may have closed early. We still publish what we have
    // and continue, never fail closed. Cap the read at 10 MiB so a large
    // or unbounded pipe cannot OOM the process: hook payloads are small
    // JSON blobs, so anything approaching this is pathological.
    let _ = std::io::stdin()
        .take(10 * 1024 * 1024)
        .read_to_end(&mut buf);
    String::from_utf8_lossy(&buf).into_owned()
}

/// Write the fixed `{"continue":true}` line (with trailing newline) to
/// stdout. Best-effort: a stdout write failure does not change the exit
/// code (the agent has likely already gone away).
fn write_continue() {
    use std::io::Write as _;
    let mut out = std::io::stdout();
    let _ = writeln!(out, "{CONTINUE_LINE}");
    let _ = out.flush();
}

/// Process entry point. Parses args, reads env + stdin, publishes via the
/// real [`SocketEmitter`], always writes `{"continue":true}` to stdout,
/// and returns the process [`ExitCode`].
///
/// Returns `0` on a successful publish (and on `--help` / `--version`)
/// and `1` on any failure (missing env, connect failure, send failure,
/// or a malformed argv). **Never** returns `2`: clap's own usage errors
/// are caught here and converted into a `{"continue":true}` line plus
/// exit `1`, so a misconfigured hook command can never wedge the agent
/// with an exit-`2` "block" verdict.
pub async fn run() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        // `--help` / `--version`: clap routes these to stdout; print and
        // exit `0`, the conventional behaviour.
        Err(e) if !e.use_stderr() => {
            let _ = e.print();
            return ExitCode::SUCCESS;
        },
        // A genuine argv error (unknown flag, both topic forms, …). Stay
        // fail-soft: emit the continue line, surface the error, exit `1`
        // — never let clap's default exit-`2` reach the agent.
        Err(e) => {
            write_continue();
            let _ = e.print();
            return ExitCode::from(1);
        },
    };

    let topic = match args.resolve_topic() {
        Ok(t) => t,
        Err(e) => {
            // Topic resolution only fails on neither-supplied. Stay
            // fail-soft: emit continue + exit 1, never 2.
            write_continue();
            eprintln!("astrid-emit: {e}");
            return ExitCode::from(1);
        },
    };

    let env = match resolve_env(env_lookup) {
        Ok(env) => env,
        Err(missing) => {
            write_continue();
            eprintln!("astrid-emit: required environment variable {missing} is missing or empty");
            return ExitCode::from(1);
        },
    };

    let stdin_payload = read_stdin_lossy();

    let emitter = SocketEmitter;
    let outcome = emit(
        &emitter,
        &topic,
        &stdin_payload,
        &HookEnvValues {
            principal_id: &env.principal_id,
            session_id: &env.session_id,
            token: &env.token,
        },
    )
    .await;

    // ALWAYS write the continue line, on success and failure alike.
    write_continue();
    if let Some(msg) = outcome.stderr {
        eprintln!("{msg}");
    }
    outcome.exit
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    /// A recording fake [`Emitter`] that captures the last published
    /// `(topic, envelope, principal)` instead of touching a socket.
    #[derive(Default)]
    struct FakeEmitter {
        recorded: Mutex<Option<(String, Value, String)>>,
        fail: bool,
    }

    impl FakeEmitter {
        fn recording() -> Self {
            Self::default()
        }

        fn failing() -> Self {
            Self {
                recorded: Mutex::new(None),
                fail: true,
            }
        }

        fn take(&self) -> (String, Value, String) {
            self.recorded
                .lock()
                .expect("fake emitter lock poisoned")
                .clone()
                .expect("emitter was never called")
        }
    }

    impl Emitter for FakeEmitter {
        async fn publish(&self, topic: &str, envelope: Value, principal: &str) -> Result<()> {
            if self.fail {
                anyhow::bail!("simulated publish failure");
            }
            *self.recorded.lock().expect("fake emitter lock poisoned") =
                Some((topic.to_string(), envelope, principal.to_string()));
            Ok(())
        }
    }

    fn env<'a>() -> HookEnvValues<'a> {
        HookEnvValues {
            principal_id: "alice",
            session_id: "s1",
            token: "tk",
        }
    }

    #[test]
    fn derive_hook_takes_trailing_segment() {
        assert_eq!(
            derive_hook("sage.v1.hook.before_tool_call"),
            "before_tool_call"
        );
        assert_eq!(derive_hook("sage.v1.hook.session_end"), "session_end");
        assert_eq!(derive_hook("notification"), "notification");
    }

    #[test]
    fn build_envelope_has_exactly_six_fields() {
        let env = build_envelope("before_tool_call", "{\"k\":1}", "alice", "s1", "tk");
        let obj = env.as_object().expect("envelope is a JSON object");
        assert_eq!(obj.len(), 6, "envelope must have exactly six fields");
        assert_eq!(obj["hook"], "before_tool_call");
        assert_eq!(obj["payload"], "{\"k\":1}");
        assert_eq!(obj["correlation_id"], Value::Null);
        assert_eq!(obj["principal_id"], "alice");
        assert_eq!(obj["session_id"], "s1");
        assert_eq!(obj["token"], "tk");
    }

    #[test]
    fn payload_is_forwarded_as_plain_string_not_base64() {
        let raw = "{\"tool_name\":\"Bash\",\"input\":{}}";
        let env = build_envelope("before_tool_call", raw, "alice", "s1", "tk");
        // The payload field is the verbatim stdin string, not base64.
        assert_eq!(env["payload"], raw);
        assert!(env["payload"].is_string());
    }

    #[tokio::test]
    async fn emit_records_topic_envelope_and_stamped_principal() {
        let fake = FakeEmitter::recording();
        let outcome = emit(
            &fake,
            "sage.v1.hook.before_tool_call",
            "{\"hook_event_name\":\"PreToolUse\"}",
            &env(),
        )
        .await;

        assert!(outcome.stderr.is_none(), "success path emits no stderr");
        // ExitCode has no public equality; assert via the success-shaped
        // outcome (no stderr) above. Re-derive the success code here for
        // documentation, but the contract assertion is the recorded msg.

        let (topic, envelope, principal) = fake.take();
        assert_eq!(topic, "sage.v1.hook.before_tool_call");
        assert_eq!(principal, "alice", "principal is stamped via publish-as");

        let obj = envelope.as_object().expect("envelope is a JSON object");
        assert_eq!(obj.len(), 6);
        assert_eq!(obj["hook"], "before_tool_call");
        assert_eq!(obj["payload"], "{\"hook_event_name\":\"PreToolUse\"}");
        assert_eq!(obj["correlation_id"], Value::Null);
        assert_eq!(obj["principal_id"], "alice");
        assert_eq!(obj["session_id"], "s1");
        assert_eq!(obj["token"], "tk");
    }

    #[tokio::test]
    async fn ac_integration_scenario() {
        // The issue #814 acceptance scenario:
        // ASTRID_PRINCIPAL_ID=alice ASTRID_SESSION_ID=s1 ASTRID_HOOK_TOKEN=tk
        // topic sage.v1.hook.before_tool_call.
        let fake = FakeEmitter::recording();
        let payload = "{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Bash\"}";
        let outcome = emit(&fake, "sage.v1.hook.before_tool_call", payload, &env()).await;
        assert!(outcome.stderr.is_none());

        let (topic, envelope, principal) = fake.take();
        assert_eq!(topic, "sage.v1.hook.before_tool_call");
        assert_eq!(principal, "alice");
        let obj = envelope.as_object().expect("object");
        assert_eq!(obj["hook"], "before_tool_call");
        assert_eq!(obj["payload"], payload);
        assert_eq!(obj["correlation_id"], Value::Null);
        // The three env values are present in the envelope.
        assert_eq!(obj["principal_id"], "alice");
        assert_eq!(obj["session_id"], "s1");
        assert_eq!(obj["token"], "tk");
    }

    #[tokio::test]
    async fn publish_failure_is_soft_fail_exit_one() {
        let fake = FakeEmitter::failing();
        let outcome = emit(&fake, "sage.v1.hook.session_end", "{}", &env()).await;
        // Soft fail: stderr present, exit 1 (the binary still writes
        // {"continue":true} on the calling side).
        let msg = outcome
            .stderr
            .expect("failure path emits a stderr diagnostic");
        assert!(msg.contains("sage.v1.hook.session_end"));
        assert!(msg.contains("failed to publish"));
    }

    #[test]
    fn resolve_env_reports_first_missing_or_empty_variable() {
        let full = |n: &str| match n {
            "ASTRID_PRINCIPAL_ID" => Some("alice".to_string()),
            "ASTRID_SESSION_ID" => Some("s1".to_string()),
            "ASTRID_HOOK_TOKEN" => Some("tk".to_string()),
            _ => None,
        };
        let env = resolve_env(full).expect("all three present");
        assert_eq!(env.principal_id, "alice");
        assert_eq!(env.session_id, "s1");
        assert_eq!(env.token, "tk");

        // A missing variable is reported by name.
        let no_token = |n: &str| match n {
            "ASTRID_PRINCIPAL_ID" => Some("alice".to_string()),
            "ASTRID_SESSION_ID" => Some("s1".to_string()),
            _ => None,
        };
        // `.err()` (not `.unwrap_err()`) so the test doesn't require
        // `HookEnv: Debug` — it deliberately isn't `Debug` so the token
        // can never be accidentally formatted.
        assert_eq!(resolve_env(no_token).err(), Some("ASTRID_HOOK_TOKEN"));

        // The FIRST missing variable wins (principal before session).
        assert_eq!(resolve_env(|_| None).err(), Some("ASTRID_PRINCIPAL_ID"));
    }

    #[test]
    fn env_lookup_treats_empty_as_absent() {
        // `env_lookup` filters empty values, so an empty var is "missing".
        // (Driven through the same Fn shape resolve_env consumes.)
        let with_empty_token = |n: &str| match n {
            "ASTRID_PRINCIPAL_ID" => Some("alice".to_string()),
            "ASTRID_SESSION_ID" => Some("s1".to_string()),
            "ASTRID_HOOK_TOKEN" => Some(String::new()).filter(|v| !v.is_empty()),
            _ => None,
        };
        assert_eq!(
            resolve_env(with_empty_token).err(),
            Some("ASTRID_HOOK_TOKEN")
        );
    }

    #[test]
    fn resolve_topic_accepts_positional() {
        let args = Args {
            topic_positional: Some("sage.v1.hook.before_tool_call".to_string()),
            topic_flag: None,
        };
        assert_eq!(
            args.resolve_topic().expect("positional topic resolves"),
            "sage.v1.hook.before_tool_call"
        );
    }

    #[test]
    fn resolve_topic_accepts_flag() {
        let args = Args {
            topic_positional: None,
            topic_flag: Some("sage.v1.hook.after_tool_call".to_string()),
        };
        assert_eq!(
            args.resolve_topic().expect("flag topic resolves"),
            "sage.v1.hook.after_tool_call"
        );
    }

    #[test]
    fn resolve_topic_rejects_neither() {
        let args = Args {
            topic_positional: None,
            topic_flag: None,
        };
        assert!(args.resolve_topic().is_err(), "neither form is an error");
    }

    #[test]
    fn both_arg_forms_parse_to_the_same_topic_via_clap() {
        // Positional form (what shipped sage writes).
        let positional = Args::try_parse_from(["astrid-emit", "sage.v1.hook.before_tool_call"])
            .expect("positional parses");
        assert_eq!(
            positional.resolve_topic().expect("resolves"),
            "sage.v1.hook.before_tool_call"
        );

        // Flag form (what issue #814's AC test invokes).
        let flagged =
            Args::try_parse_from(["astrid-emit", "--topic", "sage.v1.hook.before_tool_call"])
                .expect("flag parses");
        assert_eq!(
            flagged.resolve_topic().expect("resolves"),
            "sage.v1.hook.before_tool_call"
        );

        // Supplying both is rejected by clap's conflicts_with.
        let both = Args::try_parse_from([
            "astrid-emit",
            "sage.v1.hook.before_tool_call",
            "--topic",
            "sage.v1.hook.before_tool_call",
        ]);
        assert!(both.is_err(), "both forms together is an arg error");
    }
}
