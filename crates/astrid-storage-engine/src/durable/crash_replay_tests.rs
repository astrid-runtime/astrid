//! Exhaustive byte-prefix replay for the durable commit protocol.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use super::tests::{TestIdentity, Utf8Codec, limits, open, transaction};
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceFile {
    Arena,
    Roots,
}

impl TraceFile {
    const fn name(self) -> &'static str {
        match self {
            Self::Arena => ARENA_FILE,
            Self::Roots => ROOT_FILE,
        }
    }

    const fn magic(self) -> [u8; 8] {
        match self {
            Self::Arena => ARENA_MAGIC,
            Self::Roots => ROOT_MAGIC,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct StoreImage {
    arena: Vec<u8>,
    roots: Vec<u8>,
}

impl StoreImage {
    fn capture(directory: &Path) -> std::io::Result<Self> {
        Ok(Self {
            arena: read_or_empty(&directory.join(ARENA_FILE))?,
            roots: read_or_empty(&directory.join(ROOT_FILE))?,
        })
    }

    fn bytes(&self, file: TraceFile) -> &[u8] {
        match file {
            TraceFile::Arena => &self.arena,
            TraceFile::Roots => &self.roots,
        }
    }

    fn bytes_mut(&mut self, file: TraceFile) -> &mut Vec<u8> {
        match file {
            TraceFile::Arena => &mut self.arena,
            TraceFile::Roots => &mut self.roots,
        }
    }

    fn install(&self, directory: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(directory)?;
        std::fs::write(directory.join(ARENA_FILE), &self.arena)?;
        std::fs::write(directory.join(ROOT_FILE), &self.roots)
    }
}

fn read_or_empty(path: &Path) -> std::io::Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

#[derive(Clone, Debug)]
struct BoundaryObservation {
    point: FaultPoint,
    image: StoreImage,
}

#[derive(Debug)]
struct TraceRecorder {
    directory: PathBuf,
    observations: Mutex<Vec<BoundaryObservation>>,
}

impl TraceRecorder {
    fn new(directory: &Path) -> Self {
        Self {
            directory: directory.to_path_buf(),
            observations: Mutex::new(Vec::new()),
        }
    }

    fn observations(&self) -> Vec<BoundaryObservation> {
        self.observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl FaultInjector for TraceRecorder {
    fn should_fail(&self, point: FaultPoint) -> bool {
        let image = StoreImage::capture(&self.directory)
            .unwrap_or_else(|error| panic!("capture durable trace at {point:?}: {error}"));
        self.observations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(BoundaryObservation { point, image });
        false
    }
}

#[derive(Clone, Debug)]
enum TraceEvent {
    Append {
        file: TraceFile,
        offset: usize,
        bytes: Vec<u8>,
    },
    Flush(TraceFile),
    Acknowledged,
}

#[derive(Clone, Debug)]
struct DurableWriteTrace {
    initial: StoreImage,
    events: Vec<TraceEvent>,
}

impl DurableWriteTrace {
    fn from_observations(
        initial: StoreImage,
        observations: &[BoundaryObservation],
        acknowledged: &StoreImage,
    ) -> Result<Self, String> {
        let expected = [
            FaultPoint::AfterObjectAppend,
            FaultPoint::AfterCommitAppend,
            FaultPoint::AfterObjectFlush,
            FaultPoint::AfterCommitFlush,
            FaultPoint::BeforeRootCas,
            FaultPoint::AfterRootCas,
        ];
        if observations.len() != expected.len() {
            return Err(format!(
                "expected {} trace boundaries, observed {}",
                expected.len(),
                observations.len()
            ));
        }
        let mut current = initial.clone();
        let mut events = Vec::new();
        for (observation, expected_point) in observations.iter().zip(expected) {
            if observation.point != expected_point {
                return Err(format!(
                    "expected boundary {expected_point:?}, observed {:?}",
                    observation.point
                ));
            }
            match observation.point {
                FaultPoint::AfterObjectAppend | FaultPoint::AfterCommitAppend => {
                    append_delta(
                        &mut events,
                        &mut current,
                        &observation.image,
                        TraceFile::Arena,
                    )?;
                },
                FaultPoint::AfterObjectFlush => {
                    require_same(&current, &observation.image, observation.point)?;
                    events.push(TraceEvent::Flush(TraceFile::Arena));
                },
                FaultPoint::AfterCommitFlush | FaultPoint::BeforeRootCas => {
                    require_same(&current, &observation.image, observation.point)?;
                },
                FaultPoint::AfterRootCas => {
                    append_delta(
                        &mut events,
                        &mut current,
                        &observation.image,
                        TraceFile::Roots,
                    )?;
                    events.push(TraceEvent::Flush(TraceFile::Roots));
                },
                _ => {
                    return Err(format!(
                        "unexpected commit trace point: {:?}",
                        observation.point
                    ));
                },
            }
        }
        require_same(&current, acknowledged, FaultPoint::AfterRootCas)?;
        events.push(TraceEvent::Acknowledged);
        Ok(Self { initial, events })
    }

    fn crash_cases(&self) -> Result<Vec<CrashCase>, String> {
        let mut durable = self.initial.clone();
        let mut working = self.initial.clone();
        let mut cases = Vec::new();
        for (event_index, event) in self.events.iter().enumerate() {
            match event {
                TraceEvent::Append {
                    file,
                    offset,
                    bytes,
                } => {
                    if working.bytes(*file).len() != *offset {
                        return Err(format!(
                            "event {event_index} appends {} at {offset}, current length is {}",
                            file.name(),
                            working.bytes(*file).len()
                        ));
                    }
                    for persisted in 0..=bytes.len() {
                        let mut image = durable.clone();
                        let target = image.bytes_mut(*file);
                        target.clear();
                        target.extend_from_slice(working.bytes(*file));
                        target.extend_from_slice(&bytes[..persisted]);
                        cases.push(CrashCase::recoverable(
                            format!(
                                "event-{event_index}-{}-byte-prefix-{persisted}",
                                file.name()
                            ),
                            image,
                        ));
                    }
                    cases.extend(tail_mutation_cases(
                        event_index,
                        &durable,
                        &working,
                        *file,
                        bytes,
                    )?);
                    cases.extend(interior_corruption_cases(
                        event_index,
                        durable.clone(),
                        &working,
                        *file,
                        bytes,
                    )?);
                    working.bytes_mut(*file).extend_from_slice(bytes);
                },
                TraceEvent::Flush(file) => {
                    *durable.bytes_mut(*file) = working.bytes(*file).to_vec();
                },
                TraceEvent::Acknowledged => {
                    if durable != working {
                        return Err("acknowledgement preceded a durability boundary".to_owned());
                    }
                    cases.push(CrashCase::acknowledged(
                        format!("event-{event_index}-acknowledged"),
                        durable.clone(),
                    ));
                },
            }
        }
        Ok(cases)
    }
}

fn append_delta(
    events: &mut Vec<TraceEvent>,
    current: &mut StoreImage,
    observed: &StoreImage,
    file: TraceFile,
) -> Result<(), String> {
    let other = match file {
        TraceFile::Arena => TraceFile::Roots,
        TraceFile::Roots => TraceFile::Arena,
    };
    if current.bytes(other) != observed.bytes(other) {
        return Err(format!(
            "{} changed at the {} append boundary",
            other.name(),
            file.name()
        ));
    }
    let before = current.bytes(file);
    let after = observed.bytes(file);
    if !after.starts_with(before) {
        return Err(format!("{} write was not append-only", file.name()));
    }
    let bytes = after[before.len()..].to_vec();
    if bytes.is_empty() {
        return Err(format!("{} append boundary wrote no bytes", file.name()));
    }
    events.push(TraceEvent::Append {
        file,
        offset: before.len(),
        bytes,
    });
    *current = observed.clone();
    Ok(())
}

fn require_same(
    expected: &StoreImage,
    observed: &StoreImage,
    point: FaultPoint,
) -> Result<(), String> {
    if expected == observed {
        Ok(())
    } else {
        Err(format!("authority files changed unexpectedly at {point:?}"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedRecovery {
    Recoverable,
    Acknowledged,
    InteriorCorruption,
}

#[derive(Clone, Debug)]
struct CrashCase {
    label: String,
    image: StoreImage,
    expected: ExpectedRecovery,
}

impl CrashCase {
    fn recoverable(label: String, image: StoreImage) -> Self {
        Self {
            label,
            image,
            expected: ExpectedRecovery::Recoverable,
        }
    }

    fn acknowledged(label: String, image: StoreImage) -> Self {
        Self {
            label,
            image,
            expected: ExpectedRecovery::Acknowledged,
        }
    }

    fn interior(label: String, image: StoreImage) -> Self {
        Self {
            label,
            image,
            expected: ExpectedRecovery::InteriorCorruption,
        }
    }
}

fn tail_mutation_cases(
    event_index: usize,
    durable: &StoreImage,
    working: &StoreImage,
    file: TraceFile,
    appended: &[u8],
) -> Result<Vec<CrashCase>, String> {
    let spans = frame_spans(appended, file.magic())?;
    let last = spans
        .last()
        .ok_or_else(|| format!("{} append contained no frames", file.name()))?;
    let payload_start = last
        .start
        .checked_add(FRAME_HEADER_LEN_USIZE)
        .ok_or_else(|| "tail payload offset overflow".to_owned())?;
    let mut mutations = Vec::new();

    let mut zeroed = appended.to_vec();
    zeroed[payload_start..last.end].fill(0);
    mutations.push(("zeroed-tail-payload", zeroed));

    let mut stale = appended.to_vec();
    stale[payload_start..last.end].fill(0xa5);
    ensure_changed(&mut stale, appended, payload_start, last.end);
    mutations.push(("stale-tail-payload", stale));

    let mut reordered = appended.to_vec();
    let payload = &mut reordered[payload_start..last.end];
    if payload.len() >= 16 {
        let (head, rest) = payload.split_at_mut(8);
        let tail_start = rest
            .len()
            .checked_sub(8)
            .expect("payload length was checked before splitting");
        head.swap_with_slice(&mut rest[tail_start..]);
    } else {
        payload.reverse();
    }
    ensure_changed(&mut reordered, appended, payload_start, last.end);
    mutations.push(("reordered-tail-blocks", reordered));

    Ok(mutations
        .into_iter()
        .map(|(name, bytes)| {
            let mut image = durable.clone();
            let target = image.bytes_mut(file);
            target.clear();
            target.extend_from_slice(working.bytes(file));
            target.extend_from_slice(&bytes);
            CrashCase::recoverable(format!("event-{event_index}-{}-{name}", file.name()), image)
        })
        .collect())
}

fn ensure_changed(mutated: &mut [u8], original: &[u8], start: usize, end: usize) {
    if mutated == original && start < end {
        mutated[start] ^= 0x80;
    }
}

fn interior_corruption_cases(
    event_index: usize,
    durable: StoreImage,
    working: &StoreImage,
    file: TraceFile,
    appended: &[u8],
) -> Result<Vec<CrashCase>, String> {
    let spans = frame_spans(appended, file.magic())?;
    if spans.len() < 2 {
        return Ok(Vec::new());
    }
    let first_payload = spans[0]
        .start
        .checked_add(FRAME_HEADER_LEN_USIZE)
        .ok_or_else(|| "interior payload offset overflow".to_owned())?;
    if first_payload == spans[0].end {
        return Err("cannot corrupt an empty interior frame payload".to_owned());
    }
    let mut corrupted = appended.to_vec();
    corrupted[first_payload] ^= 0x80;
    let mut image = durable;
    let target = image.bytes_mut(file);
    target.clear();
    target.extend_from_slice(working.bytes(file));
    target.extend_from_slice(&corrupted);
    Ok(vec![CrashCase::interior(
        format!("event-{event_index}-{}-corrupt-interior-frame", file.name()),
        image,
    )])
}

fn frame_spans(bytes: &[u8], magic: [u8; 8]) -> Result<Vec<std::ops::Range<usize>>, String> {
    let mut spans = Vec::new();
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let header_end = offset
            .checked_add(FRAME_HEADER_LEN_USIZE)
            .ok_or_else(|| "frame header offset overflow".to_owned())?;
        let header = bytes
            .get(offset..header_end)
            .ok_or_else(|| "recorded append ends inside a frame header".to_owned())?;
        if header[..8] != magic {
            return Err(format!(
                "recorded {} append has invalid magic",
                TraceMagic(magic)
            ));
        }
        let payload_len = u64::from_le_bytes(
            header[12..20]
                .try_into()
                .map_err(|_| "recorded frame length is malformed".to_owned())?,
        );
        let payload_len = usize::try_from(payload_len)
            .map_err(|_| "recorded frame length is not addressable".to_owned())?;
        let end = header_end
            .checked_add(payload_len)
            .ok_or_else(|| "recorded frame end overflow".to_owned())?;
        if end > bytes.len() {
            return Err("recorded append ends inside a frame payload".to_owned());
        }
        spans.push(offset..end);
        offset = end;
    }
    Ok(spans)
}

fn pre_fix_strict_scan(bytes: &[u8], magic: [u8; 8]) -> Result<(), &'static str> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let Some(header_end) = offset.checked_add(FRAME_HEADER_LEN_USIZE) else {
            return Err("header offset overflow");
        };
        let Some(header) = bytes.get(offset..header_end) else {
            return Ok(());
        };
        if header[..8] != magic {
            return Err("magic mismatch");
        }
        let payload_len_u64 = u64::from_le_bytes(
            header[12..20]
                .try_into()
                .map_err(|_| "invalid payload length")?,
        );
        let payload_len =
            usize::try_from(payload_len_u64).map_err(|_| "payload is not addressable")?;
        let Some(frame_end) = header_end.checked_add(payload_len) else {
            return Err("frame offset overflow");
        };
        let Some(payload) = bytes.get(header_end..frame_end) else {
            return Ok(());
        };
        let expected: [u8; 32] = header[CHECKSUM_START..]
            .try_into()
            .map_err(|_| "invalid checksum width")?;
        if frame_checksum(magic, payload_len_u64, payload) != expected {
            return Err("checksum mismatch");
        }
        offset = frame_end;
    }
    Ok(())
}

struct TraceMagic([u8; 8]);

impl fmt::Display for TraceMagic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:02x?}", self.0)
    }
}

#[derive(Clone, Debug)]
struct RootExpectation {
    principal: String,
    before: Option<RootState>,
    after: Option<RootState>,
}

fn replay_all(trace: &DurableWriteTrace, roots: &[RootExpectation]) {
    let cases = trace.crash_cases().unwrap();
    assert!(cases.len() > 100, "trace did not exercise byte prefixes");
    for case in cases {
        replay_case(&case, roots);
    }
}

fn replay_case(case: &CrashCase, roots: &[RootExpectation]) {
    let directory = tempfile::tempdir().unwrap();
    case.image.install(directory.path()).unwrap();
    let outcome = match case.expected {
        ExpectedRecovery::Recoverable | ExpectedRecovery::Acknowledged => {
            verify_recoverable(directory.path(), roots, case.expected)
        },
        ExpectedRecovery::InteriorCorruption => verify_interior_corruption(directory.path()),
    };
    if let Err(detail) = outcome {
        let retained = directory.keep();
        panic!(
            "crash replay failed for {}: {detail}; image retained at {}",
            case.label,
            retained.display()
        );
    }
}

fn verify_recoverable(
    directory: &Path,
    roots: &[RootExpectation],
    expected: ExpectedRecovery,
) -> Result<(), String> {
    let first = DurableEngine::open(directory, TestIdentity, Utf8Codec, limits())
        .map_err(|error| format!("first reopen rejected a recoverable image: {error}"))?;
    let first_roots = verify_roots(&first, roots, expected)?;
    drop(first);
    let repaired = StoreImage::capture(directory)
        .map_err(|error| format!("capture repaired authority files: {error}"))?;

    let second = DurableEngine::open(directory, TestIdentity, Utf8Codec, limits())
        .map_err(|error| format!("second reopen rejected repaired image: {error}"))?;
    let second_roots = verify_roots(&second, roots, expected)?;
    drop(second);
    if first_roots != second_roots {
        return Err("reopening the repaired image changed visible roots".to_owned());
    }
    let twice_repaired = StoreImage::capture(directory)
        .map_err(|error| format!("capture twice-repaired authority files: {error}"))?;
    if repaired != twice_repaired {
        return Err("reopening the repaired image was not idempotent".to_owned());
    }
    Ok(())
}

fn verify_roots(
    engine: &DurableEngine<String, TestIdentity, Utf8Codec>,
    roots: &[RootExpectation],
    expected: ExpectedRecovery,
) -> Result<BTreeMap<String, Option<RootState>>, String> {
    let mut visible = BTreeMap::new();
    for expectation in roots {
        let actual = engine
            .root(&expectation.principal)
            .map_err(|error| format!("read recovered root: {error}"))?;
        let accepted = if expected == ExpectedRecovery::Acknowledged {
            actual == expectation.after
        } else {
            actual == expectation.before || actual == expectation.after
        };
        if !accepted {
            return Err(format!(
                "principal {} recovered invented or rolled-back root {actual:?}; before={:?}, after={:?}",
                expectation.principal, expectation.before, expectation.after
            ));
        }
        match engine
            .snapshot(&expectation.principal)
            .map_err(|error| format!("validate recovered closure: {error}"))?
        {
            Some(snapshot) if Some(snapshot.root()) == actual => {},
            None if actual.is_none() => {},
            snapshot => {
                return Err(format!(
                    "root/closure snapshot mismatch for {}: {snapshot:?}",
                    expectation.principal
                ));
            },
        }
        visible.insert(expectation.principal.clone(), actual);
    }
    Ok(visible)
}

fn verify_interior_corruption(directory: &Path) -> Result<(), String> {
    let before = StoreImage::capture(directory)
        .map_err(|error| format!("capture corrupt authority files: {error}"))?;
    for attempt in 1..=2 {
        match DurableEngine::open(directory, TestIdentity, Utf8Codec, limits()) {
            Err(DurableError::Corrupt { .. }) => {},
            Err(error) => {
                return Err(format!(
                    "attempt {attempt} returned the wrong corruption error: {error}"
                ));
            },
            Ok(_) => return Err(format!("attempt {attempt} accepted interior corruption")),
        }
        let after = StoreImage::capture(directory)
            .map_err(|error| format!("capture authority files after rejection: {error}"))?;
        if after != before {
            return Err(format!(
                "attempt {attempt} mutated an interior-corrupt authority file"
            ));
        }
    }
    Ok(())
}

fn record_single_update(
    directory: &Path,
    principal: &str,
    expected: Option<RootState>,
    payload: &[u8],
) -> (DurableWriteTrace, RootState) {
    let initial = StoreImage::capture(directory).unwrap();
    let recorder = Arc::new(TraceRecorder::new(directory));
    let faults: Arc<dyn FaultInjector> = recorder.clone();
    let engine = DurableEngine::open_with_options(
        directory,
        TestIdentity,
        Utf8Codec,
        limits(),
        faults,
        ObjectCacheConfig::disabled(),
        GroupCommitPolicy::immediate(),
    )
    .unwrap();
    let (_, transaction) = transaction(principal, expected, payload);
    let root = engine.commit(transaction).unwrap().root();
    let acknowledged = StoreImage::capture(directory).unwrap();
    drop(engine);
    (
        DurableWriteTrace::from_observations(initial, &recorder.observations(), &acknowledged)
            .unwrap(),
        root,
    )
}

fn wait_for_queued_commits(
    engine: &DurableEngine<String, TestIdentity, Utf8Codec>,
    expected: usize,
) {
    let started = Instant::now();
    while engine.queued_commit_count() < expected {
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "timed out waiting for {expected} deterministic trace entries"
        );
        thread::yield_now();
    }
}

#[test]
fn every_single_commit_byte_prefix_recovers_old_or_new_complete_root() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, first) = transaction("alice", None, b"acknowledged-before");
    let before = engine.commit(first).unwrap().root();
    drop(engine);

    let (trace, after) = record_single_update(
        directory.path(),
        "alice",
        Some(before),
        b"unacknowledged-after",
    );
    let roots = [RootExpectation {
        principal: "alice".to_owned(),
        before: Some(before),
        after: Some(after),
    }];
    let zeroed_tail = trace
        .crash_cases()
        .unwrap()
        .into_iter()
        .find(|case| case.label.contains(ARENA_FILE) && case.label.ends_with("zeroed-tail-payload"))
        .unwrap();
    assert_eq!(
        pre_fix_strict_scan(&zeroed_tail.image.arena, ARENA_MAGIC),
        Err("checksum mismatch"),
        "the historical strict scanner must reject the synthetic torn tail"
    );
    replay_case(&zeroed_tail, &roots);
    replay_all(&trace, &roots);
}

#[test]
fn every_second_commit_byte_prefix_preserves_the_first_acknowledgement() {
    let directory = tempfile::tempdir().unwrap();
    let engine = open(directory.path());
    let (_, first) = transaction("alice", None, b"generation-zero");
    let first = engine.commit(first).unwrap().root();
    drop(engine);

    let (trace, second) =
        record_single_update(directory.path(), "alice", Some(first), b"generation-one");
    replay_all(
        &trace,
        &[RootExpectation {
            principal: "alice".to_owned(),
            before: Some(first),
            after: Some(second),
        }],
    );
}

#[test]
fn grouped_commit_prefixes_never_invent_or_partially_acknowledge_roots() {
    let directory = tempfile::tempdir().unwrap();
    let initial = StoreImage::capture(directory.path()).unwrap();
    let recorder = Arc::new(TraceRecorder::new(directory.path()));
    let faults: Arc<dyn FaultInjector> = recorder.clone();
    let engine = Arc::new(
        DurableEngine::open_with_options(
            directory.path(),
            TestIdentity,
            Utf8Codec,
            limits(),
            faults,
            ObjectCacheConfig::disabled(),
            GroupCommitPolicy::new(Duration::from_millis(100)),
        )
        .unwrap(),
    );
    let mut workers = Vec::new();
    let mut starts = Vec::new();
    for value in 0_u8..4 {
        let engine = Arc::clone(&engine);
        let (start, release) = mpsc::sync_channel(0);
        starts.push(start);
        workers.push(thread::spawn(move || {
            let principal = format!("principal-{value}");
            let (_, transaction) = transaction(&principal, None, &[value]);
            release.recv().unwrap();
            (principal, engine.commit(transaction).unwrap().root())
        }));
    }
    for (index, start) in starts.into_iter().enumerate() {
        start.send(()).unwrap();
        wait_for_queued_commits(&engine, index + 1);
    }
    let mut roots = Vec::new();
    for worker in workers {
        let (principal, after) = worker.join().unwrap();
        roots.push(RootExpectation {
            principal,
            before: None,
            after: Some(after),
        });
    }
    let acknowledged = StoreImage::capture(directory.path()).unwrap();
    drop(engine);
    let trace =
        DurableWriteTrace::from_observations(initial, &recorder.observations(), &acknowledged)
            .unwrap();

    replay_all(&trace, &roots);
}
