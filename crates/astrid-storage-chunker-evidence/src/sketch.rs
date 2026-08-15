use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use astrid_storage::Blake3ObjectIdentityV1;
use astrid_storage::content_dag::{BuiltContent, ChunkingProfile, build_content};
use astrid_storage::engine::{
    BottomKSketchDescriptor, RefineryBatchContext, RefineryResourceBudget, RefinerySnapshotId,
    SketchSampleSize, SketchScoreWidth, build_bottom_k_sketch, verify_bottom_k_sketch,
};
use astrid_storage::storage_model::{
    ObjectId, ObjectIdentity, ObjectKind, ObjectRecord, PlacementEpoch,
};
use serde::Serialize;

use crate::corpus::{Corpus, CorpusKind};
use crate::throughput::{Timing, timing};

const SAMPLE_SIZES: &[u16] = &[16, 32, 64, 128, 256, 512];
const SCORE_WIDTHS: &[SketchScoreWidth] = &[SketchScoreWidth::Bits128, SketchScoreWidth::Bits256];
const DELTA_MAGIC: &[u8] = b"astrid-chunk-copy-delta-evidence-v1\0";

#[derive(Debug, Serialize)]
pub struct SketchEvidenceResult {
    pub corpus: String,
    pub corpus_kind: CorpusKind,
    pub score_width_bits: u16,
    pub sample_size: u16,
    pub files: u64,
    pub multi_chunk_targets: u64,
    pub corpus_logical_bytes: u64,
    pub source_logical_bytes: u64,
    pub source_retained_bytes_scanned: u64,
    pub sketch_retained_bytes: u64,
    pub pass_score_state_upper_bound_bytes: u64,
    pub build_elapsed_nanoseconds: u128,
    pub build_throughput: Timing,
    pub output_identity_hash: String,
    pub candidate_attempts: u64,
    pub useful_candidates_over_raw: u64,
    pub residual_improvements_over_lineage: Option<u64>,
    pub false_work_candidates: u64,
    pub no_delta_bytes: u64,
    pub lineage_delta_bytes: Option<u64>,
    pub random_delta_bytes: u64,
    pub resemblance_only_delta_bytes: u64,
    pub lineage_first_delta_bytes: Option<u64>,
}

#[derive(Clone)]
struct Version {
    file: ObjectId,
    logical_bytes: u64,
    records: Vec<(ObjectId, ObjectRecord)>,
    chunks: Vec<Chunk>,
}

#[derive(Clone, Copy)]
struct Chunk {
    id: ObjectId,
    offset: u64,
    length: u64,
}

struct MaterializedSketch {
    scores: Vec<[u8; 32]>,
    output: ObjectId,
    retained_bytes: u64,
    scanned_bytes: u64,
    elapsed: Duration,
}

struct SketchBuildTotals {
    sketches: Vec<Option<MaterializedSketch>>,
    scanned_bytes: u64,
    retained_bytes: u64,
    elapsed: Duration,
    output_hasher: blake3::Hasher,
}

#[derive(Default)]
struct DeltaTotals {
    targets: u64,
    candidate_attempts: u64,
    useful_candidates_over_raw: u64,
    residual_improvements_over_lineage: u64,
    false_work_candidates: u64,
    no_delta_bytes: u64,
    lineage_delta_bytes: u64,
    random_delta_bytes: u64,
    resemblance_only_delta_bytes: u64,
    lineage_first_delta_bytes: u64,
}

struct DeltaContext<'a> {
    corpus_kind: CorpusKind,
    versions: &'a [Version],
    sketches: &'a [Option<MaterializedSketch>],
    inverted: &'a BTreeMap<[u8; 32], Vec<usize>>,
    sample_size: u16,
}

#[derive(Clone, Debug)]
enum DeltaOperation {
    Copy { offset: u64, length: u64 },
    Add(Vec<u8>),
}

pub fn measure(corpus: &Corpus) -> Result<Vec<SketchEvidenceResult>> {
    let mut versions = Vec::new();
    corpus.visit_inputs(|bytes| {
        versions.push(Version::build(bytes)?);
        Ok(())
    })?;
    if versions.len() < 2 {
        bail!("bottom-k evidence requires at least two versions");
    }

    let mut results = Vec::new();
    for width in SCORE_WIDTHS {
        for sample_size in SAMPLE_SIZES {
            results.push(measure_configuration(
                corpus.name(),
                corpus.kind(),
                &versions,
                *width,
                *sample_size,
            )?);
        }
    }
    Ok(results)
}

fn measure_configuration(
    corpus: &str,
    corpus_kind: CorpusKind,
    versions: &[Version],
    width: SketchScoreWidth,
    sample_size: u16,
) -> Result<SketchEvidenceResult> {
    let sample = SketchSampleSize::new(sample_size)
        .ok_or_else(|| anyhow::anyhow!("sample size must be non-zero"))?;
    let descriptor = BottomKSketchDescriptor::new(width, sample);
    let mut build = build_sketches(versions, descriptor)?;
    let deltas = measure_deltas(
        corpus_kind,
        versions,
        &build.sketches,
        sample_size,
        &mut build.output_hasher,
    )?;

    let corpus_logical_bytes = versions.iter().try_fold(0_u64, |total, version| {
        checked_add(total, version.logical_bytes, "source logical bytes")
    })?;
    let source_logical_bytes = versions
        .iter()
        .filter(|version| version.chunks.len() > 1)
        .try_fold(0_u64, |total, version| {
            checked_add(total, version.logical_bytes, "multi-chunk source bytes")
        })?;
    let build_throughput = timing(build.scanned_bytes, build.elapsed, build.elapsed)?;
    let pass_score_state_upper_bound_bytes = u64::from(sample_size)
        .checked_mul(32)
        .ok_or_else(|| anyhow::anyhow!("score-state byte bound overflow"))?;
    Ok(SketchEvidenceResult {
        corpus: corpus.to_owned(),
        corpus_kind,
        score_width_bits: width.bits(),
        sample_size,
        files: u64::try_from(versions.len())?,
        multi_chunk_targets: deltas.targets,
        corpus_logical_bytes,
        source_logical_bytes,
        source_retained_bytes_scanned: build.scanned_bytes,
        sketch_retained_bytes: build.retained_bytes,
        pass_score_state_upper_bound_bytes,
        build_elapsed_nanoseconds: build.elapsed.as_nanos(),
        build_throughput,
        output_identity_hash: hex::encode(build.output_hasher.finalize().as_bytes()),
        candidate_attempts: deltas.candidate_attempts,
        useful_candidates_over_raw: deltas.useful_candidates_over_raw,
        residual_improvements_over_lineage: (corpus_kind == CorpusKind::VersionChain)
            .then_some(deltas.residual_improvements_over_lineage),
        false_work_candidates: deltas.false_work_candidates,
        no_delta_bytes: deltas.no_delta_bytes,
        lineage_delta_bytes: (corpus_kind == CorpusKind::VersionChain)
            .then_some(deltas.lineage_delta_bytes),
        random_delta_bytes: deltas.random_delta_bytes,
        resemblance_only_delta_bytes: deltas.resemblance_only_delta_bytes,
        lineage_first_delta_bytes: (corpus_kind == CorpusKind::VersionChain)
            .then_some(deltas.lineage_first_delta_bytes),
    })
}

fn build_sketches(
    versions: &[Version],
    descriptor: BottomKSketchDescriptor,
) -> Result<SketchBuildTotals> {
    let mut totals = SketchBuildTotals {
        sketches: Vec::with_capacity(versions.len()),
        scanned_bytes: 0,
        retained_bytes: 0,
        elapsed: Duration::ZERO,
        output_hasher: blake3::Hasher::new_derive_key("astrid bottom-k evidence output list v1"),
    };
    for version in versions {
        if version.chunks.len() < 2 {
            totals.sketches.push(None);
            continue;
        }
        let sketch = version.sketch(descriptor)?;
        totals.scanned_bytes = checked_add(
            totals.scanned_bytes,
            sketch.scanned_bytes,
            "sketch scanned bytes",
        )?;
        totals.retained_bytes = checked_add(
            totals.retained_bytes,
            sketch.retained_bytes,
            "sketch retained bytes",
        )?;
        totals.elapsed = totals
            .elapsed
            .checked_add(sketch.elapsed)
            .ok_or_else(|| anyhow::anyhow!("sketch duration overflow"))?;
        totals.output_hasher.update(sketch.output.as_bytes());
        totals.sketches.push(Some(sketch));
    }
    Ok(totals)
}

fn measure_deltas(
    corpus_kind: CorpusKind,
    versions: &[Version],
    sketches: &[Option<MaterializedSketch>],
    sample_size: u16,
    output_hasher: &mut blake3::Hasher,
) -> Result<DeltaTotals> {
    let mut totals = DeltaTotals::default();
    let inverted = inverted_score_index(sketches);
    let context = DeltaContext {
        corpus_kind,
        versions,
        sketches,
        inverted: &inverted,
        sample_size,
    };
    let mut seen_targets = BTreeSet::new();
    for (target_index, target) in versions.iter().enumerate() {
        if target.chunks.len() < 2
            || !seen_targets.insert(target.file)
            || (corpus_kind == CorpusKind::VersionChain && target_index == 0)
        {
            continue;
        }
        context.measure_target(target_index, &mut totals, output_hasher)?;
    }
    Ok(totals)
}

impl DeltaContext<'_> {
    fn measure_target(
        &self,
        target_index: usize,
        totals: &mut DeltaTotals,
        output_hasher: &mut blake3::Hasher,
    ) -> Result<()> {
        let target = &self.versions[target_index];
        totals.targets = checked_add(totals.targets, 1, "multi-chunk targets")?;
        totals.no_delta_bytes = checked_add(
            totals.no_delta_bytes,
            target.logical_bytes,
            "raw target bytes",
        )?;

        let lineage = (self.corpus_kind == CorpusKind::VersionChain)
            .then(|| {
                target_index
                    .checked_sub(1)
                    .ok_or_else(|| anyhow::anyhow!("version chain has no predecessor"))
            })
            .transpose()?
            .map(|predecessor| delta_size(&self.versions[predecessor], target))
            .transpose()?
            .map(|bytes| bytes.min(target.logical_bytes));
        if let Some(lineage) = lineage {
            totals.lineage_delta_bytes =
                checked_add(totals.lineage_delta_bytes, lineage, "lineage delta bytes")?;
        }

        let random_index = deterministic_random_candidate(
            target.file,
            self.corpus_kind,
            self.versions,
            target_index,
        );
        let random = random_index
            .map(|index| delta_size(&self.versions[index], target))
            .transpose()?
            .unwrap_or(target.logical_bytes)
            .min(target.logical_bytes);
        totals.random_delta_bytes =
            checked_add(totals.random_delta_bytes, random, "random delta bytes")?;

        let candidate = best_resemblance_candidate(
            self.corpus_kind,
            self.sketches,
            self.versions,
            self.inverted,
            target_index,
            self.sample_size,
        );
        let encoded_resemblance = candidate
            .map(|index| delta_size(&self.versions[index], target))
            .transpose()?;
        let resemblance = encoded_resemblance
            .unwrap_or(target.logical_bytes)
            .min(target.logical_bytes);
        if candidate.is_some() {
            totals.candidate_attempts =
                checked_add(totals.candidate_attempts, 1, "candidate attempts")?;
        }
        totals.resemblance_only_delta_bytes = checked_add(
            totals.resemblance_only_delta_bytes,
            resemblance,
            "resemblance delta bytes",
        )?;
        if encoded_resemblance.is_some_and(|encoded| encoded >= target.logical_bytes) {
            totals.false_work_candidates =
                checked_add(totals.false_work_candidates, 1, "false-work candidates")?;
        }
        if candidate.is_some() && resemblance < target.logical_bytes {
            totals.useful_candidates_over_raw = checked_add(
                totals.useful_candidates_over_raw,
                1,
                "useful candidates over raw",
            )?;
        }
        let selected = if lineage.is_some_and(|lineage| resemblance < lineage) {
            totals.residual_improvements_over_lineage = checked_add(
                totals.residual_improvements_over_lineage,
                1,
                "residual improvements",
            )?;
            resemblance
        } else {
            lineage.unwrap_or(resemblance)
        };
        if lineage.is_some() {
            totals.lineage_first_delta_bytes = checked_add(
                totals.lineage_first_delta_bytes,
                selected,
                "lineage-first delta bytes",
            )?;
        }
        output_hasher.update(target.file.as_bytes());
        output_hasher.update(
            &candidate
                .map(u64::try_from)
                .transpose()?
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        output_hasher.update(&selected.to_le_bytes());
        Ok(())
    }
}

impl Version {
    fn build(bytes: &[u8]) -> Result<Self> {
        let built = build_content(&Blake3ObjectIdentityV1, ChunkingProfile::ASTRID_V1, bytes)
            .context("build production content DAG for sketch evidence")?;
        Self::from_built(built)
    }

    fn from_built(built: BuiltContent) -> Result<Self> {
        let descriptor = built.descriptor();
        let records = built.into_records();
        let by_id = records
            .iter()
            .map(|(id, record)| (*id, record))
            .collect::<BTreeMap<_, _>>();
        let mut chunks = Vec::new();
        let mut offset = 0_u64;
        collect_chunks(descriptor.file(), &by_id, &mut offset, &mut chunks)?;
        if offset != descriptor.logical_bytes() {
            bail!("ordered chunk traversal did not reconstruct the declared file length");
        }
        Ok(Self {
            file: descriptor.file(),
            logical_bytes: descriptor.logical_bytes(),
            records,
            chunks,
        })
    }

    fn sketch(&self, descriptor: BottomKSketchDescriptor) -> Result<MaterializedSketch> {
        let scanned_bytes = self.records.iter().try_fold(0_u64, |total, (_, record)| {
            checked_add(total, record.retained_bytes()?, "sketch scan bytes")
        })?;
        let descriptor_record = descriptor.record()?;
        let started = Instant::now();
        let outputs = build_bottom_k_sketch(
            &Blake3ObjectIdentityV1,
            descriptor,
            unlimited_context(),
            self.file,
            &self.records,
        )?;
        let elapsed = started.elapsed();
        let output = outputs
            .as_slice()
            .first()
            .filter(|_| outputs.len() == 1)
            .ok_or_else(|| anyhow::anyhow!("bottom-k pass emitted an unexpected output count"))?
            .record();
        let verified = verify_bottom_k_sketch(
            &Blake3ObjectIdentityV1,
            &descriptor_record,
            output,
            self.file,
            &self.records,
        )?;
        Ok(MaterializedSketch {
            scores: verified.scores().to_vec(),
            output: Blake3ObjectIdentityV1.identify(output),
            retained_bytes: output.retained_bytes()?,
            scanned_bytes,
            elapsed,
        })
    }

    fn record(&self, id: ObjectId) -> Result<&ObjectRecord> {
        self.records
            .binary_search_by_key(&id, |(object, _)| *object)
            .ok()
            .and_then(|index| self.records.get(index))
            .map(|(_, record)| record)
            .ok_or_else(|| anyhow::anyhow!("content DAG misses ordered chunk {id:?}"))
    }

    fn materialize(&self) -> Result<Vec<u8>> {
        let capacity = usize::try_from(self.logical_bytes)?;
        let mut bytes = Vec::with_capacity(capacity);
        for chunk in &self.chunks {
            bytes.extend_from_slice(self.record(chunk.id)?.canonical_bytes());
        }
        if bytes.len() != capacity {
            bail!("materialized file length differs from its descriptor");
        }
        Ok(bytes)
    }
}

fn collect_chunks(
    id: ObjectId,
    records: &BTreeMap<ObjectId, &ObjectRecord>,
    offset: &mut u64,
    chunks: &mut Vec<Chunk>,
) -> Result<()> {
    let record = records
        .get(&id)
        .copied()
        .ok_or_else(|| anyhow::anyhow!("content DAG misses {id:?}"))?;
    match record.kind() {
        ObjectKind::Chunk => {
            let length = u64::try_from(record.canonical_bytes().len())?;
            chunks.push(Chunk {
                id,
                offset: *offset,
                length,
            });
            *offset = checked_add(*offset, length, "chunk offset")?;
        },
        ObjectKind::File | ObjectKind::ChunkTree => {
            for child in record.owning_references() {
                collect_chunks(child, records, offset, chunks)?;
            }
        },
        kind => bail!("unexpected {kind:?} in a canonical File owning closure"),
    }
    Ok(())
}

fn best_resemblance_candidate(
    corpus_kind: CorpusKind,
    sketches: &[Option<MaterializedSketch>],
    versions: &[Version],
    inverted: &BTreeMap<[u8; 32], Vec<usize>>,
    target: usize,
    sample_size: u16,
) -> Option<usize> {
    let mut best: Option<(usize, u64, u64)> = None;
    let target_sketch = sketches.get(target)?.as_ref()?;
    let candidates = target_sketch
        .scores
        .iter()
        .filter_map(|score| inverted.get(score))
        .flatten()
        .copied()
        .filter(|candidate| candidate_allowed(corpus_kind, versions, target, *candidate))
        .collect::<BTreeSet<_>>();
    for candidate in candidates {
        let (shared, sampled) = union_sample_resemblance(
            &sketches[candidate].as_ref()?.scores,
            &target_sketch.scores,
            usize::from(sample_size),
        );
        if shared == 0 || sampled == 0 {
            continue;
        }
        match best {
            None => best = Some((candidate, shared, sampled)),
            Some((best_index, best_shared, best_sampled)) => {
                let ratio = shared.saturating_mul(best_sampled);
                let best_ratio = best_shared.saturating_mul(sampled);
                let ordering = ratio
                    .cmp(&best_ratio)
                    .then_with(|| versions[best_index].file.cmp(&versions[candidate].file));
                if ordering == Ordering::Greater {
                    best = Some((candidate, shared, sampled));
                }
            },
        }
    }
    best.map(|(index, _, _)| index)
}

fn inverted_score_index(sketches: &[Option<MaterializedSketch>]) -> BTreeMap<[u8; 32], Vec<usize>> {
    let mut inverted = BTreeMap::<_, Vec<_>>::new();
    for (index, sketch) in sketches.iter().enumerate() {
        let Some(sketch) = sketch else {
            continue;
        };
        for score in &sketch.scores {
            inverted.entry(*score).or_default().push(index);
        }
    }
    inverted
}

fn candidate_allowed(
    corpus_kind: CorpusKind,
    versions: &[Version],
    target: usize,
    candidate: usize,
) -> bool {
    candidate != target
        && versions[candidate].file != versions[target].file
        && (corpus_kind != CorpusKind::VersionChain || candidate < target)
}

fn union_sample_resemblance(left: &[[u8; 32]], right: &[[u8; 32]], limit: usize) -> (u64, u64) {
    let mut left_index = 0;
    let mut right_index = 0;
    let mut shared = 0_u64;
    let mut sampled = 0_u64;
    while usize::try_from(sampled).is_ok_and(|count| count < limit)
        && (left_index < left.len() || right_index < right.len())
    {
        match (left.get(left_index), right.get(right_index)) {
            (Some(left_score), Some(right_score)) => match left_score.cmp(right_score) {
                Ordering::Less => left_index = left_index.saturating_add(1),
                Ordering::Greater => right_index = right_index.saturating_add(1),
                Ordering::Equal => {
                    shared = shared.saturating_add(1);
                    left_index = left_index.saturating_add(1);
                    right_index = right_index.saturating_add(1);
                },
            },
            (Some(_), None) => left_index = left_index.saturating_add(1),
            (None, Some(_)) => right_index = right_index.saturating_add(1),
            (None, None) => break,
        }
        sampled = sampled.saturating_add(1);
    }
    (shared, sampled)
}

fn delta_size(base: &Version, target: &Version) -> Result<u64> {
    let mut by_id = BTreeMap::new();
    for chunk in &base.chunks {
        by_id.entry(chunk.id).or_insert(*chunk);
    }
    let mut operations = Vec::new();
    for target_chunk in &target.chunks {
        if let Some(base_chunk) = by_id.get(&target_chunk.id) {
            if base.record(base_chunk.id)?.canonical_bytes()
                != target.record(target_chunk.id)?.canonical_bytes()
            {
                bail!("equal chunk identities named different bytes in delta evidence");
            }
            push_copy(&mut operations, base_chunk.offset, base_chunk.length)?;
        } else {
            push_add(
                &mut operations,
                target.record(target_chunk.id)?.canonical_bytes(),
            )?;
        }
    }
    let encoded = encode_delta(base.file, target.file, target.logical_bytes, &operations)?;
    let reconstructed = apply_delta(&base.materialize()?, &encoded)?;
    if reconstructed != target.materialize()? {
        bail!("encoded evidence delta did not reconstruct its target");
    }
    Ok(u64::try_from(encoded.len())?)
}

fn push_copy(operations: &mut Vec<DeltaOperation>, offset: u64, length: u64) -> Result<()> {
    if let Some(DeltaOperation::Copy {
        offset: previous_offset,
        length: previous_length,
    }) = operations.last_mut()
        && previous_offset.checked_add(*previous_length) == Some(offset)
    {
        *previous_length = checked_add(*previous_length, length, "copy extent length")?;
        return Ok(());
    }
    operations.push(DeltaOperation::Copy { offset, length });
    Ok(())
}

fn push_add(operations: &mut Vec<DeltaOperation>, bytes: &[u8]) -> Result<()> {
    if let Some(DeltaOperation::Add(previous)) = operations.last_mut() {
        previous
            .try_reserve(bytes.len())
            .context("reserve delta literal bytes")?;
        previous.extend_from_slice(bytes);
    } else {
        operations.push(DeltaOperation::Add(bytes.to_vec()));
    }
    Ok(())
}

fn encode_delta(
    base: ObjectId,
    target: ObjectId,
    logical_bytes: u64,
    operations: &[DeltaOperation],
) -> Result<Vec<u8>> {
    let mut encoded = Vec::new();
    encoded.extend_from_slice(DELTA_MAGIC);
    encoded.extend_from_slice(base.as_bytes());
    encoded.extend_from_slice(target.as_bytes());
    encoded.extend_from_slice(&logical_bytes.to_le_bytes());
    encoded.extend_from_slice(&u64::try_from(operations.len())?.to_le_bytes());
    for operation in operations {
        match operation {
            DeltaOperation::Copy { offset, length } => {
                encoded.push(0);
                encoded.extend_from_slice(&offset.to_le_bytes());
                encoded.extend_from_slice(&length.to_le_bytes());
            },
            DeltaOperation::Add(bytes) => {
                encoded.push(1);
                encoded.extend_from_slice(&u64::try_from(bytes.len())?.to_le_bytes());
                encoded.extend_from_slice(bytes);
            },
        }
    }
    Ok(encoded)
}

fn apply_delta(base: &[u8], encoded: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = DeltaCursor::new(encoded);
    cursor.expect(DELTA_MAGIC)?;
    cursor.skip(32)?;
    cursor.skip(32)?;
    let logical_bytes = cursor.u64()?;
    let operation_count = cursor.u64()?;
    let mut output = Vec::with_capacity(usize::try_from(logical_bytes)?);
    for _ in 0..operation_count {
        match cursor.byte()? {
            0 => {
                let offset = usize::try_from(cursor.u64()?)?;
                let length = usize::try_from(cursor.u64()?)?;
                let end = offset
                    .checked_add(length)
                    .ok_or_else(|| anyhow::anyhow!("delta copy range overflow"))?;
                output.extend_from_slice(
                    base.get(offset..end)
                        .ok_or_else(|| anyhow::anyhow!("delta copy is outside its base"))?,
                );
            },
            1 => {
                let length = usize::try_from(cursor.u64()?)?;
                output.extend_from_slice(cursor.take(length)?);
            },
            _ => bail!("unknown delta operation"),
        }
    }
    cursor.done()?;
    if output.len() != usize::try_from(logical_bytes)? {
        bail!("delta output length differs from its header");
    }
    Ok(output)
}

struct DeltaCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> DeltaCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            bail!("delta magic mismatch")
        }
    }

    fn skip(&mut self, length: usize) -> Result<()> {
        self.take(length).map(|_| ())
    }

    fn byte(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or_else(|| anyhow::anyhow!("truncated delta byte"))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("truncated delta integer"))?,
        ))
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| anyhow::anyhow!("delta cursor overflow"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| anyhow::anyhow!("truncated delta"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn done(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            bail!("delta has trailing bytes")
        }
    }
}

fn unlimited_context() -> RefineryBatchContext {
    RefineryBatchContext::new(
        RefinerySnapshotId::new(ObjectId::new([0; 32])),
        PlacementEpoch::new(1),
        RefineryResourceBudget::new(u64::MAX, u128::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX),
        None,
    )
}

fn deterministic_random_candidate(
    target: ObjectId,
    corpus_kind: CorpusKind,
    versions: &[Version],
    target_index: usize,
) -> Option<usize> {
    let digest = blake3::hash(target.as_bytes());
    let mut lane = [0_u8; 8];
    lane.copy_from_slice(&digest.as_bytes()[..8]);
    let count = u64::try_from(versions.len()).ok()?;
    let start = usize::try_from(u64::from_le_bytes(lane).checked_rem(count)?).ok()?;
    (0..versions.len())
        .filter_map(|offset| start.wrapping_add(offset).checked_rem(versions.len()))
        .find(|candidate| candidate_allowed(corpus_kind, versions, target_index, *candidate))
}

fn checked_add(left: u64, right: u64, label: &str) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| anyhow::anyhow!("{label} overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn union_sample_estimates_identical_disjoint_and_partial_sets() {
        let score = |value| {
            let mut score = [0_u8; 32];
            score[0] = value;
            score
        };
        assert_eq!(
            union_sample_resemblance(&[score(1), score(3)], &[score(1), score(3)], 2),
            (2, 2)
        );
        assert_eq!(
            union_sample_resemblance(&[score(1), score(3)], &[score(2), score(4)], 4),
            (0, 4)
        );
        assert_eq!(
            union_sample_resemblance(&[score(1), score(3)], &[score(1), score(4)], 3),
            (1, 3)
        );
    }

    #[test]
    fn absent_candidate_is_not_credited_as_a_lineage_improvement() {
        let versions = vec![
            Version::build(&vec![0x41; 600 * 1024]).unwrap(),
            Version::build(&vec![0x7e; 600 * 1024]).unwrap(),
        ];
        let result = measure_configuration(
            "unrelated-chain",
            CorpusKind::VersionChain,
            &versions,
            SketchScoreWidth::Bits128,
            16,
        )
        .unwrap();

        assert_eq!(result.multi_chunk_targets, 1);
        assert_eq!(result.candidate_attempts, 0);
        assert_eq!(result.useful_candidates_over_raw, 0);
        assert_eq!(result.residual_improvements_over_lineage, Some(0));
        assert_eq!(result.lineage_delta_bytes, Some(result.no_delta_bytes));
        assert_eq!(result.lineage_first_delta_bytes, result.lineage_delta_bytes);
    }

    #[test]
    fn directory_measurement_finds_a_cross_name_resemblance() {
        let base = vec![0x41; 600 * 1024];
        let mut related = base.clone();
        related[300 * 1024..316 * 1024].fill(0x42);
        let versions = vec![
            Version::build(&base).unwrap(),
            Version::build(&related).unwrap(),
            Version::build(&vec![0x7e; 600 * 1024]).unwrap(),
        ];
        let result = measure_configuration(
            "cross-name",
            CorpusKind::DirectorySnapshot,
            &versions,
            SketchScoreWidth::Bits128,
            16,
        )
        .unwrap();

        assert_eq!(result.multi_chunk_targets, 3);
        assert!(result.candidate_attempts >= 2);
        assert!(result.useful_candidates_over_raw >= 2);
        assert_eq!(result.lineage_delta_bytes, None);
        assert_eq!(result.lineage_first_delta_bytes, None);
    }

    #[test]
    fn chunk_copy_delta_round_trips_and_rejects_trailing_bytes() {
        let base = Version::build(&vec![0x41; 2 * 1024 * 1024]).unwrap();
        let mut target_bytes = vec![0x41; 2 * 1024 * 1024];
        target_bytes.splice(700_000..700_000, b"bounded edit".iter().copied());
        let target = Version::build(&target_bytes).unwrap();
        assert!(delta_size(&base, &target).unwrap() < target.logical_bytes);

        let mut encoded = encode_delta(
            ObjectId::new([1; 32]),
            ObjectId::new([2; 32]),
            3,
            &[DeltaOperation::Add(b"abc".to_vec())],
        )
        .unwrap();
        assert_eq!(apply_delta(&[], &encoded).unwrap(), b"abc");
        encoded.push(0);
        assert!(apply_delta(&[], &encoded).is_err());
    }
}
