use std::collections::{BTreeMap, BTreeSet};

use caseless::default_case_fold_str;
use unicode_normalization::UnicodeNormalization;

use super::{
    ContentName, ProjectedContentPath, ProjectedNameSegment, ProjectionCollisionGroup,
    ProjectionCollisionKind, ProjectionEscapeReason, ProjectionEscapedName, ProjectionNameError,
    ProjectionNameMapping, ProjectionNamePlan, ProjectionNamePolicy, ProjectionNameSyntax,
};

const MARKER: &str = "~astrid-";
const DIGEST_HEX_LENGTH: usize = 64;
const FILE_TAG: &str = "f";
const DIRECTORY_TAG: &str = "d";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum EntryRole {
    File,
    Directory,
}

impl EntryRole {
    const fn tag(self) -> &'static str {
        match self {
            Self::File => FILE_TAG,
            Self::Directory => DIRECTORY_TAG,
        }
    }
}

#[derive(Default)]
struct SourceNode {
    terminal: Option<ContentName>,
    children: BTreeMap<String, SourceNode>,
}

struct Candidate<'a> {
    source_segment: &'a str,
    role: EntryRole,
    node: &'a SourceNode,
    natural: String,
    escape: Option<ProjectionEscapeReason>,
    descendant_sources: Vec<ContentName>,
}

struct PlannedCandidate<'a> {
    candidate: Candidate<'a>,
    projected: String,
}

#[derive(Default)]
struct PlanState {
    mappings: BTreeMap<ContentName, ProjectedContentPath>,
    collisions: Vec<(ProjectionCollisionKind, Vec<ContentName>)>,
    escaped_segments: Vec<(ContentName, u32, ProjectionEscapeReason)>,
}

/// Plan deterministic projected names for one principal catalog.
///
/// Exact duplicate inputs are accepted once. The resulting mappings are
/// sorted by exact source name and are independent of input iteration order.
///
/// # Errors
///
/// Returns an error if the target segment ceiling cannot hold a safe suffix,
/// if a cryptographic suffix collision is observed between exact names, or if
/// the final paths are not unique under the selected comparison policy.
pub fn plan_projection_names(
    policy: ProjectionNamePolicy,
    names: &[ContentName],
) -> Result<ProjectionNamePlan, ProjectionNameError> {
    ensure_suffix_fits(policy)?;
    let mut root = SourceNode::default();
    for source in names {
        insert_source(&mut root, source);
    }

    let mut state = PlanState::default();
    plan_node(policy, &root, &[], &[], &mut state)?;

    let PlanState {
        mappings: planned_mappings,
        collisions,
        escaped_segments,
    } = state;
    let collisions = collisions
        .into_iter()
        .map(|(kind, sources)| {
            let projected = sources
                .iter()
                .map(|source| {
                    planned_mappings.get(source).cloned().ok_or_else(|| {
                        ProjectionNameError::MissingPlannedMapping {
                            source: source.clone(),
                        }
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ProjectionCollisionGroup::new(kind, sources, projected))
        })
        .collect::<Result<Vec<_>, ProjectionNameError>>()?;
    let escaped = escaped_segments
        .into_iter()
        .map(|(source, index, reason)| {
            let projected = planned_mappings.get(&source).cloned().ok_or_else(|| {
                ProjectionNameError::MissingPlannedMapping {
                    source: source.clone(),
                }
            })?;
            Ok(ProjectionEscapedName::new(source, index, reason, projected))
        })
        .collect::<Result<Vec<_>, ProjectionNameError>>()?;
    let mappings = planned_mappings
        .into_iter()
        .map(|(source, projected)| ProjectionNameMapping::new(source, projected))
        .collect::<Vec<_>>();
    verify_final_uniqueness(policy, &mappings)?;

    Ok(ProjectionNamePlan::new(
        policy, mappings, collisions, escaped,
    ))
}

fn insert_source(root: &mut SourceNode, source: &ContentName) {
    let mut node = root;
    for segment in source.as_str().split('/') {
        node = node.children.entry(segment.to_owned()).or_default();
    }
    node.terminal = Some(source.clone());
}

fn plan_node(
    policy: ProjectionNamePolicy,
    node: &SourceNode,
    source_prefix: &[String],
    projected_prefix: &[ProjectedNameSegment],
    state: &mut PlanState,
) -> Result<(), ProjectionNameError> {
    let candidates = candidates(node, policy);
    let collision_sets = collision_sets(policy, &candidates);
    let colliding = collision_sets
        .iter()
        .flat_map(|set| set.iter().copied())
        .collect::<BTreeSet<_>>();

    let mut planned = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.into_iter().enumerate() {
        let needs_suffix = candidate.escape.is_some() || colliding.contains(&index);
        let projected = if needs_suffix {
            escaped_segment(
                policy,
                candidate.source_segment,
                candidate.role,
                source_prefix,
            )
        } else {
            candidate.natural.clone()
        };
        planned.push(PlannedCandidate {
            candidate,
            projected,
        });
    }
    verify_sibling_uniqueness(policy, &planned)?;
    record_collisions(&collision_sets, &planned, &mut state.collisions);

    for planned_candidate in planned {
        let mut child_projected_prefix = projected_prefix.to_vec();
        child_projected_prefix.push(ProjectedNameSegment::new(
            planned_candidate.projected.clone(),
        ));
        match planned_candidate.candidate.role {
            EntryRole::File => {
                let Some(source) = planned_candidate.candidate.node.terminal.clone() else {
                    continue;
                };
                if let Some(reason) = planned_candidate.candidate.escape {
                    state.escaped_segments.push((
                        source.clone(),
                        segment_index(source_prefix, &source)?,
                        reason,
                    ));
                }
                state
                    .mappings
                    .insert(source, ProjectedContentPath::new(child_projected_prefix));
            },
            EntryRole::Directory => {
                let mut child_source_prefix = source_prefix.to_vec();
                child_source_prefix.push(planned_candidate.candidate.source_segment.to_owned());
                for source in &planned_candidate.candidate.descendant_sources {
                    if let Some(reason) = planned_candidate.candidate.escape {
                        state.escaped_segments.push((
                            source.clone(),
                            segment_index(source_prefix, source)?,
                            reason,
                        ));
                    }
                }
                plan_node(
                    policy,
                    planned_candidate.candidate.node,
                    &child_source_prefix,
                    &child_projected_prefix,
                    state,
                )?;
            },
        }
    }
    Ok(())
}

fn candidates(node: &SourceNode, policy: ProjectionNamePolicy) -> Vec<Candidate<'_>> {
    let mut result = Vec::new();
    for (segment, child) in &node.children {
        let (natural, escape) = natural_segment(policy, segment);
        if child.terminal.is_some() {
            result.push(Candidate {
                source_segment: segment,
                role: EntryRole::File,
                node: child,
                natural: natural.clone(),
                escape,
                descendant_sources: child.terminal.iter().cloned().collect(),
            });
        }
        if !child.children.is_empty() {
            result.push(Candidate {
                source_segment: segment,
                role: EntryRole::Directory,
                node: child,
                natural,
                escape,
                descendant_sources: collect_sources(child),
            });
        }
    }
    result
}

fn collect_sources(node: &SourceNode) -> Vec<ContentName> {
    let mut sources = Vec::new();
    if let Some(source) = &node.terminal {
        sources.push(source.clone());
    }
    for child in node.children.values() {
        sources.extend(collect_sources(child));
    }
    sources.sort();
    sources
}

fn collision_sets(policy: ProjectionNamePolicy, candidates: &[Candidate<'_>]) -> Vec<Vec<usize>> {
    let mut by_key = BTreeMap::<Vec<u8>, Vec<usize>>::new();
    for (index, candidate) in candidates.iter().enumerate() {
        by_key
            .entry(comparison_key(policy, &candidate.natural))
            .or_default()
            .push(index);
    }
    by_key
        .into_values()
        .filter(|indices| indices.len() > 1)
        .collect()
}

fn record_collisions(
    collision_sets: &[Vec<usize>],
    planned: &[PlannedCandidate<'_>],
    output: &mut Vec<(ProjectionCollisionKind, Vec<ContentName>)>,
) {
    for indices in collision_sets {
        let mut sources = indices
            .iter()
            .flat_map(|index| planned[*index].candidate.descendant_sources.clone())
            .collect::<Vec<_>>();
        sources.sort();
        sources.dedup();
        let kind = if indices
            .iter()
            .map(|index| planned[*index].candidate.role)
            .collect::<BTreeSet<_>>()
            .len()
            > 1
        {
            ProjectionCollisionKind::FileDirectoryConflict
        } else {
            ProjectionCollisionKind::EquivalentSegments
        };
        output.push((kind, sources));
    }
}

fn segment_index(
    source_prefix: &[String],
    source: &ContentName,
) -> Result<u32, ProjectionNameError> {
    u32::try_from(source_prefix.len()).map_err(|_| ProjectionNameError::TooManySegments {
        source: source.clone(),
    })
}

fn natural_segment(
    policy: ProjectionNamePolicy,
    segment: &str,
) -> (String, Option<ProjectionEscapeReason>) {
    let reason = escape_reason(policy, segment);
    (segment.to_owned(), reason)
}

fn escape_reason(policy: ProjectionNamePolicy, segment: &str) -> Option<ProjectionEscapeReason> {
    if segment.is_empty() || segment == "." || segment == ".." {
        return Some(ProjectionEscapeReason::StructuralSegment);
    }
    if comparison_key(policy, segment)
        .windows(MARKER.len())
        .any(|window| window == MARKER.as_bytes())
    {
        return Some(ProjectionEscapeReason::ReservedProjectionMarker);
    }
    if segment_units(policy, segment) > usize::from(policy.max_segment_units().get()) {
        return Some(ProjectionEscapeReason::SegmentTooLong);
    }
    match policy.syntax() {
        ProjectionNameSyntax::PosixUtf8V1 => None,
        ProjectionNameSyntax::WindowsUtf16V1 => {
            if segment.chars().any(is_invalid_windows_character) {
                return Some(ProjectionEscapeReason::InvalidTargetCharacter);
            }
            if segment.ends_with(' ') || segment.ends_with('.') {
                return Some(ProjectionEscapeReason::SignificantTrailingCharacter);
            }
            is_windows_reserved(segment).then_some(ProjectionEscapeReason::ReservedTargetName)
        },
    }
}

fn is_invalid_windows_character(character: char) -> bool {
    character <= '\u{1f}' || matches!(character, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*')
}

fn is_windows_reserved(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    let folded = default_case_fold_str(stem);
    matches!(
        folded.as_str(),
        "con" | "prn" | "aux" | "nul" | "conin$" | "conout$"
    ) || reserved_numbered_name(&folded, "com")
        || reserved_numbered_name(&folded, "lpt")
}

fn reserved_numbered_name(value: &str, prefix: &str) -> bool {
    let Some(number) = value.strip_prefix(prefix) else {
        return false;
    };
    matches!(
        number,
        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
    )
}

fn escaped_segment(
    policy: ProjectionNamePolicy,
    source_segment: &str,
    role: EntryRole,
    source_prefix: &[String],
) -> String {
    let suffix = suffix(source_segment, role, source_prefix);
    let reserved_units = segment_units(policy, &suffix);
    let available = usize::from(policy.max_segment_units().get()).saturating_sub(reserved_units);
    let readable = sanitize_readable(policy, source_segment);
    let prefix = truncate_to_units(policy, &readable, available);
    format!("{prefix}{suffix}")
}

fn suffix(source_segment: &str, role: EntryRole, source_prefix: &[String]) -> String {
    let mut hasher = blake3::Hasher::new_derive_key("astrid projection name suffix v1");
    hasher.update(&(source_prefix.len() as u128).to_le_bytes());
    for prefix in source_prefix {
        hash_bytes(&mut hasher, prefix.as_bytes());
    }
    hasher.update(&[match role {
        EntryRole::File => 0,
        EntryRole::Directory => 1,
    }]);
    hash_bytes(&mut hasher, source_segment.as_bytes());
    let digest = hasher.finalize();
    format!("{MARKER}{}-{}", role.tag(), hex::encode(digest.as_bytes()))
}

fn hash_bytes(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u128).to_le_bytes());
    hasher.update(bytes);
}

fn sanitize_readable(policy: ProjectionNamePolicy, segment: &str) -> String {
    let mut output = String::new();
    for character in segment.chars() {
        let allowed = match policy.syntax() {
            ProjectionNameSyntax::PosixUtf8V1 => character != '/',
            ProjectionNameSyntax::WindowsUtf16V1 => {
                character != '/' && !is_invalid_windows_character(character)
            },
        };
        output.push(if allowed { character } else { '_' });
    }
    while output.ends_with(' ') || output.ends_with('.') {
        output.pop();
    }
    if output.is_empty() || output == "." || output == ".." {
        output.push('_');
    }
    output
}

fn truncate_to_units(policy: ProjectionNamePolicy, value: &str, max_units: usize) -> String {
    let mut output = String::new();
    let mut used = 0_usize;
    for character in value.chars() {
        let units = match policy.syntax() {
            ProjectionNameSyntax::PosixUtf8V1 => character.len_utf8(),
            ProjectionNameSyntax::WindowsUtf16V1 => character.len_utf16(),
        };
        if used.saturating_add(units) > max_units {
            break;
        }
        output.push(character);
        used = used.saturating_add(units);
    }
    output
}

fn ensure_suffix_fits(policy: ProjectionNamePolicy) -> Result<(), ProjectionNameError> {
    let suffix = format!("{MARKER}{FILE_TAG}-{}", "0".repeat(DIGEST_HEX_LENGTH));
    let minimum = segment_units(policy, &suffix);
    if minimum <= usize::from(policy.max_segment_units().get()) {
        return Ok(());
    }
    Err(ProjectionNameError::SegmentLimitTooSmall {
        configured: policy.max_segment_units(),
        minimum: u16::try_from(minimum).unwrap_or(u16::MAX),
    })
}

fn verify_sibling_uniqueness(
    policy: ProjectionNamePolicy,
    planned: &[PlannedCandidate<'_>],
) -> Result<(), ProjectionNameError> {
    let mut seen = BTreeMap::<Vec<u8>, &PlannedCandidate<'_>>::new();
    for candidate in planned {
        let key = comparison_key(policy, &candidate.projected);
        if let Some(previous) = seen.insert(key, candidate) {
            let Some(first) = previous.candidate.descendant_sources.first().cloned() else {
                continue;
            };
            let Some(second) = candidate.candidate.descendant_sources.first().cloned() else {
                continue;
            };
            return Err(ProjectionNameError::DigestCollision { first, second });
        }
    }
    Ok(())
}

fn verify_final_uniqueness(
    policy: ProjectionNamePolicy,
    mappings: &[ProjectionNameMapping],
) -> Result<(), ProjectionNameError> {
    let mut seen = BTreeMap::<Vec<Vec<u8>>, &ContentName>::new();
    for mapping in mappings {
        let key = mapping
            .projected()
            .segments()
            .iter()
            .map(|segment| comparison_key(policy, segment.as_str()))
            .collect::<Vec<_>>();
        if let Some(previous) = seen.insert(key, mapping.source()) {
            return Err(ProjectionNameError::OutputCollision {
                first: previous.clone(),
                second: mapping.source().clone(),
            });
        }
    }
    Ok(())
}

fn comparison_key(policy: ProjectionNamePolicy, value: &str) -> Vec<u8> {
    match policy.comparison() {
        super::ProjectionNameComparison::ByteExactV1 => value.as_bytes().to_vec(),
        super::ProjectionNameComparison::UnicodeCanonicalV1 => {
            value.nfd().collect::<String>().into_bytes()
        },
        super::ProjectionNameComparison::UnicodeCaselessV1 => {
            default_case_fold_str(value).into_bytes()
        },
        super::ProjectionNameComparison::UnicodeCanonicalCaselessV1 => {
            default_case_fold_str(&value.nfd().collect::<String>())
                .nfd()
                .collect::<String>()
                .into_bytes()
        },
    }
}

fn segment_units(policy: ProjectionNamePolicy, value: &str) -> usize {
    match policy.syntax() {
        ProjectionNameSyntax::PosixUtf8V1 => value.len(),
        ProjectionNameSyntax::WindowsUtf16V1 => value.encode_utf16().count(),
    }
}
