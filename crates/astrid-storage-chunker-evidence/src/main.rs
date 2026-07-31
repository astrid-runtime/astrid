use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::Serialize;

mod algorithm;
mod corpus;
mod environment;
mod fixture;
mod metrics;
#[cfg(test)]
mod reference;
mod sketch;
mod source;
mod stability;
mod throughput;

use algorithm::candidates;
use corpus::{CandidateResult, Corpus};
use sketch::SketchEvidenceResult;
use source::{SourceRecord, UnavailableCandidate};
use stability::StabilityResult;
use throughput::ThroughputResult;

#[derive(Debug, Serialize)]
struct EvidenceReport {
    schema: &'static str,
    format_authority: &'static str,
    whole_file_policy: &'static str,
    corpus_privacy: &'static str,
    benchmark_environment: environment::BenchmarkEnvironment,
    object_cost_model: &'static str,
    sources: [SourceRecord; 3],
    unavailable_candidates: [UnavailableCandidate; 1],
    results: Vec<CandidateResult>,
    edit_stability: Vec<StabilityResult>,
    cpu_throughput: Vec<ThroughputResult>,
    bottom_k_sketches: Vec<SketchEvidenceResult>,
}

#[derive(Debug)]
struct Options {
    corpus_specs: Vec<(String, PathBuf)>,
    version_chain_specs: Vec<(String, PathBuf)>,
    git_history_specs: Vec<(String, PathBuf, PathBuf)>,
    include_synthetic: bool,
    sketch_only: bool,
    targets_kib: Vec<u32>,
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let options = parse_options()?;
    let corpora = load_corpora(&options)?;
    let mut results = Vec::new();
    let mut edit_stability = Vec::new();
    let mut cpu_throughput = Vec::new();
    if !options.sketch_only {
        for target_kib in options.targets_kib {
            for candidate in candidates(target_kib)? {
                for corpus in &corpora {
                    eprintln!("measuring {} on {}", candidate.name, corpus.name());
                    results.push(corpus.measure(candidate.clone())?);
                }
                eprintln!("measuring {} edit stability", candidate.name);
                edit_stability.push(stability::measure(&candidate)?);
                eprintln!("measuring {} CPU throughput", candidate.name);
                cpu_throughput.push(throughput::measure(&candidate)?);
            }
        }
    }
    let mut bottom_k_sketches = Vec::new();
    for corpus in &corpora {
        eprintln!("measuring bottom-k sketches on {}", corpus.name());
        bottom_k_sketches.extend(sketch::measure(corpus)?);
    }
    let report = EvidenceReport {
        schema: "astrid-storage-chunker-evidence/v1",
        format_authority: "third-party implementations are evidence oracles; a selected profile requires an independently specified Astrid implementation and golden cuts",
        whole_file_policy: "inputs no larger than the candidate maximum remain one whole object",
        corpus_privacy: "reports contain aggregate labels and metrics only; no input path or file name is serialized",
        benchmark_environment: environment::current(),
        object_cost_model: "unique chunk bytes + 162 bytes per unique chunk object + 40 bytes per physical reference record; compare directionally, not as an arena-format byte count",
        sources: source::source_records(),
        unavailable_candidates: source::unavailable_candidates(),
        results,
        edit_stability,
        cpu_throughput,
        bottom_k_sketches,
    };
    write_report(options.output.as_ref(), &report)
}

fn load_corpora(options: &Options) -> Result<Vec<Corpus>> {
    let mut corpora = Vec::new();
    if options.include_synthetic {
        corpora.push(Corpus::synthetic_adversarial());
        corpora.push(Corpus::synthetic_version_chain());
    }
    for (name, path) in &options.corpus_specs {
        corpora.push(Corpus::from_path(name.clone(), path)?);
    }
    for (name, path) in &options.version_chain_specs {
        corpora.push(Corpus::version_chain_from_path(name.clone(), path)?);
    }
    for (name, repository, relative_path) in &options.git_history_specs {
        corpora.push(Corpus::version_chain_from_git(
            name.clone(),
            repository,
            relative_path,
        )?);
    }
    if corpora.is_empty() {
        bail!("no corpus selected; omit --no-synthetic or pass a corpus or version-chain option");
    }
    ensure_unique_corpus_labels(&corpora)?;
    Ok(corpora)
}

fn ensure_unique_corpus_labels(corpora: &[Corpus]) -> Result<()> {
    let mut labels = HashSet::with_capacity(corpora.len());
    for corpus in corpora {
        if !labels.insert(corpus.name()) {
            bail!("duplicate corpus label {:?}", corpus.name());
        }
    }
    Ok(())
}

fn write_report(output: Option<&PathBuf>, report: &EvidenceReport) -> Result<()> {
    let mut encoded = serde_json::to_string(report)?;
    encoded.push('\n');
    if let Some(path) = output {
        fs::write(path, encoded)
            .with_context(|| format!("write evidence report {}", path.display()))?;
    } else {
        println!("{encoded}");
    }
    Ok(())
}

fn parse_options() -> Result<Options> {
    let mut corpus_specs = Vec::new();
    let mut version_chain_specs = Vec::new();
    let mut git_history_specs = Vec::new();
    let mut include_synthetic = true;
    let mut sketch_only = false;
    let mut targets_kib = Vec::new();
    let mut output = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--corpus" => corpus_specs.push(parse_path_specification("--corpus", args.next())?),
            "--version-chain" => {
                version_chain_specs.push(parse_path_specification("--version-chain", args.next())?);
            },
            "--git-history" => {
                git_history_specs.push(parse_git_specification(args.next())?);
            },
            "--no-synthetic" => include_synthetic = false,
            "--sketch-only" => sketch_only = true,
            "--target-kib" => {
                let target = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--target-kib requires an integer"))?
                    .parse::<u32>()
                    .context("parse --target-kib")?;
                targets_kib.push(target);
            },
            "--output" => {
                let path = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--output requires a path"))?;
                output = Some(PathBuf::from(path));
            },
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            },
            unknown => bail!("unknown argument {unknown:?}; use --help"),
        }
    }
    if targets_kib.is_empty() {
        targets_kib.push(64);
    }
    targets_kib.sort_unstable();
    targets_kib.dedup();
    Ok(Options {
        corpus_specs,
        version_chain_specs,
        git_history_specs,
        include_synthetic,
        sketch_only,
        targets_kib,
        output,
    })
}

fn parse_git_specification(specification: Option<String>) -> Result<(String, PathBuf, PathBuf)> {
    let (name, combined) = parse_path_specification("--git-history", specification)?;
    let combined = combined.to_string_lossy();
    let (repository, relative_path) = combined
        .split_once("::")
        .ok_or_else(|| anyhow::anyhow!("--git-history requires NAME=REPO::RELATIVE_PATH"))?;
    if repository.is_empty() || relative_path.is_empty() {
        bail!("--git-history requires non-empty NAME=REPO::RELATIVE_PATH");
    }
    Ok((
        name,
        PathBuf::from(repository),
        PathBuf::from(relative_path),
    ))
}

fn parse_path_specification(
    flag: &str,
    specification: Option<String>,
) -> Result<(String, PathBuf)> {
    let specification =
        specification.ok_or_else(|| anyhow::anyhow!("{flag} requires NAME=PATH"))?;
    let (name, path) = specification
        .split_once('=')
        .ok_or_else(|| anyhow::anyhow!("{flag} requires NAME=PATH"))?;
    if name.is_empty() || path.is_empty() {
        bail!("{flag} requires non-empty NAME=PATH");
    }
    Ok((name.to_owned(), PathBuf::from(path)))
}

fn print_help() {
    println!(
        "Usage: astrid-storage-chunker-evidence [OPTIONS]\n\
         \n\
         Options:\n\
         \x20 --corpus NAME=PATH       Add a directory snapshot; paths stay out of reports\n\
         \x20 --version-chain NAME=PATH\n\
         \x20                          Add lexically ordered version files\n\
         \x20 --git-history NAME=REPO::RELATIVE_PATH\n\
         \x20                          Add up to 32 real versions without temporary files\n\
         \x20 --no-synthetic           Exclude deterministic public fixtures\n\
         \x20 --sketch-only            Skip the CDC comparison and measure sketches only\n\
         \x20 --target-kib N           Compare profiles around N KiB (repeatable)\n\
         \x20 --output PATH            Write compact JSON to PATH instead of stdout\n\
         \x20 -h, --help               Print this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_corpus_labels_are_rejected() {
        let corpora = [
            Corpus::synthetic_adversarial(),
            Corpus::synthetic_adversarial(),
        ];
        assert!(ensure_unique_corpus_labels(&corpora).is_err());
    }
}
