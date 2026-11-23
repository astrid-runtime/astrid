#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="${1:-$repo_root/.github/workflows/ci.yml}"

ruby - "$workflow" <<'RB'
require "yaml"
require "shellwords"

workflow_path = ARGV.fetch(0)

def fail(message)
  warn "CI workflow contract: #{message}"
  exit 1
end

begin
  workflow = YAML.safe_load(File.read(workflow_path), aliases: false)
rescue StandardError => error
  fail("workflow is not valid YAML: #{error.message}")
end
fail("workflow root must be a mapping") unless workflow.is_a?(Hash)

audit_steps = workflow.fetch("jobs").fetch("audit").fetch("steps")
unless audit_steps.any? { |step| step["run"] == "cargo audit --file Cargo.lock" }
  fail("security audit must inspect Cargo.lock directly")
end
if audit_steps.any? { |step| step.fetch("uses", "").start_with?("rustsec/audit-check@") }
  fail("security audit must not depend on check-publication permissions")
end

concurrency = workflow.fetch("concurrency") do
  fail("missing top-level concurrency block")
end
fail("concurrency must be a mapping") unless concurrency.is_a?(Hash)

expected_group = "${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.run_attempt == '1' && format('pr-{0}', github.event.pull_request.number) || format('run-{0}-attempt-{1}', github.run_id, github.run_attempt) }}"
expected_cancel = "${{ github.event_name == 'pull_request' && github.run_attempt == '1' }}"

unless concurrency["group"] == expected_group
  fail("group must isolate first-attempt PRs by workflow and number, with run-id/attempt fallback")
end
unless concurrency["cancel-in-progress"] == expected_cancel
  fail("cancel-in-progress must be enabled only for first-attempt pull_request events")
end

# Keep this contract wired to filtered pushes and unconditional PRs. Parse so
# comments or similarly named text cannot make an absent path entry pass.
triggers = workflow["on"] || workflow[true]
fail("missing workflow trigger map") unless triggers.is_a?(Hash)
%w[push].each do |event_name|
  event = triggers.fetch(event_name) { fail("missing #{event_name} trigger") }
  paths = event.fetch("paths") { fail("missing #{event_name}.paths filter") }
  unless paths.is_a?(Array) && paths.count("scripts/test_ci_workflow_contract.sh") == 1
    fail("contract test must appear exactly once in #{event_name}.paths")
  end
end

# Required checks cannot depend on the base branch or changed file paths.
# A YAML null pull_request value is the intended unconditional event.
fail("missing pull_request trigger") unless triggers.key?("pull_request")
fail("pull_request must be unconditional") unless triggers["pull_request"].nil?
pr_checks_path = File.join(File.dirname(workflow_path), "pr-checks.yml")
pr_checks = YAML.safe_load(File.read(pr_checks_path), aliases: false)
pr_events = (pr_checks["on"] || pr_checks[true]).fetch("pull_request")
fail("PR Checks must allow stacked bases") if pr_events.key?("branches") || pr_events.key?("branches-ignore")

%w[ci.yml release.yml].each do |name|
  text = File.read(File.join(File.dirname(workflow_path), name))
  fail("#{name} must use shared GNU package setup") unless text.include?('bash scripts/ci/install_gnu_build_packages.sh "${packages[@]}"')
end

# The selected checkout can differ from github.sha on prepare-only dispatches.
# Native builds inherit the selected source; Docker builds must forward it.
release = YAML.safe_load(File.read(File.join(File.dirname(workflow_path), "release.yml")), aliases: false)
build = release.fetch("jobs").fetch("build")
def release_provenance?(build)
  source = "${{ needs.classify.outputs.source-commit }}"
  return false unless build.fetch("env", {})["ASTRID_GIT_COMMIT"] == source
  checkout = build.fetch("steps").find { |step| step.fetch("uses", "").start_with?("actions/checkout@") }
  return false unless checkout && checkout.fetch("with", {})["ref"] == source
  containers = build.fetch("steps").select { |step| step.fetch("run", "").include?("cargo build") && step.fetch("run", "").include?("docker run") }
  return false unless containers.length == 2
  containers.all? { |step| Shellwords.split(step.fetch("run")).each_cons(2).include?(["--env", "ASTRID_GIT_COMMIT"]) }
end
fail("Release builds must embed the selected checkout commit on native, GNU and MUSL targets") unless release_provenance?(build)

wrong_source = Marshal.load(Marshal.dump(build))
wrong_source.fetch("env")["ASTRID_GIT_COMMIT"] = "${{ github.sha }}"
fail("event SHA must not satisfy selected-source provenance") if release_provenance?(wrong_source)
build.fetch("steps").each_with_index do |step, index|
  next unless step.fetch("run", "").include?("docker run") && step.fetch("run", "").include?("cargo build")
  missing_forward = Marshal.load(Marshal.dump(build))
  missing_forward.fetch("steps")[index]["run"] = step.fetch("run").gsub("--env ASTRID_GIT_COMMIT", "")
  fail("every Linux container must receive source provenance") if release_provenance?(missing_forward)
end

def group(workflow_name, event_name, pr_number, run_id, run_attempt)
  if event_name == "pull_request" && run_attempt == "1"
    "#{workflow_name}-pr-#{pr_number}"
  else
    "#{workflow_name}-run-#{run_id}-attempt-#{run_attempt}"
  end
end

def cancel(event_name, run_attempt)
  event_name == "pull_request" && run_attempt == "1"
end

# Successive first-attempt pull_request events for one PR cancel the older run;
# a different PR remains independent.
first_pr_old = group("CI", "pull_request", 1837, "101", "1")
first_pr_new = group("CI", "pull_request", 1837, "102", "1")
fail("successive commits for one pull request must share a group") unless first_pr_old == first_pr_new
fail("first-attempt pull requests must enable cancellation") unless cancel("pull_request", "1")
fail("different pull requests must not share a group") if first_pr_new == group("CI", "pull_request", 1838, "103", "1")

# A manual rerun keeps the original run_id but increments run_attempt. It must
# not join the PR group, cancel, or evict the latest first-attempt PR run.
stale_rerun = group("CI", "pull_request", 1837, "101", "2")
fail("stale pull-request reruns must use a unique group") if stale_rerun == first_pr_new
fail("stale pull-request reruns must not enable cancellation") if cancel("pull_request", "2")
fail("stale pull-request reruns must not share a group with a newer PR push") if stale_rerun == group("CI", "pull_request", 1837, "104", "1")

# Non-PR runs receive unique run/attempt groups and never cancel, including
# main pushes, tag pushes, and workflow_dispatch runs.
[["push", "201", "1"], ["push", "202", "1"], ["push", "203", "2"], ["workflow_dispatch", "204", "1"], ["workflow_dispatch", "205", "1"], ["tag", "206", "1"], ["tag", "207", "1"]].each do |event_name, run_id, run_attempt|
  fail("#{event_name} runs must not enable cancellation") if cancel(event_name, run_attempt)
end
fail("successive main pushes must use independent groups") if group("CI", "push", nil, "201", "1") == group("CI", "push", nil, "202", "1")
fail("successive tag pushes must use independent groups") if group("CI", "tag", nil, "206", "1") == group("CI", "tag", nil, "207", "1")
fail("successive manual runs must use independent groups") if group("CI", "workflow_dispatch", nil, "204", "1") == group("CI", "workflow_dispatch", nil, "205", "1")

# A commented expected expression is not parsed as a key/value and must not
# satisfy this contract shape.
comment_spoof = <<~YAML
  concurrency:
    # group: #{expected_group}
    # cancel-in-progress: #{expected_cancel}
    group: wrong
    cancel-in-progress: false
YAML
spoofed = YAML.safe_load(comment_spoof, aliases: false)
spoofed_concurrency = spoofed.fetch("concurrency")
if spoofed_concurrency["group"] == expected_group || spoofed_concurrency["cancel-in-progress"] == expected_cancel
  fail("commented expressions must not satisfy the parsed concurrency contract")
end


# Release must gate signed multi-target builds on runtime-recovery qualification.
runtime = release.fetch("jobs").fetch("runtime-recovery") do
  fail("release.yml must define jobs.runtime-recovery")
end
unless runtime.is_a?(Hash) && runtime["uses"] == "./.github/workflows/runtime-recovery.yml"
  fail("runtime-recovery must call ./.github/workflows/runtime-recovery.yml")
end
unless runtime.dig("with", "source-commit") == "${{ needs.classify.outputs.source-commit }}"
  fail("runtime-recovery must qualify the selected source commit")
end
needs = build.fetch("needs")
needs_list = case needs
             when Array then needs
             when String then [needs]
             else fail("build.needs must be present")
             end
unless needs_list.include?("classify") && needs_list.include?("runtime-recovery")
  fail("build.needs must include classify and runtime-recovery")
end

release_path = File.join(File.dirname(workflow_path), "release.yml")
release_lines = File.readlines(release_path).length
fail("release.yml must stay <= 1000 lines (have #{release_lines})") if release_lines > 1000

release_text = File.read(release_path)
unless release_text.include?("scripts/release_manifest.py materialize")
  fail("release.yml must materialize manifests through release_manifest.py")
end
if release_text.match?(/compgen -G "artifacts\/\*x86_64-pc-windows-msvc\*"/)
  fail("Windows reject preflight must live in release_manifest materialize, not inline release.yml")
end

recovery_path = File.join(File.dirname(workflow_path), "runtime-recovery.yml")
fail("missing runtime-recovery.yml") unless File.file?(recovery_path)
recovery = YAML.safe_load(File.read(recovery_path), aliases: false)

# Shared validators: live workflow and mutated fixtures must use the same functions.
def runtime_recovery_workflow_error(recovery)
  triggers = recovery["on"] || recovery[true]
  return "runtime-recovery trigger map missing" unless triggers.is_a?(Hash)
  trigger_names = triggers.keys.map(&:to_s)
  unless trigger_names == ["workflow_call"]
    return "runtime-recovery must be workflow_call-only (found #{trigger_names.inspect})"
  end
  call = triggers["workflow_call"]
  return "workflow_call must be a mapping" unless call.is_a?(Hash)
  inputs = call["inputs"]
  return "workflow_call.inputs missing" unless inputs.is_a?(Hash)
  source = inputs["source-commit"]
  return "source-commit input missing" unless source.is_a?(Hash)
  return "source-commit input must be required" unless source["required"] == true
  return "source-commit input must be a string" unless source["type"].to_s == "string"

  job = recovery.dig("jobs", "recovery")
  return "recovery job missing" unless job.is_a?(Hash)
  matrix_os = job.dig("strategy", "matrix", "os")
  unless matrix_os == ["ubuntu-latest", "macos-latest"]
    return "recovery matrix.os must be exactly [ubuntu-latest, macos-latest]"
  end
  checkout = job.fetch("steps", []).find { |step| step.fetch("uses", "").start_with?("actions/checkout@") }
  return "recovery checkout step missing" unless checkout
  unless checkout.dig("with", "ref") == "${{ inputs.source-commit }}"
    return "recovery checkout.ref must use inputs.source-commit"
  end
  nil
end

def assert_runtime_recovery_workflow!(recovery)
  error = runtime_recovery_workflow_error(recovery)
  fail(error) if error
end

assert_runtime_recovery_workflow!(recovery)

recovery_job = recovery.fetch("jobs").fetch("recovery")
recovery_env = recovery_job.fetch("env")
%w[CARGO_PROFILE_DEV_DEBUG CARGO_PROFILE_TEST_DEBUG].each do |key|
  fail("runtime-recovery must set #{key}=0") unless recovery_env[key].to_s == "0"
end
pins = recovery_job.fetch("steps").map { |step| step["uses"] }.compact
{
  "step-security/harden-runner@" => "05e31511f85b41b11d1cf0ef85d0992719546e2c",
  "actions/checkout@" => "3d3c42e5aac5ba805825da76410c181273ba90b1",
  "dtolnay/rust-toolchain@" => "29eef336d9b2848a0b548edc03f92a220660cdb8",
  "Swatinem/rust-cache@" => "e18b497796c12c097a38f9edb9d0641fb99eee32",
}.each do |prefix, sha|
  step = pins.find { |value| value.start_with?(prefix) }
  fail("runtime-recovery missing #{prefix}") unless step
  fail("runtime-recovery must pin #{prefix}#{sha}") unless step.split("@", 2)[1] == sha
end
toolchain = recovery_job.fetch("steps").find { |step| step.fetch("uses", "").start_with?("dtolnay/rust-toolchain@") }
unless toolchain.dig("with", "toolchain").to_s == "1.95.0"
  fail("runtime-recovery must install exact toolchain 1.95.0")
end

# Extra triggers must fail the same workflow_call-only validator.
spoof_triggers = Marshal.load(Marshal.dump(recovery))
spoof_on = spoof_triggers["on"] || spoof_triggers[true]
spoof_on["push"] = { "branches" => ["main"] }
extra_trigger_error = runtime_recovery_workflow_error(spoof_triggers)
fail("additional triggers must fail workflow_call-only contract") if extra_trigger_error.nil?
fail("additional-trigger failure must mention workflow_call-only") unless extra_trigger_error.include?("workflow_call-only")

# Wrong checkout ref must fail the same validator.
spoof_ref = Marshal.load(Marshal.dump(recovery))
checkout = spoof_ref.fetch("jobs").fetch("recovery").fetch("steps").find do |step|
  step.fetch("uses", "").start_with?("actions/checkout@")
end
checkout.fetch("with")["ref"] = "${{ github.sha }}"
ref_error = runtime_recovery_workflow_error(spoof_ref)
fail("checkout ref spoof must fail recovery contract") if ref_error.nil?

# Narrowed/expanded matrix must fail the same validator.
spoof_matrix = Marshal.load(Marshal.dump(recovery))
spoof_matrix.fetch("jobs").fetch("recovery").fetch("strategy").fetch("matrix")["os"] = ["ubuntu-latest"]
matrix_error = runtime_recovery_workflow_error(spoof_matrix)
fail("matrix spoof must fail recovery contract") if matrix_error.nil?

API_CANCEL_SAFE_STEPS = {
  "Install cargo-semver-checks for core report" => ["install-internal-semver", "${{ !cancelled() && steps.api-inputs.outputs.run == 'true' }}"],
  "Report core crate API compatibility" => ["internal-semver", "${{ !cancelled() && steps.api-inputs.outputs.run == 'true' && steps.install-internal-semver.outcome == 'success' }}"],
  "Summarize Rust API compatibility policy" => [nil, "${{ !cancelled() && steps.api-inputs.outputs.run == 'true' }}"],
}.freeze

def api_cancel_safe_error(api_job)
  API_CANCEL_SAFE_STEPS.each do |name, (expected_id, expected_condition)|
    step = api_job.fetch("steps").find { |candidate| candidate["name"] == name }
    return "missing api-compatibility step #{name}" unless step
    return "api step #{name} id drift" if expected_id && step["id"] != expected_id
    condition = step["if"].to_s
    return "api step #{name} must not use always()" if condition.include?("always()")
    return "api step #{name} must use the exact cancel-safe condition" unless condition == expected_condition
  end
  nil
end

def assert_api_cancel_safe!(api_job)
  error = api_cancel_safe_error(api_job)
  fail(error) if error
end

api = workflow.fetch("jobs").fetch("api-compatibility")
assert_api_cancel_safe!(api)

# Mutated parsed workflow must fail through the same validator (not a mirror check).
spoof_always = Marshal.load(Marshal.dump(api))
spoof_always.fetch("steps").each do |step|
  next unless API_CANCEL_SAFE_STEPS.key?(step["name"].to_s)
  step["if"] = step["if"].to_s.gsub("!cancelled()", "always()")
end
always_error = api_cancel_safe_error(spoof_always)
fail("always() spoof must fail cancel-safe contract") if always_error.nil?
fail("always() spoof must be rejected for using always()") unless always_error.include?("must not use always()")

spoof_dead = Marshal.load(Marshal.dump(api))
spoof_dead.fetch("steps").each do |step|
  next unless API_CANCEL_SAFE_STEPS.key?(step["name"].to_s)
  step["if"] = step["if"].to_s.sub("!cancelled()", "false && !cancelled()")
end
dead_error = api_cancel_safe_error(spoof_dead)
fail("dead cancel-safe expression must fail") if dead_error.nil?
fail("dead expression must fail the exact condition") unless dead_error.include?("exact cancel-safe condition")

puts "CI workflow contract: PASS"
RB
