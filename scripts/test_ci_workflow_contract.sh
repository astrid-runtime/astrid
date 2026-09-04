#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
workflow="${1:-$repo_root/.github/workflows/ci.yml}"

ruby - "$workflow" <<'RB'
require "yaml"

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

# Keep this contract wired to both CI trigger classes. Parse the trigger map so
# comments or similarly named text cannot make an absent path entry pass.
triggers = workflow["on"] || workflow[true]
fail("missing workflow trigger map") unless triggers.is_a?(Hash)
%w[push pull_request].each do |event_name|
  event = triggers.fetch(event_name) { fail("missing #{event_name} trigger") }
  paths = event.fetch("paths") { fail("missing #{event_name}.paths filter") }
  unless paths.is_a?(Array) && paths.count("scripts/test_ci_workflow_contract.sh") == 1
    fail("contract test must appear exactly once in #{event_name}.paths")
  end
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

puts "CI workflow contract: PASS"
RB
