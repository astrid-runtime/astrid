## Linked Issue

Closes #<!-- issue number -->

<!-- Every PR must be linked to an issue. If there is no issue, create one first. -->

## Summary

<!-- What does this PR do and why? Keep it brief. -->

## Changes

<!-- Bullet list of notable changes. -->

-

## Verification

<!-- How was this PR validated? Pick what applies:
     - Code: `cargo test --workspace` passes, no new clippy warnings, new/updated tests for the change.
     - Release: CI green on the version bump + `scripts/changelog.py roll`; no code changes.
     - Docs / CI / chore: how you checked the result (rendered output, workflow run, dry-run, etc.).
     Include manual verification steps for a reviewer where they add signal. -->

## AI / Tool Assistance

<!-- Enter "None" for no meaningful tool-generated content. Otherwise include an Assisted-by: TOOL:MODEL line, describe the affected areas and assistance, and explain how you reviewed and validated the result. Trivial autocomplete, formatting, and mechanical edits do not need disclosure. -->

None

## Checklist

- [ ] Linked to an issue
- [ ] Changelog fragment added under `changes/{issue}.{kind}.md` (docs/CI-only may skip; release PRs roll fragments into the version section instead of adding one)
- [ ] I understand every change in this PR and can explain its design, risks, and validation.
- [ ] I reviewed and tested any meaningful tool-generated output included in this PR.
- [ ] Every non-bot, non-merge commit has a matching `Signed-off-by` trailer.
