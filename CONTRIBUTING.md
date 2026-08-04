# Contributing to Astrid

Thank you for your interest in Astrid. This document explains how contributions work.

Astrid is a security-critical runtime. Every change is reviewed carefully. We use a tiered
contributor system to protect the project while welcoming new contributors who follow the process.

## Contributor Tiers

| Tier | Who | What they can do |
|------|-----|------------------|
| **New** | Anyone not yet in `contributors.yml` and without repository read access | Must open an issue first, wait for assignment, and have a maintainer add the `newcomer-approved` label to their PR |
| **Astrinaut** | Promoted after a successful first contribution | Can self-claim issues and submit PRs to non-core crates (CLI, SDK, capsules, docs, tests) |
| **Core** | Promoted after sustained quality contributions | Can work on core crates (kernel, events, hooks, config). Security-critical paths still require maintainer co-review |
| **Maintainer** | Project leads | Full access including security paths, refactors, and releases |

Tier promotions happen at maintainer discretion based on the quality and consistency of your work.
The contributor list lives in `.github/contributors.yml`.

## How to Contribute

### 1. Start with an issue

Every PR must be linked to an issue. No exceptions.

- Check existing issues before opening a new one
- Use the bug report or feature request templates, or open a blank issue
- Wait for a maintainer to triage and assign the issue to you before starting work

Do not open a PR for work nobody asked for. Unsolicited PRs will be closed.

### 2. Get assigned

Comment on the issue to claim it. A maintainer will assign it to you. For new contributors, this is
also when a maintainer evaluates whether the task is a good fit for a first contribution.

### 3. Fork and branch

- Fork the repository
- Create a branch off `main` with a descriptive name: `feat/add-auth`, `fix/timeout-bug`
- Keep your branch up to date with `main`

### 4. Write your code

- Follow existing code style and patterns
- Individual files must not exceed 1000 lines. Split large files into modules
- Run `cargo test --workspace` and `cargo clippy -- -D warnings` before submitting
- Update `CHANGELOG.md` under the `[Unreleased]` section

### 5. Open a pull request

- Fill in the PR template completely. PRs with empty sections will be rejected by CI
- Link your PR to the issue using `Closes #N`
- New contributors without repository read access: a maintainer will review and add the `newcomer-approved` label

### 6. Review

All PRs require at least one maintainer review. Expect feedback - this is a security project and
review is thorough. Address all comments before requesting re-review.

## Contribution Quality and AI-Assisted Submissions

Astrid does not accept bulk audits, speculative findings, or drive-by issues and PRs generated
without the contributor checking them. AI output is a drafting aid, not evidence.

Before opening an issue, reproduce the problem where possible and include the affected version or
commit, exact steps, expected and actual behavior, and supporting evidence. Before opening a PR,
understand the complete diff, explain why the change is needed, run the relevant tests, and be
prepared to answer review questions or narrow the scope. Maintainers may close submissions that
do not meet this bar or temporarily restrict further submissions while a contributor establishes
that they can participate constructively.

## Developer Certificate of Origin and Tool-Assisted Contributions

Every non-bot, non-merge commit must include a `Signed-off-by` trailer whose email matches
the commit author. Add it with Git's sign-off option:

```bash
git commit -s -m "fix(scope): describe the change"
```

The sign-off is a human certification. An AI or other tool must not add it on the contributor's
behalf. See the [Developer Certificate of Origin](https://developercertificate.org/) for the
full terms.

Astrid permits tool-assisted contributions when the human contributor remains accountable for
the complete submission. For meaningful tool-generated content, disclose the tool or model,
the affected areas, the nature of the assistance, and the review and validation performed in
the PR's **AI / Tool Assistance** section. Use an attribution such as
`Assisted-by: Codex: MODEL_VERSION` there. For longer sessions, include a concise summary of
the prompts or instructions that materially shaped the result. Trivial autocomplete,
formatting, and mechanical transformations are outside this disclosure requirement.

Before requesting review, the contributor must understand every change, be able to explain its
design and risks, defend the implementation, and respond meaningfully to review comments.
Maintainers may request a walkthrough, additional tests, or a narrower change set when the
submission is not sufficiently understood or validated.

## What We Will Not Accept

- **Drive-by PRs** with no linked issue or prior discussion
- **Tool-generated bulk submissions** that the contributor cannot explain, defend, or validate
- **Refactors** from non-maintainers. If you see something that needs refactoring, open an issue
- **Changes to security-critical crates** without the appropriate tier

## Code Guidelines

- **1000-line file limit.** No exceptions without the `large-file-ok` label from a maintainer
- **Conventional Commits.** `feat(scope): description`, `fix(scope): description`, etc.
- **Tests required.** New features need tests. Bug fixes need a regression test
- **No unsafe code** without explicit justification and maintainer approval

## Security-Critical Crates

The following crates form the security boundary and have restricted access:

- `astrid-crypto` - Cryptographic primitives
- `astrid-capabilities` - Capability token authorization
- `astrid-audit` - Cryptographic audit logging
- `astrid-approval` - Approval gate system
- `astrid-vfs` - Virtual filesystem sandbox
- `astrid-storage` - Persistent state and keychain
- `astrid-sys` - OS microkernel bindings
- `astrid-core` - Foundation types and authorization interfaces

Only core and maintainer tier contributors can modify these crates.

## Reporting Security Vulnerabilities

Do **not** open a public issue. Use
[GitHub Security Advisories](https://github.com/astrid-runtime/astrid/security/advisories/new)
to report vulnerabilities privately. See [SECURITY.md](SECURITY.md) for details.
