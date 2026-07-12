# Contributing to Astrid

Thank you for your interest in Astrid. This document explains how contributions work.

Astrid is a security-critical runtime. Every change is reviewed carefully. We use a tiered
contributor system to protect the project while welcoming new contributors who follow the process.

## Contributor Tiers

| Tier | Who | What they can do |
|------|-----|------------------|
| **New** | Anyone not yet in `contributors.yml` | Must open an issue first, wait for assignment, and have a maintainer add the `newcomer-approved` label to their PR |
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
- New contributors: a maintainer will review and add the `newcomer-approved` label

### 6. Review

All PRs require at least one maintainer review. Expect feedback - this is a security project and
review is thorough. Address all comments before requesting re-review.

## What We Will Not Accept

- **Drive-by PRs** with no linked issue or prior discussion
- **AI-generated bulk submissions** that lack understanding of the codebase
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
