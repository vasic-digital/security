# Security — Constitution

## INHERITED FROM constitution/Constitution.md

All rules in `constitution/Constitution.md` (and the `constitution/Constitution.md` it references) apply unconditionally. This file's rules below extend them — they MUST NOT weaken any inherited rule. See parent root `CLAUDE.md` §6.AD for the Lava-specific incorporation context (29th §6.L cycle, 2026-05-14) and §6.AD-debt for the implementation-gap inventory. Use `constitution/find_constitution.sh` from the parent project root to resolve the absolute path of the submodule from any nested location.

## INHERITED FROM the Helix Constitution

This module is governed by the Helix Constitution. All rules in the
constitution's `CONSTITUTION.md` and the `Constitution.md` it references apply
unconditionally. Locate the constitution from any nested depth via its
`find_constitution.sh` helper — do NOT hardcode a path (this module stays
fully decoupled and project-agnostic per §11.4.28).

Canonical reference: https://github.com/HelixDevelopment/HelixConstitution

> **Status:** Active. This document is the project's authoritative
> rule set. When a rule here conflicts with `CLAUDE.md`, `AGENTS.md`,
> or any guide, the Constitution wins.

## Mission

See README.md.

## Mandatory Standards

1. **Reproducibility:** every change is reproducible from a clean
   clone (`git clone <repo> && <project bootstrap>`); no hidden steps.
2. **Tests track behavior, not code:** test what the user-visible
   behavior is, not what the implementation looks like.
3. **No silent skips, no silent mocks above unit tests.**
4. **Conventional Commits** for all commits.
5. **SSH-only for git operations** (`git@…`); HTTPS prohibited.

## Definition of Done

A change is done when:

1. The code change is committed.
2. All project-level tests pass on a clean clone.
3. All challenges in `challenges/scripts/` pass on the running host.
4. Governance docs (`CONSTITUTION.md`, `AGENTS.md`, `CLAUDE.md`) are
   coherent with the change.

## Submodule Decoupling & Reusability — Mandatory

**Status:** Mandatory. Non-negotiable.

**Rule:** This repository is a **shared submodule** consumed by
multiple independent consumer projects. Its value depends on staying
**fully decoupled and reusable**. No change in this repository may
introduce coupling that breaks its standalone reusability for any
consumer.

**Prohibited inside this repository:**

1. Hardcoding any specific consumer project's name, paths, platform
   list, version strings, release-naming conventions, branding, or
   feature names.
2. `import` / dependency on any consumer-project namespace, package,
   or build coordinate.
3. Embedding consumer-project-specific governance, rule numbering, or
   release cadence into this repository's `CONSTITUTION.md` /
   `CLAUDE.md` / `AGENTS.md`.
4. Assuming this repository is consumed by a particular CLI, build
   system, language toolchain version, or target architecture beyond
   what its public interface documents.

**Required inside this repository:**

1. All public surfaces (APIs, CLIs, configuration files, environment
   variables, scripts) MUST be expressed in terms of THIS repository's
   own domain — not any consumer's.
2. Governance MUST describe responsibilities and contract from THIS
   repository's perspective. Consumer projects appear as illustrative
   examples at most, never as load-bearing requirements.
3. Cross-project rules adopted from a consumer (such as a
   cross-platform impact mandate) MUST be phrased generically —
   "every consuming project's full platform matrix" — and never
   hardcode any single consumer's matrix.

**Why:** Repositories like this one have shipped changes in the past
where one consumer's platform list, feature names, or rule numbering
leaked into shared-repo governance — and then collided at merge time
with another consumer's parallel work, leaving the repository
unmergeable until manual conflict resolution stripped the
consumer-specific text back out. Decoupling is the only mechanism
that preserves this repository's value as shared infrastructure.

**Recursive scope:** any submodule this repository consumes inherits
the same decoupling+reusability rule. Third-party upstream submodules
that this repository merely vendors (e.g. open-source tools under a
`tools/opensource/` tree, if present) are explicitly out of scope —
we are not their owners.

## See also

- `README.md` — project overview, quickstart.
- `AGENTS.md` — guidance for AI coding agents (Codex, Cursor, etc.).
- `CLAUDE.md` — guidance specifically for Claude Code.
