# CLAUDE.md - Security Module

## INHERITED FROM constitution/CLAUDE.md

All rules in `constitution/CLAUDE.md` (and the `constitution/Constitution.md` it references) apply unconditionally. This file's rules below extend them — they MUST NOT weaken any inherited rule. See parent root `CLAUDE.md` §6.AD for the Lava-specific incorporation context (29th §6.L cycle, 2026-05-14) and §6.AD-debt for the implementation-gap inventory. Use `constitution/find_constitution.sh` from the parent project root to resolve the absolute path of the submodule from any nested location.

## INHERITED FROM the Helix Constitution

This module is governed by the Helix Constitution. All rules in the
constitution's `CLAUDE.md` and the `Constitution.md` it references apply
unconditionally. Locate the constitution from any nested depth via its
`find_constitution.sh` helper — do NOT hardcode a path (this module stays
fully decoupled and project-agnostic per §11.4.28).

Canonical reference: https://github.com/HelixDevelopment/HelixConstitution

## Definition of Done

This module inherits the consuming project's universal Definition of Done. In
one line: **no task is done without pasted output from a real run of the real
system in the same session as the change.** Coverage and green suites are not
evidence.

### Acceptance demo for this module

```bash
# Guardrails + PII detection/redaction over real sensitive-string inputs
cd Security && GOMAXPROCS=2 nice -n 19 go test -count=1 -race -v ./pkg/pii/... ./pkg/guardrails/...
```
Expect: PASS; exercises `pii.NewRedactor`, `guardrails.NewEngine`, `content.NewChainFilter`, `policy.NewEnforcer` per `Security/README.md`. For the adversarial suite, see `RedTeam/` and `make test-redteam-fixtures` at root.


## Overview

`digital.vasic.security` is a standalone, reusable Go security module providing content guardrails, PII detection and redaction, content filtering, policy enforcement, and vulnerability scanning interfaces.

## Module Structure

- `pkg/guardrails` - Content guardrail engine with configurable rules
- `pkg/pii` - PII detection and redaction (email, phone, SSN, credit card, IP)
- `pkg/content` - Content filtering with chain-of-filters pattern
- `pkg/policy` - Policy enforcement with rules, conditions, and decisions
- `pkg/scanner` - Vulnerability scanning interface with findings and reports

## Build & Test

```bash
go test ./... -count=1 -race    # Run all tests with race detection
go test ./... -cover             # Run with coverage
go vet ./...                     # Vet all packages
```

## Code Style

- Standard Go conventions, `gofmt` formatting
- Imports grouped: stdlib, third-party, internal
- Table-driven tests with testify
- Interfaces: small, focused, accept interfaces return structs
- Errors: always check, wrap with `fmt.Errorf("...: %w", err)`

## Dependencies

- `github.com/stretchr/testify` - Testing assertions
- `golang.org/x/crypto` - audited crypto library; permitted for the ChaCha20-Poly1305 AEAD (`golang.org/x/crypto/chacha20poly1305`, RFC 8439) used by `pkg/e2ee` alongside stdlib AES-256-GCM. (Operator-authorized 2026-06-03 for HXC-1561, overriding the prior testify-only clause for this single audited crypto dependency.)
- No other external dependencies
- No dependency on any consuming application

## Integration Seams

| Direction | Sibling modules |
|-----------|-----------------|
| Upstream (this module imports) | none |
| Downstream (these import this module) | HelixLLM, HelixQA |

*Siblings* means other project-owned modules at the parent project's repo root. The root application and external systems are not listed here — the list above is intentionally scoped to module-to-module seams, because drift *between* sibling modules is where the "tests pass, product broken" class of bug most often lives.

## Submodule Decoupling & Reusability — MANDATORY

This repository is **shared infrastructure** consumed by multiple
independent consumer projects. Its specialized responsibility makes
it reusable — and that reusability is destroyed the moment any
consumer's specifics leak in.

**Hard rules when editing anything in this repository:**

- DO NOT hardcode any specific consumer project's name, platform
  list, paths, version strings, or release-naming conventions.
- DO NOT import / reference any consumer-project namespace.
- DO NOT embed consumer-project-specific governance, branding, or
  rule numbering in `CONSTITUTION.md` / `CLAUDE.md` / `AGENTS.md`.
- DO assume N ≥ 2 unrelated consumer projects exist, even if you
  only know of one today.

Cross-project rules MUST be phrased generically ("every consuming
project's full platform matrix"), never with a specific consumer's
matrix hardcoded.
