# AGENTS.md - Security Module

## INHERITED FROM constitution/AGENTS.md

All rules in `constitution/AGENTS.md` (and the `constitution/Constitution.md` it references) apply unconditionally. This file's rules below extend them — they MUST NOT weaken any inherited rule. Use `constitution/find_constitution.sh` from the parent project root to resolve the absolute path of the submodule from any nested location.

## INHERITED FROM the Helix Constitution

This module is governed by the Helix Constitution. All rules in the
constitution's `AGENTS.md` and the `Constitution.md` it references apply
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

## Module Overview

`digital.vasic.security` is a standalone, reusable Go security module (Go
1.24+) providing five independent packages for content guardrails, PII
detection and redaction, content filtering, policy enforcement, and
vulnerability scanning. The module has zero dependencies on any consuming
application.

## Package Responsibilities

### pkg/guardrails
- **Responsibility**: Configurable content guardrail engine with rule-based validation.
- **Key types**: `Engine`, `Rule` (interface), `Config`, `RuleConfig`, `Result`, `RuleResult`, `Severity`
- **Built-in rules**: `MaxLengthRule`, `ForbiddenPatternsRule`, `RequireFormatRule`
- **Concurrency**: Thread-safe via `sync.RWMutex` on `Engine`
- **Key file**: `pkg/guardrails/guardrails.go`

### pkg/pii
- **Responsibility**: PII detection and redaction with configurable detectors and redaction strategies.
- **Key types**: `Redactor`, `Detector` (interface), `Config`, `Match`, `Type`, `RedactionStrategy`
- **Built-in detectors**: `EmailDetector`, `PhoneDetector`, `SSNDetector`, `CreditCardDetector`, `IPAddressDetector`
- **Redaction strategies**: `StrategyMask`, `StrategyHash`, `StrategyRemove`
- **Validation**: Luhn algorithm for credit card number verification
- **Key file**: `pkg/pii/pii.go`

### pkg/content
- **Responsibility**: Composable content filter chains for input validation.
- **Key types**: `ChainFilter`, `Filter` (interface), `FilterResult`, `LengthFilter`, `PatternFilter`, `KeywordFilter`
- **Pattern**: Chain of Responsibility — content must pass all filters sequentially.
- **Key file**: `pkg/content/content.go`

### pkg/policy
- **Responsibility**: Rule-based policy evaluation with conditions, operators, and decisions.
- **Key types**: `Enforcer`, `Policy`, `Rule`, `Condition`, `EvaluationContext`, `EvaluationResult`, `Decision`, `Operator`
- **Decisions**: `Allow`, `Deny`, `Audit`
- **Operators**: `Equals`, `NotEquals`, `Contains`, `StartsWith`, `EndsWith`, `In`, `NotIn`, `Exists`, `NotExists`
- **Concurrency**: Thread-safe via `sync.RWMutex` on `Enforcer`
- **Context support**: All evaluation methods accept `context.Context`
- **Key file**: `pkg/policy/policy.go`

### pkg/scanner
- **Responsibility**: Vulnerability scanning interface with findings aggregation and reporting.
- **Key types**: `Scanner` (interface), `Finding`, `Report`, `Severity`
- **Report features**: Severity breakdown, filtering, merging, summary generation
- **Context support**: `Scanner.Scan` accepts `context.Context`
- **Key file**: `pkg/scanner/scanner.go`

## Agent Coordination Model

### Independence Principle
Each package is fully self-contained with no cross-package imports. Agents working on different packages can operate in complete isolation without coordination overhead.

### Integration Points
When an integrating application combines these packages, coordination follows this order:

1. **Content Filtering** (`content`) — first-pass validation of raw input (length, patterns, keywords)
2. **PII Detection** (`pii`) — detect and redact sensitive data before further processing
3. **Guardrails** (`guardrails`) — validate processed content against domain-specific rules
4. **Policy Enforcement** (`policy`) — evaluate access control and behavioral policies
5. **Vulnerability Scanning** (`scanner`) — scan artifacts for security vulnerabilities

### Work Distribution Guidelines
- **Adding a new built-in rule/filter/detector**: Work within the single relevant package. No cross-package changes needed.
- **Adding a new package**: Create under `pkg/`, ensure zero imports from other `pkg/` packages, add tests.
- **Modifying an interface**: Coordinate with all agents that may implement or consume that interface. The interfaces are `Rule`, `Detector`, `Filter`, `Scanner`.
- **Updating shared patterns** (e.g., severity levels): Both `guardrails` and `scanner` define their own `Severity` type independently. Changes to one do not affect the other.

## Build & Test

```bash
# Run all tests with race detection
go test ./... -count=1 -race

# Run all tests with coverage
go test ./... -cover

# Run a single package's tests
go test -v ./pkg/guardrails/...
go test -v ./pkg/pii/...
go test -v ./pkg/content/...
go test -v ./pkg/policy/...
go test -v ./pkg/scanner/...

# Run a specific test
go test -v -run TestEngine_Check_WithRules ./pkg/guardrails/

# Vet all packages
go vet ./...
```

## Code Style

- Standard Go conventions, `gofmt` formatting
- Imports grouped: stdlib, third-party, internal
- Table-driven tests with testify
- Interfaces: small, focused, accept interfaces return structs
- Errors: always check, wrap with `fmt.Errorf("...: %w", err)`

## Dependencies

### External
- `github.com/stretchr/testify` — test assertions and requirements (test-only)
- `golang.org/x/crypto` — audited crypto library; permitted for the ChaCha20-Poly1305 AEAD (`golang.org/x/crypto/chacha20poly1305`, RFC 8439) used by `pkg/e2ee` alongside stdlib AES-256-GCM. (Operator-authorized 2026-06-03 for HXC-1561, overriding the prior testify-only clause for this single audited crypto dependency.)
- No other external dependencies
- No dependency on any consuming application

### Indirect (via testify)
- `github.com/davecgh/go-spew`
- `github.com/pmezard/go-difflib`
- `gopkg.in/yaml.v3`

### Standard Library Usage
- `fmt` — error formatting and string output
- `regexp` — pattern matching in guardrails, PII detection, content filtering
- `sync` — `RWMutex` for thread-safe engines (guardrails, policy)
- `strings` — string manipulation in PII masking, keyword filtering, condition evaluation
- `crypto/sha256` — PII hash redaction strategy
- `encoding/hex` — hex encoding for hash output
- `context` — context propagation in policy and scanner
- `time` — scan duration and timestamps in scanner reports

## Integration Seams

| Direction | Sibling modules |
|-----------|-----------------|
| Upstream (this module imports) | none |
| Downstream (these import this module) | HelixLLM, HelixQA |

*Siblings* means other project-owned modules at the parent project's repo root. The root application and external systems are not listed here — the list above is intentionally scoped to module-to-module seams, because drift *between* sibling modules is where the "tests pass, product broken" class of bug most often lives.

### Integration with a consuming application
This module has no dependency on any consuming application. A consuming application integrates it via `internal/security/` which wraps these packages with application-specific configuration. When working on this module, changes should never introduce imports from `dev.helix.agent` or any other external module besides testify.

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
  rule numbering in this module's own governance carriers.
- DO assume N ≥ 2 unrelated consumer projects exist, even if you
  only know of one today.

Cross-project rules MUST be phrased generically ("every consuming
project's full platform matrix"), never with a specific consumer's
matrix hardcoded.

## Anti-Bluff — read first

Tests and Challenges exist for exactly one purpose: to confirm a feature
genuinely works for a real end user, end-to-end. A test that passes while the
feature is broken is a bluff test and is forbidden. CI green is necessary,
never sufficient. See this module's governance-carrier set (this file's
siblings, one per supported CLI) and `CONSTITUTION.md` for the full
anti-bluff mandate.
