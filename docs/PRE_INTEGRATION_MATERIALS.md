# Security — Pre-Integration Materials

**Revision:** 1
**Last modified:** 2026-07-15T11:20:53Z
**Purpose:** Consolidated pre-integration materials (gate before any integration/deployment work).

> Scope note: this document consolidates and verifies existing pre-integration
> materials for the `digital.vasic.security` Go module. It cross-references
> `ARCHITECTURE.md`, `README.md`, and `docs/` rather than rewriting them. Every
> statement below is grounded in the real repository at
> `tools/helixqa/security`; anything not determinable from the repo is marked
> `UNKNOWN:` per §11.4.6 (no-guessing). Security-sensitive configuration is
> described by variable NAME only — no secret values appear here.

---

## 1. Purpose / What it is

Generic, reusable **defensive security library** for Go applications
(`ARCHITECTURE.md` §Purpose; `README.md` intro). It is a leaf Go module —
`module digital.vasic.security` (`go.mod:1`) — providing composable,
independently-usable security concerns. Real capabilities, grounded in the
`pkg/` source tree:

- **Content guardrails** — rule pipeline with severity levels (`pkg/guardrails/`).
- **PII detection + redaction** — email / phone / SSN / credit-card / IPv4, with
  confidence scoring and Mask / Hash / Remove strategies (`pkg/pii/`).
- **Content filtering** — composable chain-of-filters, first-rejection-wins
  (`pkg/content/`).
- **Policy enforcement** — named policies with rules, conditions (8 operators),
  and Allow / Deny / Audit decisions (`pkg/policy/`).
- **Vulnerability scanning interface** — findings, reports, severity filtering,
  report merging (`pkg/scanner/scanner.go:1` — "provides a vulnerability
  scanning interface with severity …").
- **HTTP security-headers middleware** — CSP / HSTS / X-Frame-Options and more
  (`pkg/headers/`).
- **AES-256-GCM encrypted file storage** — key-value storage, credential/token/key
  helpers, Argon2id key derivation (`pkg/securestorage/`; `README.md`
  Anti-Bluff Guarantee #1).
- **Host / container privilege-escalation scanning** — probes `/proc/self/status`,
  capability bitmasks, namespace/cgroup hierarchy on the local host
  (`pkg/security/privesc_scan.go:1` — "provides host and container security
  scanning utilities."; `README.md` Anti-Bluff Guarantee #5).
- **SSRF guard** — canonical Server-Side Request Forgery deny-guard for the
  caller's outbound HTTP client (`pkg/ssrf/guard.go:4` — "Package ssrf is the
  canonical Server-Side Request Forgery guard").
- **End-to-end encryption transport** — ChaCha20-Poly1305 sealed packages,
  response keypairs, SSE, compression (`pkg/e2ee/`; sole crypto dependency
  `golang.org/x/crypto/chacha20poly1305`).
- **TEE attestation** — clean-room Trusted Execution Environment attestation
  (`pkg/attestation/attestation.go:1`).
- **GPU attestation** — clean-room proof-of-GPU attestation + sealing
  (`pkg/gpuattest/package.go:1`).
- **i18n** — message bundle / translator support for security messages
  (`pkg/i18n/`).

**Defensive-use boundary (load-bearing):** every package's polarity is
detect / redact / deny / harden / audit — never attack, exfiltrate, escalate,
or evade (`README.md` §"Defensive-use boundary"). Flipping a package's polarity
is a boundary violation regardless of test status.

> `UNKNOWN:` documentation/code delta — `ARCHITECTURE.md` §Structure and
> `README.md` §Architecture enumerate 7 core packages (guardrails, pii, content,
> policy, scanner, headers, securestorage). The shipped `pkg/` tree additionally
> contains `e2ee`, `attestation`, `gpuattest`, `ssrf`, `i18n`, and
> `security` (privesc_scan). The `README.md` Anti-Bluff and Defensive-use
> sections DO reference `ssrf` and `security/privesc_scan`, so the omission is in
> the two structure diagrams only. Flagged for the doc-sync owner; not resolved
> here (docs-only, no source edits).

## 2. Architecture overview

Layered, defence-in-depth design where each package addresses one concern
independently and packages compose (`ARCHITECTURE.md` §Purpose + §Data Flow;
`README.md` §Architecture). Canonical data flows (`ARCHITECTURE.md` §"Data Flow"):

- Content validation: `input → guardrails.Check() → pii.Redact() →
  content.ChainFilter.Check()`.
- Policy enforcement: `enforcer.Evaluate(ctx, "policy-name", evalCtx)` → per-rule
  condition evaluation → matched `rule.Decision`, else `DefaultDecision`.
- Security headers: `headers.Middleware(config)(handler)` sets the standard header
  set on every response.

Real package layout (from the `pkg/` tree):

```
pkg/
  guardrails/     content guardrail engine (rules + severity)
  pii/            PII detection + redaction (+ confidence scoring)
  content/        composable filter chains
  policy/         rule/condition/decision enforcement
  scanner/        vulnerability scan interface + reports
  headers/        HTTP security-headers middleware
  securestorage/  AES-256-GCM encrypted key-value storage
  ssrf/           SSRF deny-guard for outbound HTTP
  security/       host/container privesc scanner
  e2ee/           end-to-end encryption transport (ChaCha20-Poly1305)
  attestation/    clean-room TEE attestation
  gpuattest/      clean-room proof-of-GPU attestation
  i18n/           message bundle / translator
```

Stack: pure Go (`go 1.25.0`, `toolchain go1.26.4` — `go.mod:3-4`). Full
per-symbol reference: `docs/API_REFERENCE.md`; layered design notes:
`ARCHITECTURE.md` (this document does not restate them). Diagrams:
`docs/diagrams/architecture.mmd`, `class.mmd`, `sequence.mmd`.

## 3. Dependencies

**Submodule dependency manifest** (`helix-deps.yaml`): `schema_version: 1`,
`deps: []` — a leaf Go module with **ZERO own-org submodule dependencies**;
`transitive_handling.recursive: true`, `conflict_resolution: operator-required`,
`language_specific_subtree: false`. Consistent with the absence of a
`.gitmodules` file (none present in the repo root).

**Go module dependencies** (`go.mod`):

- Direct:
  - `github.com/stretchr/testify v1.11.1` — test assertions (test-only).
  - `golang.org/x/crypto v0.52.0` — cryptographic primitives; the only crypto
    sub-package imported in `pkg/` is `golang.org/x/crypto/chacha20poly1305`
    (used by `pkg/e2ee/`). AES-256-GCM in `pkg/securestorage/` uses the Go
    standard library (`crypto/aes`, `crypto/cipher`).
- Indirect: `davecgh/go-spew`, `kr/pretty`, `pmezard/go-difflib`,
  `rogpeppe/go-internal`, `golang.org/x/sys`, `gopkg.in/check.v1`,
  `gopkg.in/yaml.v3` (all transitive of testify).

`ARCHITECTURE.md` §Dependencies states "zero production dependencies"; the sole
non-stdlib production import is `golang.org/x/crypto/chacha20poly1305`
(`golang.org/x/crypto` is a Go-team-maintained extended-stdlib module).

**Required config env-var NAMES only** (`env.properties`): `PROJECT_NAME` is the
only key present. `env.properties` contains **no credential or secret keys** —
it holds a single non-sensitive project-name property. There is a separate
credential loader `scripts/load_api_keys.sh` (script present; not invoked here,
and no key values are read or echoed).

**Infra:** none required to consume the library — no database, message broker,
container runtime, or external service is referenced by `pkg/` production code.

## 4. Deploy / Distribution design

**Type: Go LIBRARY.** No binary and no container:

- The build target is `go build ./...` (`Makefile:9-10`) — it compiles the
  packages; it produces **no executable artifact** (there is no `cmd/` directory
  and no `func main()` in production `pkg/` code — the only `main()` occurrences
  are in the shell Challenge helper `challenges/scripts/security_describe_challenge.sh:109`
  and in doc code examples under `docs/`).
- No `Dockerfile*` / `compose*.yml` exists in the repo (`ls` for
  `docker`/`compose` returned none).

**Distribution slice:** consumed **by reference** as a Go module dependency —
downstream Go code imports `digital.vasic.security/pkg/<concern>` (e.g.
`import "digital.vasic.security/pkg/guardrails"`, `docs/API_REFERENCE.md`). In
the Helix multi-repo layout it is also carried as a git submodule; upstream
remotes are wired via the repo-local `install_upstreams.sh` + `upstreams/`
directory (present in the repo root), consistent with the §11.4.36
install-upstreams-on-clone discipline. Per `helix-deps.yaml` it stays
project-agnostic and fully decoupled (§11.4.28) — a consuming project registers
its own configuration; the library hard-codes no consumer context.

## 5. Ports

`UNKNOWN:` — **library, no own listen port.** A grep of `pkg/` for
`ListenAndServe` / `http.Serve` / `net.Listen` returned no matches. The module
exposes no network server; `pkg/headers/` is middleware that decorates a
caller-owned `http.Handler` (it does not open a socket). Any listening port is
owned by the consuming application, not by this library.

## 6. Health

`UNKNOWN:` — **library, no health endpoint / no long-running process.** A grep of
`pkg/` for `/health` / `/healthz` / `Serve(` returned no matches. There is no
daemon to health-check; correctness is asserted by the module's own test +
Challenge suite instead (see §8). Consumers that embed the middleware/guards
expose health through their own service surface.

## 7. How it boots

**Consumed as a library — there is no entrypoint / no boot sequence.** The module
has no `cmd/`, no `func main()` in production code, and no init service. A
consumer:

1. Adds the module (`go get digital.vasic.security/...` or via the submodule /
   `install_upstreams.sh` wiring).
2. Imports the specific package(s) it needs
   (`digital.vasic.security/pkg/<concern>`).
3. Constructs and invokes the exported types directly (e.g.
   `guardrails.Engine`, `pii.Redactor`, `policy.Enforcer`,
   `headers.Middleware`, `securestorage.FileStorage`; see `docs/USER_GUIDE.md`
   and `docs/website/getting-started.md` for integration walkthroughs).

Build / test / verify entrypoints for CI (`Makefile`): `make build`
(`go build ./...`), `make test` / `make test-race` (race-enabled, `-p 1`),
`make test-coverage`, `make vet`, `make lint`, and `make ci-validate-all`
(`no-silent-skips-warn` + `demo-all-warn`, `Makefile:87`). Anti-bluff Challenge
runners live under `challenges/scripts/` (12 scripts, incl.
`security_functionality_challenge.sh`, `security_unit_challenge.sh`,
`security_compile_challenge.sh`, `security_describe_challenge.sh` mutation
harness, plus stress / chaos / scaling / DDoS / UX scripts).

## 8. Materials status (verify pass)

| Material | Present? | Evidence (path) | Notes |
|---|---|---|---|
| Purpose / capability description | YES | `ARCHITECTURE.md` §Purpose, `README.md` intro | Real capabilities enumerated in §1 |
| Architecture doc | YES | `ARCHITECTURE.md`, `docs/ARCHITECTURE.md`, `docs/diagrams/*.mmd` | Cross-referenced, not rewritten |
| API reference | YES | `docs/API_REFERENCE.md` | Per-symbol reference |
| User / integration guide | YES | `docs/USER_GUIDE.md`, `docs/website/getting-started.md`, `docs/CONTRIBUTING.md` | Boot-as-library walkthrough |
| Dependency manifest | YES | `helix-deps.yaml` (`deps: []`), `go.mod` | Leaf module, zero own-org deps |
| Submodule wiring | YES | `install_upstreams.sh`, `upstreams/`; no `.gitmodules` | Consumed by reference |
| Config surface (env) | YES | `env.properties` (`PROJECT_NAME` only) | No secrets in `env.properties` |
| Build/test tooling | YES | `Makefile`, `scripts/`, `tests/` (integration/e2e/stress/benchmark/security) | `go build ./...`, race tests |
| Anti-bluff Challenges | YES | `challenges/scripts/*.sh` (12 scripts) | Paired-mutation contract per §1.1 |
| Governance | YES | `CONSTITUTION.md`, `CLAUDE.md`, `AGENTS.md`, `QWEN.md` | Inherited |
| Host-power posture | YES | `docs/HOST_POWER_MANAGEMENT.md`, `scripts/host-power-management/` | CONST-033 |
| Dockerfile / compose | N/A | (none) | Library — no container distribution |
| Listen port | N/A | grep: no `ListenAndServe`/`net.Listen` | §5 `UNKNOWN:` (library) |
| Health endpoint | N/A | grep: no `/health` | §6 `UNKNOWN:` (library) |
| Runtime entrypoint | N/A | no `cmd/`, no production `main()` | §7 consumed as library |

**Verdict: HAS-VERIFIED.** All pre-integration materials required for a Go
library — purpose, architecture, API reference, integration guide, dependency
manifest, config surface, build/test tooling, and anti-bluff Challenges — exist
in the repository and were verified against the real source tree. The Ports,
Health, Dockerfile, and Runtime-entrypoint rows are `N/A` because the module is a
consumed-by-reference library with no own process, not because a material is
missing. One documentation-sync observation is recorded in §1 (`UNKNOWN:` doc/code
package-list delta) for the doc-sync owner; it does not block integration.
