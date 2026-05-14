## INHERITED FROM Helix Constitution

This module is a submodule of a Helix-family project (e.g.
HelixCode, HelixAgent, ATMOSphere) that includes the Helix
Constitution submodule at the parent's `constitution/` path. All
rules in `constitution/CLAUDE.md` and the
`constitution/Constitution.md` it references (universal anti-bluff
covenant §11.4, no-guessing mandate §11.4.6, credentials-handling
mandate §11.4.10, host-session safety §12, data safety §9, mutation-
paired gates §1.1) apply unconditionally to every change landed here.
The module-specific rules below extend them — they never weaken any
universal clause.

When this file disagrees with the constitution submodule, the
constitution wins. Locate the constitution submodule from any
arbitrary nested depth using its `find_constitution.sh` helper.

Canonical reference: <https://github.com/HelixDevelopment/HelixConstitution>

---

# AGENTS.md - Security Module Multi-Agent Coordination Guide

## Module Overview

`digital.vasic.security` is a standalone, reusable Go security module (Go 1.24+) providing five independent packages for content guardrails, PII detection and redaction, content filtering, policy enforcement, and vulnerability scanning. The module has zero dependencies on HelixAgent and only depends on `github.com/stretchr/testify` for testing.

## Package Responsibilities

### pkg/guardrails
- **Owner**: Content Safety Agent
- **Responsibility**: Configurable content guardrail engine with rule-based validation.
- **Key types**: `Engine`, `Rule` (interface), `Config`, `RuleConfig`, `Result`, `RuleResult`, `Severity`
- **Built-in rules**: `MaxLengthRule`, `ForbiddenPatternsRule`, `RequireFormatRule`
- **Concurrency**: Thread-safe via `sync.RWMutex` on `Engine`
- **Key file**: `pkg/guardrails/guardrails.go`

### pkg/pii
- **Owner**: Data Privacy Agent
- **Responsibility**: PII detection and redaction with configurable detectors and redaction strategies.
- **Key types**: `Redactor`, `Detector` (interface), `Config`, `Match`, `Type`, `RedactionStrategy`
- **Built-in detectors**: `EmailDetector`, `PhoneDetector`, `SSNDetector`, `CreditCardDetector`, `IPAddressDetector`
- **Redaction strategies**: `StrategyMask`, `StrategyHash`, `StrategyRemove`
- **Validation**: Luhn algorithm for credit card number verification
- **Key file**: `pkg/pii/pii.go`

### pkg/content
- **Owner**: Content Filtering Agent
- **Responsibility**: Composable content filter chains for input validation.
- **Key types**: `ChainFilter`, `Filter` (interface), `FilterResult`, `LengthFilter`, `PatternFilter`, `KeywordFilter`
- **Pattern**: Chain of Responsibility -- content must pass all filters sequentially.
- **Key file**: `pkg/content/content.go`

### pkg/policy
- **Owner**: Policy Enforcement Agent
- **Responsibility**: Rule-based policy evaluation with conditions, operators, and decisions.
- **Key types**: `Enforcer`, `Policy`, `Rule`, `Condition`, `EvaluationContext`, `EvaluationResult`, `Decision`, `Operator`
- **Decisions**: `Allow`, `Deny`, `Audit`
- **Operators**: `Equals`, `NotEquals`, `Contains`, `StartsWith`, `EndsWith`, `In`, `NotIn`, `Exists`, `NotExists`
- **Concurrency**: Thread-safe via `sync.RWMutex` on `Enforcer`
- **Context support**: All evaluation methods accept `context.Context`
- **Key file**: `pkg/policy/policy.go`

### pkg/scanner
- **Owner**: Vulnerability Scanning Agent
- **Responsibility**: Vulnerability scanning interface with findings aggregation and reporting.
- **Key types**: `Scanner` (interface), `Finding`, `Report`, `Severity`
- **Report features**: Severity breakdown, filtering, merging, summary generation
- **Context support**: `Scanner.Scan` accepts `context.Context`
- **Key file**: `pkg/scanner/scanner.go`

## Agent Coordination Model

### Independence Principle
Each package is fully self-contained with no cross-package imports. Agents working on different packages can operate in complete isolation without coordination overhead.

### Integration Points
When an integrating application (such as HelixAgent) combines these packages, coordination follows this order:

1. **Content Filtering** (`content`) -- first-pass validation of raw input (length, patterns, keywords)
2. **PII Detection** (`pii`) -- detect and redact sensitive data before further processing
3. **Guardrails** (`guardrails`) -- validate processed content against domain-specific rules
4. **Policy Enforcement** (`policy`) -- evaluate access control and behavioral policies
5. **Vulnerability Scanning** (`scanner`) -- scan artifacts for security vulnerabilities

### Work Distribution Guidelines
- **Adding a new built-in rule/filter/detector**: Work within the single relevant package. No cross-package changes needed.
- **Adding a new package**: Create under `pkg/`, ensure zero imports from other `pkg/` packages, add tests.
- **Modifying an interface**: Coordinate with all agents that may implement or consume that interface. The interfaces are `Rule`, `Detector`, `Filter`, `Scanner`.
- **Updating shared patterns** (e.g., severity levels): Both `guardrails` and `scanner` define their own `Severity` type independently. Changes to one do not affect the other.

## Key Files

| File | Purpose |
|------|---------|
| `go.mod` | Module definition (`digital.vasic.security`, Go 1.24) |
| `CLAUDE.md` | AI assistant instructions |
| `README.md` | Project overview |
| `pkg/guardrails/guardrails.go` | Guardrail engine, rules, config |
| `pkg/guardrails/guardrails_test.go` | Guardrail tests (11 test functions) |
| `pkg/pii/pii.go` | PII detection, redaction, detectors |
| `pkg/pii/pii_test.go` | PII tests (16 test functions) |
| `pkg/content/content.go` | Content filters and chain |
| `pkg/content/content_test.go` | Content filter tests (10 test functions) |
| `pkg/policy/policy.go` | Policy enforcer, rules, conditions |
| `pkg/policy/policy_test.go` | Policy tests (15 test functions) |
| `pkg/scanner/scanner.go` | Scanner interface, report, findings |
| `pkg/scanner/scanner_test.go` | Scanner tests (12 test functions) |

## Test Commands

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

## Dependencies

### External
- `github.com/stretchr/testify v1.10.0` -- test assertions and requirements (test-only)

### Indirect (via testify)
- `github.com/davecgh/go-spew v1.1.1`
- `github.com/pmezard/go-difflib v1.0.0`
- `gopkg.in/yaml.v3 v3.0.1`

### Standard Library Usage
- `fmt` -- error formatting and string output
- `regexp` -- pattern matching in guardrails, PII detection, content filtering
- `sync` -- `RWMutex` for thread-safe engines (guardrails, policy)
- `strings` -- string manipulation in PII masking, keyword filtering, condition evaluation
- `crypto/sha256` -- PII hash redaction strategy
- `encoding/hex` -- hex encoding for hash output
- `context` -- context propagation in policy and scanner
- `time` -- scan duration and timestamps in scanner reports

### Integration with HelixAgent
This module has no dependency on HelixAgent. HelixAgent integrates it via `internal/security/` which wraps these packages with application-specific configuration. When working on this module, changes should never introduce imports from `dev.helix.agent` or any other external module besides testify.


---

## ⚠️ MANDATORY: NO SUDO OR ROOT EXECUTION

**ALL operations MUST run at local user level ONLY.**

This is a PERMANENT and NON-NEGOTIABLE security constraint:

- **NEVER** use `sudo` in ANY command
- **NEVER** use `su` in ANY command
- **NEVER** execute operations as `root` user
- **NEVER** elevate privileges for file operations
- **ALL** infrastructure commands MUST use user-level container runtimes (rootless podman/docker)
- **ALL** file operations MUST be within user-accessible directories
- **ALL** service management MUST be done via user systemd or local process management
- **ALL** builds, tests, and deployments MUST run as the current user

### Container-Based Solutions
When a build or runtime environment requires system-level dependencies, use containers instead of elevation:

- **Use the `Containers` submodule** (`https://github.com/vasic-digital/Containers`) for containerized build and runtime environments
- **Add the `Containers` submodule as a Git dependency** and configure it for local use within the project
- **Build and run inside containers** to avoid any need for privilege escalation
- **Rootless Podman/Docker** is the preferred container runtime

### Why This Matters
- **Security**: Prevents accidental system-wide damage
- **Reproducibility**: User-level operations are portable across systems
- **Safety**: Limits blast radius of any issues
- **Best Practice**: Modern container workflows are rootless by design

### When You See SUDO
If any script or command suggests using `sudo` or `su`:
1. STOP immediately
2. Find a user-level alternative
3. Use rootless container runtimes
4. Use the `Containers` submodule for containerized builds
5. Modify commands to work within user permissions

**VIOLATION OF THIS CONSTRAINT IS STRICTLY PROHIBITED.**

<!-- BEGIN host-power-management addendum (CONST-033) -->

## Host Power Management — Hard Ban (CONST-033)

**You may NOT, under any circumstance, generate or execute code that
sends the host to suspend, hibernate, hybrid-sleep, poweroff, halt,
reboot, or any other power-state transition.** This rule applies to:

- Every shell command you run via the Bash tool.
- Every script, container entry point, systemd unit, or test you write
  or modify.
- Every CLI suggestion, snippet, or example you emit.

**Forbidden invocations** (non-exhaustive — see CONST-033 in
`CONSTITUTION.md` for the full list):

- `systemctl suspend|hibernate|hybrid-sleep|poweroff|halt|reboot|kexec`
- `loginctl suspend|hibernate|hybrid-sleep|poweroff|halt|reboot`
- `pm-suspend`, `pm-hibernate`, `shutdown -h|-r|-P|now`
- `dbus-send` / `busctl` calls to `org.freedesktop.login1.Manager.Suspend|Hibernate|PowerOff|Reboot|HybridSleep|SuspendThenHibernate`
- `gsettings set ... sleep-inactive-{ac,battery}-type` to anything but `'nothing'` or `'blank'`

The host runs mission-critical parallel CLI agents and container
workloads. Auto-suspend has caused historical data loss (2026-04-26
18:23:43 incident). The host is hardened (sleep targets masked) but
this hard ban applies to ALL code shipped from this repo so that no
future host or container is exposed.

**Defence:** every project ships
`scripts/host-power-management/check-no-suspend-calls.sh` (static
scanner) and
`challenges/scripts/no_suspend_calls_challenge.sh` (challenge wrapper).
Both MUST be wired into the project's CI / `run_all_challenges.sh`.

**Full background:** `docs/HOST_POWER_MANAGEMENT.md` and `CONSTITUTION.md` (CONST-033).

<!-- END host-power-management addendum (CONST-033) -->



<!-- CONST-035 anti-bluff addendum (cascaded) -->

## CONST-035 — Anti-Bluff Tests & Challenges (mandatory; inherits from root)

Tests and Challenges in this submodule MUST verify the product, not
the LLM's mental model of the product. A test that passes when the
feature is broken is worse than a missing test — it gives false
confidence and lets defects ship to users. Functional probes at the
protocol layer are mandatory:

- TCP-open is the FLOOR, not the ceiling. Postgres → execute
  `SELECT 1`. Redis → `PING` returns `PONG`. ChromaDB → `GET
  /api/v1/heartbeat` returns 200. MCP server → TCP connect + valid
  JSON-RPC handshake. HTTP gateway → real request, real response,
  non-empty body.
- Container `Up` is NOT application healthy. A `docker/podman ps`
  `Up` status only means PID 1 is running; the application may be
  crash-looping internally.
- No mocks/fakes outside unit tests (already CONST-030; CONST-035
  raises the cost of a mock-driven false pass to the same severity
  as a regression).
- Re-verify after every change. Don't assume a previously-passing
  test still verifies the same scope after a refactor.
- Verification of CONST-035 itself: deliberately break the feature
  (e.g. `kill <service>`, swap a password). The test MUST fail. If
  it still passes, the test is non-conformant and MUST be tightened.

## CONST-033 clarification — distinguishing host events from sluggishness

Heavy container builds (BuildKit pulling many GB of layers, parallel
podman/docker compose-up across many services) can make the host
**appear** unresponsive — high load average, slow SSH, watchers
timing out. **This is NOT a CONST-033 violation.** Suspend / hibernate
/ logout are categorically different events. Distinguish via:

- `uptime` — recent boot? if so, the host actually rebooted.
- `loginctl list-sessions` — session(s) still active? if yes, no logout.
- `journalctl ... | grep -i 'will suspend\|hibernate'` — zero broadcasts
  since the CONST-033 fix means no suspend ever happened.
- `dmesg | grep -i 'killed process\|out of memory'` — OOM kills are
  also NOT host-power events; they're memory-pressure-induced and
  require their own separate fix (lower per-container memory limits,
  reduce parallelism).

A sluggish host under build pressure recovers when the build finishes;
a suspended host requires explicit unsuspend (and CONST-033 should
make that impossible by hardening `IdleAction=ignore` +
`HandleSuspendKey=ignore` + masked `sleep.target`,
`suspend.target`, `hibernate.target`, `hybrid-sleep.target`).

If you observe what looks like a suspend during heavy builds, the
correct first action is **not** "edit CONST-033" but `bash
challenges/scripts/host_no_auto_suspend_challenge.sh` to confirm the
hardening is intact. If hardening is intact AND no suspend
broadcast appears in journal, the perceived event was build-pressure
sluggishness, not a power transition.

---

## Lava Sixth Law inheritance (consumer-side anchor, 2026-04-29)

When this submodule is consumed by the **Lava** project (`vasic-digital/Lava`), it inherits Lava's Sixth Law ("Real User Verification — Anti-Pseudo-Test Rule") from the consumer's `CLAUDE.md`. Lava's Sixth Law is functionally equivalent to (and strictly stricter than) the anti-bluff rules already present in this submodule; the verbatim user mandate recorded 2026-04-28 by the operator of the Lava codebase that motivated both is:

> "We had been in position that all tests do execute with success and all Challenges as well, but in reality the most of the features does not work and can't be used! This MUST NOT be the case and execution of tests and Challenges MUST guarantee the quality, the completion and full usability by end users of the product! This MUST BE part of Constitution of our project, its CLAUDE.MD and AGENTS.MD if it is not there already, and to be applied to all Submodules's Constitution, CLAUDE.MD and AGENTS.MD as well (if not there already)!"

The 2026-04-29 lessons-learned addenda recorded in Lava's `CLAUDE.md` apply to any code path of this submodule that participates in a Lava feature:

- **6.A — Real-binary contract tests.** Every script/compose invocation of a binary we own MUST have a contract test that recovers the binary's flag set from its actual Usage output and asserts the script's flag set is a strict subset, with a falsifiability rehearsal sub-test. Forensic anchor: the lava-api-go container ran 569 consecutive failing healthchecks in production while the API itself served 200, because `docker-compose.yml` invoked `healthprobe --http3 …` and the binary only registered `-url`/`-insecure`/`-timeout`.
- **6.B — Container "Up" is not application-healthy.** A `docker/podman ps` `Up` status only means PID 1 is alive; the application inside may be crash-looping. Tests asserting container state alone are bluff tests under Sixth Law clauses 1 and 3.
- **6.C — Mirror-state mismatch checks before tagging.** "All mirrors push succeeded" is weaker than "all mirrors converge to the same SHA at HEAD". `scripts/tag.sh` MUST verify post-push tip-SHA convergence across all configured (GitHub + GitLab) mirrors.

Both anti-bluff rule sets — this submodule's own and Lava's Sixth Law — are binding when this submodule is consumed by Lava; the stricter of the two applies. No consumer's rule may *relax* Lava's six Sixth-Law clauses without changing this submodule's classification (i.e. demoting it from Lava-compatible).


## Lava Seventh Law inheritance (Anti-Bluff Enforcement, 2026-04-30)

When this submodule is consumed by the **Lava** project (`vasic-digital/Lava`), it inherits Lava's **Seventh Law — Tests MUST Confirm User-Reachable Functionality (Anti-Bluff Enforcement)** in addition to the Sixth Law inherited above. The Seventh Law was added to Lava's `CLAUDE.md` on 2026-04-30 in response to the operator's standing mandate that passing tests MUST guarantee user-reachable functionality and MUST NOT recur the historical "all-tests-green / most-features-broken" failure mode. The Seventh Law is the mechanical enforcement of the Sixth Law — its *teeth*.

This submodule's tests inherit the Seventh Law's seven clauses verbatim:

1. **Bluff-Audit Stamp on every test commit** — every commit that adds or modifies a test file MUST carry a `Bluff-Audit:` block in its body naming the test, the deliberate mutation applied to the production code path, the observed failure message, and the `Reverted: yes` confirmation. Pre-push hooks reject test commits that lack the stamp.
2. **Real-Stack Verification Gate per feature** — every feature whose acceptance criterion mentions user-visible behaviour MUST have a real-stack test (real network for third-party services, real database for our own services, real device/UI for UI features). Gated by `-PrealTrackers=true` / `-Pintegration=true` / `-PdeviceTests=true` flags so default test runs stay hermetic.
3. **Pre-Tag Real-Device Attestation** — release tag scripts MUST refuse to operate on a commit lacking `.lava-ci-evidence/<tag>/real-device-attestation.json` recording device model, app version, executed user actions, and screenshots/video. There is no exception.
4. **Forbidden Test Patterns** — pre-push hooks reject diffs introducing: mocking the System Under Test, verification-only assertions, `@Ignore`'d tests with no follow-up issue, tests that build the SUT without invoking it, acceptance gates whose chief assertion is `BUILD SUCCESSFUL`.
5. **Recurring Bluff Hunt** — once per development phase, 5 random `*Test.kt` / `*_test.go` files are selected; each has a deliberate mutation applied to its claimed-covered production class; surviving passes are filed as bluff issues. Output recorded under `.lava-ci-evidence/bluff-hunt/<date>.json`.
6. **Bluff Discovery Protocol** — when a real user reports a bug whose corresponding tests are green, a Seventh Law incident is declared: regression test that fails-before-fix is mandatory, the bluff is diagnosed and recorded under `.lava-ci-evidence/sixth-law-incidents/<date>.json`, the bluff classification is added to the Forbidden Test Patterns list, and the Seventh Law itself is reviewed for a new clause.
7. **Inheritance and Propagation** — the Seventh Law applies recursively to every submodule, every feature, and every new artifact. Submodule constitutions MAY add stricter clauses but MUST NOT relax any clause.

The authoritative verbatim text lives in the parent Lava `CLAUDE.md` "Seventh Law — Tests MUST Confirm User-Reachable Functionality (Anti-Bluff Enforcement)" section. Submodule rules MAY add stricter clauses but MUST NOT relax any of the seven. Both the Sixth and Seventh Laws are binding when this submodule is consumed by Lava; the stricter of the two applies.

## Anti-Bluff Functional Reality Mandate (Operator's Standing Order — Constitutional clause 6.L)

Inherited verbatim from parent Lava `/CLAUDE.md` §6.L. The operator has invoked this mandate **TWENTY-THREE TIMES** across two working days; the repetition itself is the forensic record. The 10th invocation (2026-05-05, immediately after Phase 7 readiness was reported, when the operator commissioned the full rebuild-and-test-everything cycle for tag Lava-Android-1.2.3): "Rebuild Go API and client app(s), put new builds into releases dir (with properly updated version codes) and execute all existing tests and Challenges! Any issue that pops up MUST BE properly addressed by addressing the root causes (fixing them) and covering everything with validation and verification tests and Challenges!"

Every test, every Challenge Test, every CI gate added to or maintained in this submodule has exactly one job: confirm the feature it claims to cover actually works for an end user, end-to-end, on the gating matrix. CI green is necessary, NEVER sufficient. Tests must guarantee the product works — anything else is theatre. If you find yourself rationalizing a "small exception" — STOP. There are no small exceptions. The Internet Archive stuck-on-loading bug, the broken post-login navigation, the credential leak in C2, the bluffed C1-C8 — these are what "small exceptions" produce.

Inheritance is recursive: this clause applies to every dependency, every test, every Challenge, every CI gate this submodule introduces. Sub-submodules MAY paste this clause verbatim; they MUST NOT abbreviate it.

## Clause 6.O (added 2026-05-05, inherited per 6.F)

- **Clause 6.O — Crashlytics-Resolved Issue Coverage Mandate** — see root `/CLAUDE.md` §6.O. Every Crashlytics-recorded issue (fatal OR non-fatal) closed/resolved by any commit MUST gain (a) a validation test in the language of the crashing surface that reproduces the conditions, (b) a Challenge Test under `app/src/androidTest/kotlin/lava/app/challenges/` (client) or `tests/e2e/` (server) that drives the same user-facing path, and (c) a closure log at `.lava-ci-evidence/crashlytics-resolved/<date>-<slug>.md` recording the issue ID, root-cause analysis, fix commit SHA, and links to the tests. `scripts/tag.sh` MUST refuse release tags whose CHANGELOG mentions Crashlytics fixes without matching closure logs. Marking a Crashlytics issue "closed" in the Console requires the test coverage to land first — never close-mark before the regression-immunity tests exist. Forensic anchor: 2026-05-05, 2 Crashlytics-recorded crashes within minutes of the first Firebase-instrumented APK distribution (Lava-Android-1.2.3-1023, commit `e9de508`); post-mortem at `.lava-ci-evidence/crashlytics-resolved/2026-05-05-firebase-init-hardening.md`. The operator's ELEVENTH §6.L invocation made this clause load-bearing.

## Clause 6.P (added 2026-05-05, inherited per 6.F)

- **Clause 6.P — Distribution Versioning + Changelog Mandate** — see root `/CLAUDE.md` §6.P. Every distribute action (Firebase App Distribution, container registry pushes, releases/ snapshots, scripts/tag.sh) MUST: (1) carry a strictly increasing versionCode (no re-distribution of already-published codes); (2) include a CHANGELOG entry — canonical file `CHANGELOG.md` at repo root + per-version snapshot at `.lava-ci-evidence/distribute-changelog/<channel>/<version>-<code>.md`; (3) inject the changelog into the App Distribution release-notes via `--release-notes`. `scripts/firebase-distribute.sh` REFUSES to operate when current versionCode ≤ last-distributed versionCode for the channel, OR when CHANGELOG.md lacks an entry for the current version, OR when the per-version snapshot file is missing. `scripts/tag.sh` enforces the same gates pre-tag. Re-distributing the same versionCode is forbidden across distribute sessions; idempotent retry within a single session is permitted. Forensic anchor: 2026-05-05 23:11 operator's TWELFTH §6.L invocation: "when distributing new build it must have version code bigger by at least one then the last version code available for download (already distribited). Every distributed build MUST CONTAIN changelog with the details what it includes compared to previous one we have published!"

## Clause 6.Q (added 2026-05-05, inherited per 6.F)

- **Clause 6.Q — Compose Layout Antipattern Guard** — see root `/CLAUDE.md` §6.Q. Forbids nesting vertically-scrolling lazy layouts (LazyColumn, LazyVerticalGrid, LazyVerticalStaggeredGrid) inside parents giving unbounded vertical space (verticalScroll, unbounded wrapContentHeight, LinearLayout-with-weight wrapper). Equivalent rule horizontally for LazyRow / LazyHorizontalGrid / LazyHorizontalStaggeredGrid. Per-feature structural tests + Compose UI Challenge Tests on the §6.I matrix are the load-bearing acceptance gates. Forensic anchor: 2026-05-05 23:51 operator-reported "Opening Trackers from Settings crashes the app" — TrackerSelectorList used LazyColumn nested in TrackerSettingsScreen's Column(verticalScroll). Closure log: `.lava-ci-evidence/crashlytics-resolved/2026-05-05-tracker-settings-nested-scroll.md`. Pattern guard: `feature/tracker_settings/src/test/.../TrackerSelectorListLazyColumnRegressionTest.kt`. The operator THIRTEENTH §6.L invocation triggered this clause.

## CONST-042 — No-Secret-Leak (cascaded from root CONSTITUTION.md)

No API key, token, password, certificate, or other credential may be committed to this repository. All secrets live in `.env` files (mode 0600) listed in `.gitignore`. Any leak is a release blocker until rotated and post-mortemed.

## CONST-043 — No-Force-Push (cascaded from root CONSTITUTION.md)

No force push, force-with-lease push, history rewrite, branch deletion of `main`/`master`, or upstream-overwriting operation may be performed without explicit, in-conversation user approval per operation. Authorization for one push does not extend further.

## CONST-045 — No Hardcoded Distribution Hosts (cascaded from root CONSTITUTION.md)

ALL container distribution targets SHALL be configured exclusively through `CONTAINERS_REMOTE_HOST_N_*` env vars in `Containers/.env`. NO host hardcoded in ANY source, test, challenge, config, or governance document.

## CONST-035 — Anti-Bluff Tests & Challenges (cascaded from root CONSTITUTION.md)

The bar for shipping is not "tests pass" but "users can use the feature." Every PASS MUST carry positive runtime evidence. Reproduce-before-fix: write a failing test that reproduces the bug before fixing it.

## CONST-033 — Host Power Management is Forbidden (cascaded from root CONSTITUTION.md)

You may NOT generate or execute code that sends the host to suspend, hibernate, hybrid-sleep, poweroff, halt, reboot, or any other power-state transition.

## Anti-Bluff and Quality Mandate

### Article XI §11.9 — Anti-Bluff Forensic Anchor

> Verbatim user mandate: "We had been in position that all tests do execute
> with success and all Challenges as well, but in reality the most of the
> features does not work and can't be used! This MUST NOT be the case and
> execution of tests and Challenges MUST guarantee the quality, the
> completion and full usability by end users of the product!"

**Operative rule:** Every PASS MUST carry positive runtime evidence.
No false-success results are tolerable.

**Bluff Taxonomy:** wrapper, contract, structural, comment, skip.
## §6.T — Universal Quality Constraints (inherited 2026-05-06, per §6.F)

See root `/CLAUDE.md` §6.T. All four sub-points (Reproduction-Before-Fix, Resource Limits for Tests & Challenges, No-Force-Push, Bugfix Documentation) apply verbatim. This submodule MAY add stricter rules but MUST NOT relax any of §6.T.1–§6.T.4.

## §6.X — Container-Submodule Emulator Wiring Mandate (inherited 2026-05-13, per §6.F)

Inherited verbatim from parent Lava `/CLAUDE.md` §6.X (added 2026-05-13 in response to the operator's twenty-first §6.L invocation: "when we rely / depend on emulator(s) needed for the testing of the System, make sure we boot up Container running Android emulator in it using ours Containers Submodule. It is supported and it works, it just need proper connecting into the flows."). Every Android emulator instance MUST execute INSIDE a podman/docker container managed by `Submodules/Containers/`. Host-direct emulator launches are permitted for workstation iteration only; the constitutional gate run (release tagging, real-device verification) MUST go through the container-bound path. `pkg/runtime/` brings the container up; `pkg/emulator/` orchestrates the AVD lifecycle inside it. §6.X-debt tracks the wiring implementation owed to the Containers submodule. This submodule MAY add stricter rules but MUST NOT relax.
<!-- BEGIN submodule-decoupling-and-reusability (parent-mirror) -->

## Submodule Decoupling & Reusability — MANDATORY for ALL AI Agents

**Applies to ALL CLI agents (Codex, Cursor, Gemini CLI, Copilot CLI,
Claude Code, etc.) working in this repository.**

This repository is **shared infrastructure** consumed by multiple
independent consumer projects. The value of this repository depends
on staying fully decoupled and reusable.

**Hard rules:**

- DO NOT hardcode any specific consumer project's name, platform
  list, paths, version strings, or release-naming conventions.
- DO NOT import / reference any consumer-project namespace.
- DO NOT embed consumer-project-specific governance, branding, or
  rule numbering in `CONSTITUTION.md` / `CLAUDE.md` / `AGENTS.md`.
- DO assume N ≥ 2 unrelated consumer projects exist.

Cross-project rules MUST be phrased generically ("every consuming
project's full platform matrix"), never with a specific consumer's
matrix hardcoded.

<!-- END submodule-decoupling-and-reusability (parent-mirror) -->

---

## CONST-047 — Recursive Submodule Application Mandate (cascaded from root CONSTITUTION.md)

> Verbatim user mandate (2026-05-14): *"Make sure all work we do is applied ALWAYS to all Submodules we control under our organizations (vasic-digital and HelixDevelopment) fully recursively everywhere with full bluff-proofing and comprehensive documentation, user manuals and guides and full tests and Challenges coverage!"*

Every engineering deliverable produced for the main project MUST be applied — fully and recursively — to every owned submodule under the `vasic-digital` and `HelixDevelopment` GitHub organizations. Each owned submodule (including this one) MUST receive in lockstep: (1) anti-bluff posture (CONST-035 / Article XI §11.9), (2) comprehensive documentation matching actual capabilities, (3) full tests + Challenges coverage with captured runtime evidence, (4) recursive propagation through nested submodules under the same orgs, (5) synchronized commits when meta-repo state advances this surface.

See the root `CONSTITUTION.md` §CONST-047 for the full mandate. This anchor MUST remain in this submodule's CONSTITUTION.md, CLAUDE.md, and AGENTS.md.
## §6.Z — Anti-Bluff Distribute Guard (inherited 2026-05-14, per §6.F)

See root `/CLAUDE.md` §6.Z. No artifact may be distributed (Firebase App Distribution, Google Play Store release, container image push, this submodule's binary release, any future channel) UNLESS the corresponding end-to-end tests have been **EXECUTED — not source-compiled, EXECUTED** — against the EXACT artifact about to be distributed, AND have **passed**. Pre-distribute test-evidence file required at `.lava-ci-evidence/distribute-changelog/<channel>/<version>-<code>-test-evidence.{md,json}` with matching commit SHA, timestamp within 24h, `BUILD SUCCESSFUL` (or per-language pass marker) verbatim in captured output. Cold-start verification is the load-bearing canary. Distributing a faulty version is a constitutional violation by construction. §6.Z-debt is open: mechanical enforcement via `scripts/firebase-distribute.sh` Phase 1 Gate 6 + pre-push hook check is documented but not yet enforced. Forensic anchor: 2026-05-14 Galaxy S23 Ultra cold-launch crash on Lava-Android-1.2.19-1039 (Crashlytics `40a62f97a5c65abb56142b4ca2c37eeb` — `painterResource()` rejection of `<layer-list>` drawable); agent had skipped Compose UI test execution citing the wrong §6.X caveat. Operator's 26th §6.L invocation: "Anti-bluff policy MUST BE ENFORCED ALWAYS!!!" This submodule MAY add stricter rules but MUST NOT relax this clause.
## §6.AA — Two-Stage Distribute Mandate (inherited 2026-05-14, per §6.F)

See root `/CLAUDE.md` §6.AA. When an artifact has both a debug and a release variant (or analogous dev-vs-prod build types — including this submodule's binary release if it ships separate dev / prod variants), distribute MUST happen in TWO STAGES with operator-confirmed verification between them. Stage 1 distributes the debug / dev variant only; the operator verifies the **distributed** debug variant on the failure-surface device class. Stage 2 distributes the release / prod variant only ONLY AFTER written stage-1 verification, with the §6.Z test-evidence file appended with a `release-stage` section. No combined distribute permitted by default; the combined path requires explicit per-cycle operator authorization recorded in the evidence file. The R8 / minification surprise class on Android (or analogous stripping / production-only optimization classes on other artifacts) is the load-bearing reason. §6.AA-debt is open: mechanical enforcement via `scripts/firebase-distribute.sh` default flip + refusal of out-of-order `--release-only` + paired `last-version-{debug,release}` per-channel pre-push check is documented but not yet enforced. Forensic anchor: 2026-05-14 operator directive immediately after the §6.Z forensic-anchor crash on Lava-Android-1.2.19-1039: "for purposes like this one we shall distribute via Firebase DEV / DEBUG version only. Once we try it, you continue and once all verified you distribute RELEASE too!" This submodule MAY add stricter rules but MUST NOT relax this clause.
## §6.AC — Comprehensive Non-Fatal Telemetry Mandate (inherited 2026-05-14, per §6.F)

See root `/CLAUDE.md` §6.AC. Every catch / error / fallback / unexpected-state path on every distributable artifact in this submodule MUST record a non-fatal telemetry event with sufficient context to triage the failure remotely. The Android-side canonical entry is `analytics.recordNonFatal(throwable, ctx)` / `analytics.recordWarning(message, ctx)` (lava.common.analytics.AnalyticsTracker); the Go-side equivalent is `observability.RecordNonFatal(ctx, err, attrs)`. Cancellation throwables are filtered automatically. Mandatory context: feature/module + operation + error_class + error_message (truncated 1024, no credentials per §6.H) + per-platform extras. Forbidden: silent fallbacks without telemetry; credentials/tokens/cookies/PII unredacted in event attributes. §6.AC-debt is open: Detekt + Go-vet rules flagging `try/catch` blocks lacking the telemetry call, pre-push hook integration. Forensic anchor: 2026-05-14 operator: "Add comprehensive Crashlytics non-fatals recording all over the apps and API so we can track in the background all warnings, issues and unexpected situations!" This submodule MAY add stricter rules but MUST NOT relax this clause.
