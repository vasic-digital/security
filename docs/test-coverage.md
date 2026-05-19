# Test Coverage Ledger — Security submodule

**Revision:** 1 — round-300 introduction (2026-05-19)
**Last modified:** 2026-05-19
**Maintainer:** vasic-digital/Security

Per CONST-048 (full-automation-coverage) and CONST-050 (100% test-type coverage), this ledger maps every exported symbol of the `digital.vasic.security` module to the test that exercises it AND to the Challenge that proves end-user reachability.

Symbols without a test → CONST-048 invariant (1) violation; tests without a paired mutation → CONST-050(B) violation; Challenges without exit-0/exit-non-zero polarity → §1.1 violation.

## pkg/guardrails — Content guardrail engine

| Symbol | Unit test | Edge test | Challenge | Mutation surface |
|---|---|---|---|---|
| `NewEngine(*Config)` | `guardrails_test.go::TestEngine_Check_AllPass` | `guardrails_edge_test.go::TestEngine_NilConfig` | `security_functionality_challenge.sh` | drop nil-config guard → panic on `Check()` |
| `Engine.AddRule(Rule)` | `guardrails_test.go::TestEngine_AddRule` | — | `security_functionality_challenge.sh` | no-op AddRule → empty rule slice never executes |
| `Engine.Check(string)` | `guardrails_test.go::TestEngine_Check_Forbidden` | `guardrails_edge_test.go::TestEngine_StopOnFirstFailure` | `security_describe_challenge.sh` | return always-pass Result → mutation flips to FAIL |
| `NewMaxLengthRule(int)` | `guardrails_test.go::TestMaxLengthRule` | — | `security_functionality_challenge.sh` | ignore length → mutation overflow passes silently |
| `NewForbiddenPatternsRule(map)` | `guardrails_test.go::TestForbiddenPatternsRule` | `guardrails_edge_test.go::TestForbiddenPatterns_InvalidRegex` | `security_describe_challenge.sh` | swallow regex compile error → silent pass |
| `NewRequireFormatRule(name,pattern)` | `guardrails_test.go::TestRequireFormatRule` | — | `security_functionality_challenge.sh` | match-anything regex → mutation accepts garbage |

## pkg/pii — PII detection and redaction

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `NewRedactor(*Config)` | `pii_test.go::TestRedactor_AllTypes` | `security_describe_challenge.sh` | return passthrough Redactor → mutation leaks raw PII |
| `Redactor.Redact(string) string` | `pii_test.go::TestRedactor_Strategies` | `security_describe_challenge.sh` | echo input → mutation prints SSN unmasked |
| `Detector.Detect(string) []Match` | `pii_test.go::TestDetector_Email/Phone/SSN/CC/IP` | `security_functionality_challenge.sh` | return nil slice → mutation reports zero PII present |
| `StrategyMask` / `StrategyHash` / `StrategyRemove` | `pii_test.go::TestRedaction_StrategyMatrix` | `security_describe_challenge.sh` | swap StrategyMask → StrategyNoop → mutation leaks |

## pkg/content — Content filter chains

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `NewChainFilter([]Filter)` | `content_test.go::TestChain_Sequence` | `security_functionality_challenge.sh` | iterate but discard verdict → mutation accepts banned content |
| `Chain.Apply(string)` | `content_test.go::TestChain_RejectOnFirst` | `security_describe_challenge.sh` | early return Allow → mutation bypasses subsequent filters |
| `NewLengthFilter` / `NewProfanityFilter` / `NewTokenBudgetFilter` | `content_edge_test.go` | `security_functionality_challenge.sh` | invert threshold comparison → mutation lets oversized through |

## pkg/policy — Policy enforcement

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `NewEnforcer([]Rule)` | `policy_test.go::TestEnforcer_Decide_Allow/Deny` | `security_describe_challenge.sh` | return always-allow Enforcer → mutation grants admin to anonymous |
| `Enforcer.Decide(Request) Decision` | `policy_test.go::TestDecide_RuleOrder` | `security_functionality_challenge.sh` | drop deny-overrides-allow → mutation favors first rule only |
| `Rule.Evaluate(Request)` | `policy_test.go::TestRule_Evaluate` | `security_describe_challenge.sh` | hardcode true → mutation makes every condition match |

## pkg/scanner — Vulnerability scanning interface

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `Scanner.Scan(target) (*Report, error)` | `scanner_test.go::TestScanner_RealRun` | `security_describe_challenge.sh` | return empty Report → mutation reports no findings on known-vuln target |
| `Report.Findings()` / `Severity` | `scanner_test.go::TestReport_FilterSeverity` | `security_functionality_challenge.sh` | collapse all severities to Info → mutation hides Critical |

## pkg/headers — HTTP security headers middleware

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `Middleware(http.Handler) http.Handler` | `headers_test.go::TestMiddleware_AddsAllHeaders` | `security_describe_challenge.sh` | strip middleware → mutation response lacks CSP / HSTS |
| `WithCSP(string)` / `WithHSTS(string)` | `headers_test.go::TestOptions` | `security_functionality_challenge.sh` | accept option but discard → mutation emits default values only |

## pkg/securestorage — AES-256-GCM encrypted file storage

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `NewFileStorage(path, key)` | `securestorage_test.go::TestFileStorage_NewWithKey` | `security_describe_challenge.sh` | accept empty key → mutation seals with null key |
| `FileStorage.Put(k,v)` / `Get(k)` | `securestorage_test.go::TestPutGet_RoundTrip` | `security_describe_challenge.sh` | persist plaintext → mutation IsSecure() FAILs |
| `FileStorage.IsSecure() (bool, error)` | `securestorage_coverage_test.go::TestIsSecure_RoundTripCheck` | `security_describe_challenge.sh` | return true unconditionally → mutation hides plaintext leak |

## pkg/ssrf — SSRF guard

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `Guard.Allow(url) error` | `guard_test.go::TestGuard_RejectsPrivateIPs` | `security_describe_challenge.sh` | always nil → mutation lets 169.254.169.254 metadata-service URL through |
| `Guard.AllowHost(host)` | `guard_test.go::TestGuard_RejectsLocalhost` | `security_functionality_challenge.sh` | hardcode allow-loopback → mutation enables internal pivot |

## pkg/security — Privilege-escalation scanner

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `PrivescScan(ctx) (*Report, error)` | `privesc_scan_test.go::TestPrivescScan_OnHost` | `security_describe_challenge.sh` | return empty Report → mutation misses world-writable root |
| Privileged-container / writable-root / dangerous-caps / host-namespace / SUID checks | `privesc_scan_test.go::TestEachCheck_*` | `security_functionality_challenge.sh` | invert pass-condition → mutation reports clean when world-writable / privileged / SETUID present |

## pkg/i18n — Message bundle (CONST-046)

| Symbol | Unit test | Challenge | Mutation surface |
|---|---|---|---|
| `Translator.Translate(msgID, locale, args)` | `translator_test.go::TestTranslator_Fallback` | `security_describe_challenge.sh` (5-locale fixtures) | always return msgID literal → mutation locale-blind output |
| `NoopTranslator` | `translator_test.go::TestNoop_ReturnsMsgID` | — | (intended noop) |

## Test-type coverage matrix (CONST-050(B))

| Type | Location | Round-300 status |
|---|---|---|
| Unit | `pkg/*/`*`_test.go` | 241 tests, all PASS |
| Edge | `pkg/{content,guardrails}/*_edge_test.go` | PASS |
| Integration | `tests/integration/` | PASS |
| E2E | `tests/e2e/` | PASS |
| Security | `tests/security/` | PASS |
| Stress | `tests/stress/` | PASS |
| Benchmark | `tests/benchmark/` | no benchmarks defined yet (documented gap) |
| Challenges | `challenges/scripts/*.sh` | 11 scripts; round-300 adds `security_describe_challenge.sh` |
| Paired mutation | `security_describe_challenge.sh --mutate` | exit-99 on mutation, exit-0 clean |

## Known gaps (tracked, not bluffed)

1. `tests/benchmark/` is empty — populating with real micro-bench for `pii.Redact` and `securestorage.IsSecure` is owed (CONST-048 invariant (2)).
2. `tests/e2e/` exercises subset of public surface; expanding to HTTP-level e2e through `pkg/headers` middleware against a `httptest.Server` is owed.
3. Real chaos / DDoS coverage is documented in `challenges/scripts/{chaos,ddos,stress,scaling}_*.sh` but not yet wired into the round-300 mutation-paired execution path.

Gaps are recorded here rather than hidden, per CONST-035: a known unbluffed gap is preferable to an invisible bluff.
