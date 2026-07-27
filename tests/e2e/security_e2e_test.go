package e2e

// BLUFF-VIOLATION: R-12 — This E2E test uses testScanner mock.
// Mocks are permitted ONLY in Unit tests per Constitution §6 / R-12.
// Remediation: Replace with real security scanner (Trivy, Snyk CLI) in container.
// Tracked in: docs/research/chapters/MVP/05_Response/anti_bluff_audit_2026-05-02.md

import (
	"context"
	"testing"
	"time"

	"digital.vasic.security/pkg/content"
	"digital.vasic.security/pkg/guardrails"
	"digital.vasic.security/pkg/pii"
	"digital.vasic.security/pkg/policy"
	"digital.vasic.security/pkg/scanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFullSecurityPipeline_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode") // SKIP-OK: #short-mode
	}

	// Step 1: Content filtering — reject dangerous inputs
	keywordFilter := content.NewKeywordFilter(
		[]string{"drop table", "rm -rf"}, false,
	)
	patternFilter, err := content.NewPatternFilter(map[string]string{
		"html_injection": `<script[^>]*>.*</script>`,
	})
	require.NoError(t, err)
	chain := content.NewChainFilter(
		content.NewLengthFilter(1, 50000),
		keywordFilter,
		patternFilter,
	)

	// Step 2: PII redaction
	redactor := pii.NewRedactor(&pii.Config{
		EnabledDetectors:  []pii.Type{pii.TypeEmail, pii.TypePhone, pii.TypeSSN},
		RedactionStrategy: pii.StrategyMask,
		MaskChar:          '*',
	})

	// Step 3: Guardrails
	grCfg := guardrails.DefaultConfig()
	grEngine := guardrails.NewEngine(grCfg)
	grEngine.AddRule(guardrails.NewMaxLengthRule(50000))

	// Step 4: Policy enforcement
	enforcer := policy.NewEnforcer()
	err = enforcer.LoadPolicy(&policy.Policy{
		Name: "data-access",
		Rules: []policy.Rule{
			{
				Name: "allow-internal",
				Conditions: []policy.Condition{
					{Field: "source", Operator: policy.OperatorEquals, Value: "internal"},
				},
				Decision: policy.DecisionAllow,
			},
			{
				Name: "audit-external",
				Conditions: []policy.Condition{
					{Field: "source", Operator: policy.OperatorEquals, Value: "external"},
				},
				Decision: policy.DecisionAudit,
			},
		},
		DefaultDecision: policy.DecisionDeny,
	})
	require.NoError(t, err)

	// Simulate incoming user input through the full pipeline
	userInput := "Please contact support@company.com or call 555-123-4567. " +
		"My SSN is 987-65-4321."

	// Filter content
	filterResult, err := chain.Check(userInput)
	require.NoError(t, err)
	assert.True(t, filterResult.Allowed, "normal user input should pass content filter")

	// Redact PII
	redacted, matches := redactor.Redact(userInput)
	assert.True(t, len(matches) >= 3, "should detect email, phone, and SSN")
	assert.NotContains(t, redacted, "support@company.com")
	assert.NotContains(t, redacted, "987-65-4321")

	// Run guardrails on redacted content
	grResult := grEngine.Check(redacted)
	assert.True(t, grResult.Passed, "redacted content should pass guardrails")

	// Enforce policy for internal source
	evalResult, err := enforcer.Evaluate(context.Background(), "data-access",
		&policy.EvaluationContext{Fields: map[string]string{"source": "internal"}})
	require.NoError(t, err)
	assert.Equal(t, policy.DecisionAllow, evalResult.Decision)
}

func TestDangerousInputBlocked_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode") // SKIP-OK: #short-mode
	}

	chain := content.NewChainFilter(
		content.NewLengthFilter(1, 10000),
		content.NewKeywordFilter([]string{"drop table"}, false),
	)

	dangerousInputs := []string{
		"Please DROP TABLE users;",
		"Run: drop table accounts; --",
	}

	for _, input := range dangerousInputs {
		result, err := chain.Check(input)
		require.NoError(t, err)
		assert.False(t, result.Allowed,
			"dangerous input should be blocked: %s", input)
	}
}

func TestRedactionStrategies_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode") // SKIP-OK: #short-mode
	}

	input := "Email me at alice@example.org about the issue."

	strategies := []pii.RedactionStrategy{
		pii.StrategyMask,
		pii.StrategyHash,
		pii.StrategyRemove,
	}

	for _, strategy := range strategies {
		redactor := pii.NewRedactor(&pii.Config{
			EnabledDetectors:  []pii.Type{pii.TypeEmail},
			RedactionStrategy: strategy,
			MaskChar:          '*',
		})
		redacted, matches := redactor.Redact(input)
		assert.True(t, len(matches) > 0, "should find email for strategy %s", strategy)
		assert.NotContains(t, redacted, "alice@example.org",
			"original email should be removed for strategy %s", strategy)
	}
}

func TestScannerEndToEndWorkflow_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode") // SKIP-OK: #short-mode
	}

	// Create a mock scanner that implements the Scanner interface
	mockScanner := &testScanner{
		findings: []scanner.Finding{
			{
				Severity:    scanner.SeverityHigh,
				Title:       "Hardcoded credentials",
				Description: "API key found in source code",
				Location:    "config.go:15",
				Remediation: "Use environment variables",
			},
			{
				Severity:    scanner.SeverityMedium,
				Title:       "Missing input validation",
				Description: "User input not sanitized",
				Location:    "handler.go:42",
			},
		},
	}

	report, err := scanner.RunScanner(
		context.Background(), mockScanner, "test-scanner", "/app",
	)
	require.NoError(t, err)
	assert.Equal(t, 2, report.TotalCount)
	assert.True(t, report.HasHighOrAbove())
	assert.False(t, report.HasCritical())
	assert.Contains(t, report.Summary(), "2 findings")
}

func TestGuardrailsStopOnFirstFailure_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode") // SKIP-OK: #short-mode
	}

	cfg := &guardrails.Config{
		Rules: map[string]guardrails.RuleConfig{
			"max_length": {Enabled: true, Severity: guardrails.SeverityCritical},
		},
		StopOnFirstFailure: true,
	}
	engine := guardrails.NewEngine(cfg)
	engine.AddRule(guardrails.NewMaxLengthRule(5))

	formatRule, err := guardrails.NewRequireFormatRule("json", `^\{.*\}$`)
	require.NoError(t, err)
	engine.AddRule(formatRule)

	// Input exceeds max length, should stop after first failure
	result := engine.Check("this is too long")
	assert.False(t, result.Passed)
	assert.Equal(t, 1, len(result.Results),
		"should stop after first failure")
}

func TestPolicyOperators_E2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode") // SKIP-OK: #short-mode
	}

	enforcer := policy.NewEnforcer()
	err := enforcer.LoadPolicy(&policy.Policy{
		Name: "operator-tests",
		Rules: []policy.Rule{
			{
				Name: "in-list",
				Conditions: []policy.Condition{
					{
						Field:    "region",
						Operator: policy.OperatorIn,
						Values:   []string{"us-east-1", "eu-west-1"},
					},
				},
				Decision: policy.DecisionAllow,
			},
			{
				Name: "starts-with-admin",
				Conditions: []policy.Condition{
					{
						Field:    "path",
						Operator: policy.OperatorStartsWith,
						Value:    "/admin",
					},
				},
				Decision: policy.DecisionDeny,
			},
		},
		DefaultDecision: policy.DecisionAudit,
	})
	require.NoError(t, err)

	// Region in allowed list
	result, err := enforcer.Evaluate(context.Background(), "operator-tests",
		&policy.EvaluationContext{Fields: map[string]string{
			"region": "us-east-1",
			"path":   "/api/data",
		}})
	require.NoError(t, err)
	assert.Equal(t, policy.DecisionAllow, result.Decision)

	// Path starts with /admin
	result, err = enforcer.Evaluate(context.Background(), "operator-tests",
		&policy.EvaluationContext{Fields: map[string]string{
			"region": "ap-south-1",
			"path":   "/admin/users",
		}})
	require.NoError(t, err)
	assert.Equal(t, policy.DecisionDeny, result.Decision)

	// Nothing matches — default audit
	result, err = enforcer.Evaluate(context.Background(), "operator-tests",
		&policy.EvaluationContext{Fields: map[string]string{
			"region": "ap-south-1",
			"path":   "/api/data",
		}})
	require.NoError(t, err)
	assert.Equal(t, policy.DecisionAudit, result.Decision)
}

// testScanner implements scanner.Scanner for testing.
type testScanner struct {
	findings []scanner.Finding
}

func (s *testScanner) Scan(
	_ context.Context, _ string,
) ([]scanner.Finding, error) {
	time.Sleep(5 * time.Millisecond) // simulate scan work
	return s.findings, nil
}
