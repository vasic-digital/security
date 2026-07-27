package integration

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

func TestGuardrailsWithPIIRedaction_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode") // SKIP-OK: #short-mode
	}

	// Build a guardrail engine that checks content length and forbidden patterns
	cfg := guardrails.DefaultConfig()
	cfg.StopOnFirstFailure = false
	engine := guardrails.NewEngine(cfg)
	engine.AddRule(guardrails.NewMaxLengthRule(5000))

	patterns, err := guardrails.NewForbiddenPatternsRule(map[string]string{
		"script_tag": `<script[^>]*>`,
	})
	require.NoError(t, err)
	engine.AddRule(patterns)

	// First pass the content through PII redaction, then through guardrails
	redactor := pii.NewRedactor(pii.DefaultConfig())

	input := "Contact john.doe@example.com or call 555-123-4567 for details."
	redacted, matches := redactor.Redact(input)

	assert.True(t, len(matches) > 0, "should detect PII in input")
	assert.NotEqual(t, input, redacted, "redacted text should differ from original")

	// Now run the redacted content through guardrails
	result := engine.Check(redacted)
	assert.True(t, result.Passed, "redacted content should pass guardrails")
}

func TestContentFilterWithPolicyEnforcement_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode") // SKIP-OK: #short-mode
	}

	// Set up content filtering chain
	lengthFilter := content.NewLengthFilter(1, 10000)
	keywordFilter := content.NewKeywordFilter(
		[]string{"password", "secret_key"}, false,
	)
	chain := content.NewChainFilter(lengthFilter, keywordFilter)

	// Set up policy enforcer
	enforcer := policy.NewEnforcer()
	err := enforcer.LoadPolicy(&policy.Policy{
		Name: "content-access",
		Rules: []policy.Rule{
			{
				Name: "block-admin-content",
				Conditions: []policy.Condition{
					{
						Field:    "role",
						Operator: policy.OperatorEquals,
						Value:    "guest",
					},
					{
						Field:    "content_type",
						Operator: policy.OperatorEquals,
						Value:    "admin",
					},
				},
				Decision: policy.DecisionDeny,
			},
		},
		DefaultDecision: policy.DecisionAllow,
	})
	require.NoError(t, err)

	// Test: allowed content for regular user
	filterResult, err := chain.Check("This is a normal message.")
	require.NoError(t, err)
	assert.True(t, filterResult.Allowed)

	evalResult, err := enforcer.Evaluate(context.Background(), "content-access",
		&policy.EvaluationContext{
			Fields: map[string]string{
				"role":         "user",
				"content_type": "general",
			},
		})
	require.NoError(t, err)
	assert.Equal(t, policy.DecisionAllow, evalResult.Decision)

	// Test: blocked content with keyword
	filterResult, err = chain.Check("My password is abc123")
	require.NoError(t, err)
	assert.False(t, filterResult.Allowed, "content with blocked keyword should be rejected")

	// Test: policy denies guest access to admin content
	evalResult, err = enforcer.Evaluate(context.Background(), "content-access",
		&policy.EvaluationContext{
			Fields: map[string]string{
				"role":         "guest",
				"content_type": "admin",
			},
		})
	require.NoError(t, err)
	assert.Equal(t, policy.DecisionDeny, evalResult.Decision)
}

func TestScannerReportWithFilterBySeverity_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode") // SKIP-OK: #short-mode
	}

	findings := []scanner.Finding{
		{Severity: scanner.SeverityCritical, Title: "SQL Injection", Description: "Unescaped input"},
		{Severity: scanner.SeverityHigh, Title: "XSS", Description: "Reflected XSS in form"},
		{Severity: scanner.SeverityMedium, Title: "Missing CSRF token", Description: "No CSRF protection"},
		{Severity: scanner.SeverityLow, Title: "Verbose errors", Description: "Stack trace in response"},
		{Severity: scanner.SeverityInfo, Title: "Server banner", Description: "Server header exposed"},
	}

	report := scanner.NewReport(findings, "test-scanner", "/api/v1", 100*time.Millisecond)

	assert.True(t, report.HasCritical())
	assert.True(t, report.HasHighOrAbove())
	assert.Equal(t, 5, report.TotalCount)

	highAndAbove := report.FilterBySeverity(scanner.SeverityHigh)
	assert.Equal(t, 2, len(highAndAbove))

	mediumAndAbove := report.FilterBySeverity(scanner.SeverityMedium)
	assert.Equal(t, 3, len(mediumAndAbove))

	summary := report.Summary()
	assert.Contains(t, summary, "5 findings")
}

func TestMergedScannerReports_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode") // SKIP-OK: #short-mode
	}

	report1 := scanner.NewReport(
		[]scanner.Finding{
			{Severity: scanner.SeverityCritical, Title: "RCE"},
		},
		"scanner-a", "/api", 50*time.Millisecond,
	)

	report2 := scanner.NewReport(
		[]scanner.Finding{
			{Severity: scanner.SeverityLow, Title: "Info leak"},
			{Severity: scanner.SeverityMedium, Title: "IDOR"},
		},
		"scanner-b", "/api", 75*time.Millisecond,
	)

	merged := scanner.MergeReports(report1, report2)
	assert.Equal(t, 3, merged.TotalCount)
	assert.True(t, merged.HasCritical())
	assert.Equal(t, 1, merged.BySeverity[scanner.SeverityCritical])
	assert.Equal(t, 1, merged.BySeverity[scanner.SeverityMedium])
	assert.Equal(t, 1, merged.BySeverity[scanner.SeverityLow])
}

func TestPIIDetectionAllTypes_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode") // SKIP-OK: #short-mode
	}

	redactor := pii.NewRedactor(pii.DefaultConfig())

	input := "Email: alice@corp.com, Phone: (555) 987-6543, " +
		"SSN: 123-45-6789, IP: 192.168.1.100"
	matches := redactor.Detect(input)

	typesSeen := make(map[pii.Type]bool)
	for _, m := range matches {
		typesSeen[m.Type] = true
	}

	assert.True(t, typesSeen[pii.TypeEmail], "should detect email")
	assert.True(t, typesSeen[pii.TypePhone], "should detect phone")
	assert.True(t, typesSeen[pii.TypeSSN], "should detect SSN")
	assert.True(t, typesSeen[pii.TypeIPAddress], "should detect IP address")
}

func TestPolicyEvaluateAllMostRestrictive_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode") // SKIP-OK: #short-mode
	}

	enforcer := policy.NewEnforcer()

	err := enforcer.LoadPolicies([]*policy.Policy{
		{
			Name: "allow-policy",
			Rules: []policy.Rule{
				{
					Name: "allow-users",
					Conditions: []policy.Condition{
						{Field: "role", Operator: policy.OperatorExists},
					},
					Decision: policy.DecisionAllow,
				},
			},
			DefaultDecision: policy.DecisionAllow,
		},
		{
			Name: "deny-policy",
			Rules: []policy.Rule{
				{
					Name: "deny-external",
					Conditions: []policy.Condition{
						{Field: "origin", Operator: policy.OperatorEquals, Value: "external"},
					},
					Decision: policy.DecisionDeny,
				},
			},
			DefaultDecision: policy.DecisionAllow,
		},
	})
	require.NoError(t, err)

	result, err := enforcer.EvaluateAll(context.Background(), &policy.EvaluationContext{
		Fields: map[string]string{
			"role":   "user",
			"origin": "external",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, policy.DecisionDeny, result.Decision,
		"most restrictive decision (deny) should win")
}
