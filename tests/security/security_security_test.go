package security

import (
	"context"
	"strings"
	"testing"

	"digital.vasic.security/pkg/content"
	"digital.vasic.security/pkg/guardrails"
	"digital.vasic.security/pkg/pii"
	"digital.vasic.security/pkg/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGuardrails_XSSInjection_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	patterns, err := guardrails.NewForbiddenPatternsRule(map[string]string{
		"script_tag":    `<script`,
		"onerror":       `onerror\s*=`,
		"onclick":       `onclick\s*=`,
		"javascript":    `javascript:`,
		"data_uri":      `data:text/html`,
		"event_handler": `on\w+\s*=\s*["']`,
	})
	require.NoError(t, err)

	engine := guardrails.NewEngine(guardrails.DefaultConfig())
	engine.AddRule(patterns)

	xssPayloads := []string{
		`<script>alert('xss')</script>`,
		`<img src=x onerror=alert(1)>`,
		`<div onclick=alert(1)>click me</div>`,
		`<a href="javascript:alert(1)">click</a>`,
		`<object data="data:text/html,<script>alert(1)</script>">`,
		`<body onload="alert(1)">`,
	}

	for _, payload := range xssPayloads {
		result := engine.Check(payload)
		assert.False(t, result.Passed,
			"XSS payload should be blocked: %s", payload)
	}
}

func TestGuardrails_SQLInjection_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	patterns, err := guardrails.NewForbiddenPatternsRule(map[string]string{
		"union_select": `(?i)union\s+select`,
		"drop_table":   `(?i)drop\s+table`,
		"or_1_eq_1":    `(?i)'\s+or\s+['"]?\d+['"]?\s*=\s*['"]?\d+`,
		"comment":      `--\s*$`,
	})
	require.NoError(t, err)

	engine := guardrails.NewEngine(guardrails.DefaultConfig())
	engine.AddRule(patterns)

	sqlPayloads := []string{
		"' UNION SELECT * FROM users--",
		"'; DROP TABLE accounts; --",
		"' OR '1'='1",
	}

	for _, payload := range sqlPayloads {
		result := engine.Check(payload)
		assert.False(t, result.Passed,
			"SQL injection payload should be blocked: %s", payload)
	}
}

func TestPIIRedactor_NilAndEmptyInput_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	redactor := pii.NewRedactor(pii.DefaultConfig())

	// Empty string should not panic
	redacted, matches := redactor.Redact("")
	assert.Equal(t, "", redacted)
	assert.Empty(t, matches)

	// String with no PII
	redacted, matches = redactor.Redact("Hello World")
	assert.Equal(t, "Hello World", redacted)
	assert.Empty(t, matches)
}

func TestPIIRedactor_NilConfig_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	// Passing nil config should use defaults, not panic
	redactor := pii.NewRedactor(nil)
	redacted, matches := redactor.Redact("test@example.com")
	assert.True(t, len(matches) > 0)
	assert.NotContains(t, redacted, "test@example.com")
}

func TestContentFilter_LargeInput_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	filter := content.NewLengthFilter(0, 1000)

	// Attempt to pass extremely large input
	largeInput := strings.Repeat("A", 1_000_000)
	result, err := filter.Check(largeInput)
	require.NoError(t, err)
	assert.False(t, result.Allowed,
		"input exceeding max length should be rejected")
}

func TestContentFilter_EmptyKeywordList_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	// Empty keyword list should not block anything
	filter := content.NewKeywordFilter([]string{}, false)
	result, err := filter.Check("any content here")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestPatternFilter_InvalidRegex_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	// Invalid regex should return error, not panic
	_, err := content.NewPatternFilter(map[string]string{
		"invalid": `[unclosed`,
	})
	assert.Error(t, err, "invalid regex should produce an error")
}

func TestPolicyEnforcer_NilPolicy_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	enforcer := policy.NewEnforcer()

	// Loading nil policy should return error
	err := enforcer.LoadPolicy(nil)
	assert.Error(t, err)

	// Loading policy with empty name should return error
	err = enforcer.LoadPolicy(&policy.Policy{Name: ""})
	assert.Error(t, err)
}

func TestPolicyEnforcer_NonexistentPolicy_Security(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping security test in short mode") // SKIP-OK: #short-mode
	}

	enforcer := policy.NewEnforcer()

	_, err := enforcer.Evaluate(context.Background(), "nonexistent",
		&policy.EvaluationContext{Fields: map[string]string{}})
	assert.Error(t, err, "evaluating nonexistent policy should error")
}
