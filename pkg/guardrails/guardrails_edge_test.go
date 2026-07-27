package guardrails_test

import (
	"strings"
	"testing"

	"digital.vasic.security/pkg/guardrails"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- SQL Injection Payloads ---

func TestGuardrails_SQLInjectionPayloads(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"sql_union":        `(?i)\bUNION\b.*\bSELECT\b`,
		"sql_drop":         `(?i)\bDROP\b.*\bTABLE\b`,
		"sql_or_1_eq_1":    `(?i)\bOR\b\s+['"]?1['"]?\s*=\s*['"]?1['"]?`,
		"sql_semicolon":    `;\s*(?i)(DROP|DELETE|INSERT|UPDATE|ALTER)\b`,
		"sql_comment":      `--\s*$`,
		"sql_single_quote": `'\s*(?i)(OR|AND)\s+`,
	}

	rule, err := guardrails.NewForbiddenPatternsRule(patterns)
	require.NoError(t, err)

	engine := guardrails.NewEngine(nil)
	engine.AddRule(rule)

	payloads := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"union_select", "1 UNION SELECT * FROM users", true},
		{"drop_table", "'; DROP TABLE users;", true},
		{"or_1_eq_1", "admin' OR 1=1 --", true},
		{"semicolon_delete", "1; DELETE FROM sessions", true},
		{"normal_text", "This is a normal search query", false},
		{"sql_keywords_in_prose", "I want to select the union of these results", false},
		{"encoded_quotes", "admin%27%20OR%201=1", false}, // URL-encoded, not raw SQL
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := engine.Check(tc.input)
			if tc.blocked {
				assert.False(t, result.Passed, "expected %q to be blocked", tc.input)
			} else {
				assert.True(t, result.Passed, "expected %q to be allowed", tc.input)
			}
		})
	}
}

// --- XSS Payloads ---

func TestGuardrails_XSSPayloads(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"script_tag":     `(?i)<\s*script[^>]*>`,
		"on_event":       `(?i)\bon\w+\s*=`,
		"javascript_uri": `(?i)javascript\s*:`,
		"img_onerror":    `(?i)<\s*img[^>]+onerror\s*=`,
	}

	rule, err := guardrails.NewForbiddenPatternsRule(patterns)
	require.NoError(t, err)

	engine := guardrails.NewEngine(nil)
	engine.AddRule(rule)

	payloads := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"script_tag", "<script>alert('xss')</script>", true},
		{"onclick", `<div onclick="alert(1)">`, true},
		{"javascript_href", `<a href="javascript:alert(1)">`, true},
		{"img_onerror", `<img src=x onerror=alert(1)>`, true},
		{"nested_script", `<scr<script>ipt>alert(1)</script>`, true},
		{"normal_html", "<p>Hello World</p>", false},
		{"normal_text", "This is just regular text", false},
		{"code_discussion", "Use the script element in HTML", false},
	}

	for _, tc := range payloads {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := engine.Check(tc.input)
			if tc.blocked {
				assert.False(t, result.Passed, "expected %q to be blocked", tc.input)
			} else {
				assert.True(t, result.Passed, "expected %q to be allowed", tc.input)
			}
		})
	}
}

// --- Path Traversal Strings ---

func TestGuardrails_PathTraversalStrings(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"dot_dot_slash":     `\.\./`,
		"dot_dot_backslash": `\.\.\\`,
		"encoded_traversal": `%2e%2e[/\\]`,
	}

	rule, err := guardrails.NewForbiddenPatternsRule(patterns)
	require.NoError(t, err)

	engine := guardrails.NewEngine(nil)
	engine.AddRule(rule)

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"unix_traversal", "../../etc/passwd", true},
		{"windows_traversal", `..\..\windows\system32`, true},
		{"encoded_traversal", "%2e%2e/etc/passwd", true},
		{"triple_traversal", "../../../secret", true},
		{"normal_path", "/api/v1/users", false},
		{"relative_path", "./config.json", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := engine.Check(tc.input)
			if tc.blocked {
				assert.False(t, result.Passed, "expected %q to be blocked", tc.input)
			} else {
				assert.True(t, result.Passed, "expected %q to be allowed", tc.input)
			}
		})
	}
}

// --- Null Bytes in Strings ---

func TestGuardrails_NullBytes(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"null_byte": `\x00`,
	}

	rule, err := guardrails.NewForbiddenPatternsRule(patterns)
	require.NoError(t, err)

	engine := guardrails.NewEngine(nil)
	engine.AddRule(rule)

	tests := []struct {
		name    string
		input   string
		blocked bool
	}{
		{"embedded_null", "hello\x00world", true},
		{"leading_null", "\x00data", true},
		{"trailing_null", "data\x00", true},
		{"no_null", "clean string", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := engine.Check(tc.input)
			if tc.blocked {
				assert.False(t, result.Passed, "expected input with null byte to be blocked")
			} else {
				assert.True(t, result.Passed)
			}
		})
	}
}

// --- Extremely Long Input Strings ---

func TestGuardrails_ExtremelyLongInput(t *testing.T) {
	t.Parallel()

	engine := guardrails.NewEngine(nil)
	engine.AddRule(guardrails.NewMaxLengthRule(1000))

	tests := []struct {
		name   string
		length int
		passed bool
	}{
		{"within_limit", 500, true},
		{"at_limit", 1000, true},
		{"over_limit", 1001, false},
		{"way_over", 100000, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			input := strings.Repeat("A", tc.length)
			result := engine.Check(input)
			assert.Equal(t, tc.passed, result.Passed)
		})
	}
}

// --- Empty Inputs ---

func TestGuardrails_EmptyInput(t *testing.T) {
	t.Parallel()

	engine := guardrails.NewEngine(nil)
	engine.AddRule(guardrails.NewMaxLengthRule(100))

	result := engine.Check("")
	assert.True(t, result.Passed, "empty string should pass max length check")
}

func TestGuardrails_EmptyInput_ForbiddenPatterns(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"script_tag": `<script>`,
	}
	rule, err := guardrails.NewForbiddenPatternsRule(patterns)
	require.NoError(t, err)

	engine := guardrails.NewEngine(nil)
	engine.AddRule(rule)

	result := engine.Check("")
	assert.True(t, result.Passed, "empty string should not match any pattern")
}

// --- Special Regex Characters in Input ---

func TestGuardrails_SpecialRegexCharsInInput(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"sql_injection": `(?i)\bDROP\b`,
	}
	rule, err := guardrails.NewForbiddenPatternsRule(patterns)
	require.NoError(t, err)

	engine := guardrails.NewEngine(nil)
	engine.AddRule(rule)

	// These inputs contain regex metacharacters but are not SQL injection
	regexInputs := []string{
		"Price is $100.00 (50% off)",
		"Pattern: [a-z]+ matches lowercase",
		"Use ^ and $ for anchors",
		"Escape with \\ backslash",
		"Question? Yes or no.",
		"Star * and plus +",
		"Braces {1,3} for repetition",
		"Pipe | for alternation",
	}

	for _, input := range regexInputs {
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			result := engine.Check(input)
			assert.True(t, result.Passed, "regex metacharacters should not cause issues")
		})
	}
}

// --- Invalid Pattern in ForbiddenPatternsRule ---

func TestForbiddenPatternsRule_InvalidPattern(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"bad_pattern": `[invalid`,
	}
	_, err := guardrails.NewForbiddenPatternsRule(patterns)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid pattern")
}

// --- RequireFormatRule Edge Cases ---

func TestRequireFormatRule_InvalidPattern(t *testing.T) {
	t.Parallel()

	_, err := guardrails.NewRequireFormatRule("test", `[broken`)
	assert.Error(t, err)
}

func TestRequireFormatRule_EmptyInput(t *testing.T) {
	t.Parallel()

	rule, err := guardrails.NewRequireFormatRule("email", `^[^@]+@[^@]+\.[^@]+$`)
	require.NoError(t, err)

	err = rule.Check("")
	assert.Error(t, err, "empty string should not match email format")
}

func TestRequireFormatRule_ValidInput(t *testing.T) {
	t.Parallel()

	rule, err := guardrails.NewRequireFormatRule("email", `^[^@]+@[^@]+\.[^@]+$`)
	require.NoError(t, err)

	err = rule.Check("user@example.com")
	assert.NoError(t, err)
}

// --- MaxLengthRule Zero and Negative ---

func TestMaxLengthRule_ZeroLimit(t *testing.T) {
	t.Parallel()

	rule := guardrails.NewMaxLengthRule(0)

	// Any non-empty string exceeds 0
	err := rule.Check("x")
	assert.Error(t, err)

	// Empty string should pass
	err = rule.Check("")
	assert.NoError(t, err)
}

// --- StopOnFirstFailure ---

func TestEngine_StopOnFirstFailure(t *testing.T) {
	t.Parallel()

	cfg := &guardrails.Config{
		Rules:              make(map[string]guardrails.RuleConfig),
		StopOnFirstFailure: true,
	}
	engine := guardrails.NewEngine(cfg)
	engine.AddRule(guardrails.NewMaxLengthRule(5))

	rule, err := guardrails.NewForbiddenPatternsRule(map[string]string{
		"test": `test`,
	})
	require.NoError(t, err)
	engine.AddRule(rule)

	// "test string" exceeds length AND matches pattern, but should stop after first
	result := engine.Check("test string")
	assert.False(t, result.Passed)
	// With StopOnFirstFailure, only one result should have an error
	failCount := 0
	for _, rr := range result.Results {
		if !rr.Passed {
			failCount++
		}
	}
	assert.Equal(t, 1, failCount, "should stop after first failure")
}

// --- Disabled Rules ---

func TestEngine_DisabledRules(t *testing.T) {
	t.Parallel()

	cfg := &guardrails.Config{
		Rules: map[string]guardrails.RuleConfig{
			"max_length": {Enabled: false, Severity: guardrails.SeverityLow},
		},
	}
	engine := guardrails.NewEngine(cfg)
	engine.AddRule(guardrails.NewMaxLengthRule(5))

	// Max length rule is disabled, so long input should pass
	result := engine.Check("this is a very long string that exceeds the limit")
	assert.True(t, result.Passed)
	assert.Empty(t, result.Results, "disabled rule should not produce results")
}

// --- Engine With No Rules ---

func TestEngine_NoRules(t *testing.T) {
	t.Parallel()

	engine := guardrails.NewEngine(nil)
	result := engine.Check("anything goes")
	assert.True(t, result.Passed)
	assert.Empty(t, result.Results)
}

// --- Nil Config ---

func TestEngine_NilConfig(t *testing.T) {
	t.Parallel()

	engine := guardrails.NewEngine(nil)
	require.NotNil(t, engine)

	engine.AddRule(guardrails.NewMaxLengthRule(10))
	result := engine.Check("short")
	assert.True(t, result.Passed)
}
