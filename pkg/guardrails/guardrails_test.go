package guardrails

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngine_Check_NoRules(t *testing.T) {
	engine := NewEngine(nil)
	result := engine.Check("any content")
	assert.True(t, result.Passed)
	assert.Empty(t, result.Results)
}

func TestEngine_Check_WithRules(t *testing.T) {
	engine := NewEngine(nil)
	engine.AddRule(NewMaxLengthRule(10))

	tests := []struct {
		name    string
		content string
		passed  bool
	}{
		{
			name:    "within limit",
			content: "short",
			passed:  true,
		},
		{
			name:    "at limit",
			content: "1234567890",
			passed:  true,
		},
		{
			name:    "exceeds limit",
			content: "this is way too long",
			passed:  false,
		},
		{
			name:    "empty content",
			content: "",
			passed:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := engine.Check(tc.content)
			assert.Equal(t, tc.passed, result.Passed)
			assert.Len(t, result.Results, 1)
			assert.Equal(t, "max_length", result.Results[0].RuleName)
		})
	}
}

func TestEngine_Check_StopOnFirstFailure(t *testing.T) {
	config := &Config{
		Rules:              make(map[string]RuleConfig),
		StopOnFirstFailure: true,
	}
	engine := NewEngine(config)
	engine.AddRule(NewMaxLengthRule(5))

	fp, err := NewForbiddenPatternsRule(map[string]string{
		"digits": `\d+`,
	})
	require.NoError(t, err)
	engine.AddRule(fp)

	// Content that fails first rule -- should stop
	result := engine.Check("this is too long 123")
	assert.False(t, result.Passed)
	assert.Len(t, result.Results, 1)
	assert.Equal(t, "max_length", result.Results[0].RuleName)
}

func TestEngine_Check_DisabledRule(t *testing.T) {
	config := &Config{
		Rules: map[string]RuleConfig{
			"max_length": {Enabled: false, Severity: SeverityHigh},
		},
	}
	engine := NewEngine(config)
	engine.AddRule(NewMaxLengthRule(5))

	result := engine.Check("this exceeds the limit")
	assert.True(t, result.Passed)
	assert.Empty(t, result.Results)
}

func TestEngine_Check_CustomSeverity(t *testing.T) {
	config := &Config{
		Rules: map[string]RuleConfig{
			"max_length": {Enabled: true, Severity: SeverityCritical},
		},
	}
	engine := NewEngine(config)
	engine.AddRule(NewMaxLengthRule(5))

	result := engine.Check("too long")
	assert.False(t, result.Passed)
	require.Len(t, result.Results, 1)
	assert.Equal(t, SeverityCritical, result.Results[0].Severity)
}

func TestMaxLengthRule(t *testing.T) {
	tests := []struct {
		name      string
		maxLen    int
		content   string
		expectErr bool
	}{
		{"within limit", 100, "hello", false},
		{"at limit", 5, "hello", false},
		{"exceeds limit", 3, "hello", true},
		{"empty content", 0, "", false},
		{"zero limit non-empty", 0, "a", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rule := NewMaxLengthRule(tc.maxLen)
			assert.Equal(t, "max_length", rule.Name())
			err := rule.Check(tc.content)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestForbiddenPatternsRule(t *testing.T) {
	patterns := map[string]string{
		"sql_injection": `(?i)(DROP\s+TABLE|DELETE\s+FROM)`,
		"xss":           `(?i)<script`,
	}
	rule, err := NewForbiddenPatternsRule(patterns)
	require.NoError(t, err)
	assert.Equal(t, "forbidden_patterns", rule.Name())

	tests := []struct {
		name      string
		content   string
		expectErr bool
	}{
		{"clean content", "hello world", false},
		{"sql injection", "DROP TABLE users", true},
		{"xss attack", "<script>alert('xss')</script>", true},
		{"case insensitive sql", "drop table users", true},
		{"empty content", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rule.Check(tc.content)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestForbiddenPatternsRule_InvalidPattern(t *testing.T) {
	patterns := map[string]string{
		"bad": `[invalid`,
	}
	_, err := NewForbiddenPatternsRule(patterns)
	assert.Error(t, err)
}

func TestRequireFormatRule(t *testing.T) {
	rule, err := NewRequireFormatRule("alphanumeric", `^[a-zA-Z0-9]+$`)
	require.NoError(t, err)
	assert.Equal(t, "require_format", rule.Name())

	tests := []struct {
		name      string
		content   string
		expectErr bool
	}{
		{"valid alphanumeric", "Hello123", false},
		{"with spaces", "Hello 123", true},
		{"with special chars", "Hello@123", true},
		{"empty string", "", true},
		{"numbers only", "12345", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := rule.Check(tc.content)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestRequireFormatRule_InvalidPattern(t *testing.T) {
	_, err := NewRequireFormatRule("bad", `[invalid`)
	assert.Error(t, err)
}

func TestEngine_ConcurrentAccess(t *testing.T) {
	engine := NewEngine(nil)
	engine.AddRule(NewMaxLengthRule(100))

	done := make(chan struct{})
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 100; j++ {
				result := engine.Check("test content")
				assert.True(t, result.Passed)
			}
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.NotNil(t, config)
	assert.NotNil(t, config.Rules)
	assert.False(t, config.StopOnFirstFailure)
}

func TestEngine_MultipleRulesAllPass(t *testing.T) {
	engine := NewEngine(nil)
	engine.AddRule(NewMaxLengthRule(100))

	fp, err := NewForbiddenPatternsRule(map[string]string{
		"sql": `(?i)DROP\s+TABLE`,
	})
	require.NoError(t, err)
	engine.AddRule(fp)

	result := engine.Check("hello world")
	assert.True(t, result.Passed)
	assert.Len(t, result.Results, 2)
	for _, rr := range result.Results {
		assert.True(t, rr.Passed)
	}
}

func TestEngine_MultipleRulesOneFails(t *testing.T) {
	engine := NewEngine(nil)
	engine.AddRule(NewMaxLengthRule(100))

	fp, err := NewForbiddenPatternsRule(map[string]string{
		"sql": `(?i)DROP\s+TABLE`,
	})
	require.NoError(t, err)
	engine.AddRule(fp)

	result := engine.Check("DROP TABLE users")
	assert.False(t, result.Passed)
	assert.Len(t, result.Results, 2)
	assert.True(t, result.Results[0].Passed)
	assert.False(t, result.Results[1].Passed)
}
