package content_test

import (
	"strings"
	"testing"

	"digital.vasic.security/pkg/content"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- SQL Injection Payloads ---

func TestPatternFilter_SQLInjection(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"sql_union":     `(?i)\bUNION\b.*\bSELECT\b`,
		"sql_drop":      `(?i)\bDROP\b.*\bTABLE\b`,
		"sql_or_1_eq_1": `(?i)\bOR\b\s+['"]?1['"]?\s*=\s*['"]?1['"]?`,
		"sql_comment":   `--\s*$`,
	}

	f, err := content.NewPatternFilter(patterns)
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"union_select", "1 UNION SELECT * FROM users", false},
		{"drop_table", "'; DROP TABLE users;", false},
		{"or_1_eq_1", "admin' OR 1=1 --", false},
		{"comment_injection", "query --", false},
		{"normal_query", "find all products by name", true},
		{"empty_string", "", true},
		{"prose_without_sql_pattern", "The team met to discuss a leader", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := f.Check(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, result.Allowed)
		})
	}
}

// --- XSS Payloads ---

func TestPatternFilter_XSSPayloads(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"script_tag":     `(?i)<\s*script[^>]*>`,
		"on_event":       `(?i)\bon\w+\s*=`,
		"javascript_uri": `(?i)javascript\s*:`,
	}

	f, err := content.NewPatternFilter(patterns)
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"script_tag", "<script>alert('xss')</script>", false},
		{"onclick", `<div onclick="alert(1)">`, false},
		{"javascript_href", `<a href="javascript:alert(1)">`, false},
		{"normal_html", "<p>Hello World</p>", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := f.Check(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, result.Allowed)
		})
	}
}

// --- Path Traversal Strings ---

func TestPatternFilter_PathTraversal(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"dot_dot_slash":     `\.\./`,
		"dot_dot_backslash": `\.\.\\`,
	}

	f, err := content.NewPatternFilter(patterns)
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"unix_traversal", "../../etc/passwd", false},
		{"windows_traversal", `..\..\windows\system32`, false},
		{"triple_depth", "../../../secret", false},
		{"normal_path", "/api/v1/users", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := f.Check(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, result.Allowed)
		})
	}
}

// --- Null Byte Injection ---

func TestPatternFilter_NullByteInjection(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"null_byte": `\x00`,
	}

	f, err := content.NewPatternFilter(patterns)
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"embedded_null", "hello\x00world", false},
		{"leading_null", "\x00data", false},
		{"trailing_null", "data\x00", false},
		{"clean_string", "no nulls here", true},
		{"empty", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := f.Check(tt.input)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, result.Allowed)
		})
	}
}

// --- Extremely Long Inputs ---

func TestLengthFilter_ExtremelyLongInput(t *testing.T) {
	t.Parallel()

	f := content.NewLengthFilter(0, 1000)

	tests := []struct {
		name    string
		length  int
		allowed bool
	}{
		{"within_limit", 500, true},
		{"at_limit", 1000, true},
		{"over_limit", 1001, false},
		{"way_over", 100000, false},
		{"empty", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input := strings.Repeat("A", tt.length)
			result, err := f.Check(input)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, result.Allowed)
		})
	}
}

// --- Empty Inputs ---

func TestLengthFilter_EmptyInput_WithMinimum(t *testing.T) {
	t.Parallel()

	f := content.NewLengthFilter(5, 100)

	result, err := f.Check("")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "below minimum")
}

func TestLengthFilter_EmptyInput_NoMinimum(t *testing.T) {
	t.Parallel()

	f := content.NewLengthFilter(0, 100)

	result, err := f.Check("")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestLengthFilter_ZeroMaxLength_NoLimit(t *testing.T) {
	t.Parallel()

	f := content.NewLengthFilter(0, 0)

	// With max=0, no upper limit is applied
	result, err := f.Check(strings.Repeat("x", 100000))
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// --- ChainFilter Edge Cases ---

func TestChainFilter_EmptyChain(t *testing.T) {
	t.Parallel()

	chain := content.NewChainFilter()

	result, err := chain.Check("anything")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestChainFilter_SingleFilter(t *testing.T) {
	t.Parallel()

	chain := content.NewChainFilter(content.NewLengthFilter(0, 10))

	result, err := chain.Check("short")
	require.NoError(t, err)
	assert.True(t, result.Allowed)

	result, err = chain.Check("this is way too long")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestChainFilter_StopsOnFirstRejection(t *testing.T) {
	t.Parallel()

	lengthFilter := content.NewLengthFilter(0, 5)
	patterns := map[string]string{
		"test": `test`,
	}
	patternFilter, err := content.NewPatternFilter(patterns)
	require.NoError(t, err)

	chain := content.NewChainFilter(lengthFilter, patternFilter)

	// "test string" exceeds length, should stop before checking patterns
	result, err := chain.Check("test string")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "exceeds maximum")
}

func TestChainFilter_AddFilter(t *testing.T) {
	t.Parallel()

	chain := content.NewChainFilter()
	chain.AddFilter(content.NewLengthFilter(1, 100))

	result, err := chain.Check("")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

// --- KeywordFilter Edge Cases ---

func TestKeywordFilter_CaseSensitive(t *testing.T) {
	t.Parallel()

	f := content.NewKeywordFilter([]string{"BadWord"}, true)

	result, err := f.Check("contains BadWord here")
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	result, err = f.Check("contains badword here")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestKeywordFilter_CaseInsensitive(t *testing.T) {
	t.Parallel()

	f := content.NewKeywordFilter([]string{"badword"}, false)

	result, err := f.Check("contains BADWORD here")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestKeywordFilter_EmptyKeywords(t *testing.T) {
	t.Parallel()

	f := content.NewKeywordFilter([]string{}, false)

	result, err := f.Check("anything goes")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestKeywordFilter_EmptyInput(t *testing.T) {
	t.Parallel()

	f := content.NewKeywordFilter([]string{"bad"}, false)

	result, err := f.Check("")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestKeywordFilter_UnicodeKeywords(t *testing.T) {
	t.Parallel()

	f := content.NewKeywordFilter([]string{"\u5371\u9669"}, false)

	result, err := f.Check("\u8fd9\u662f\u5371\u9669\u5185\u5bb9")
	require.NoError(t, err)
	assert.False(t, result.Allowed)

	result, err = f.Check("safe content")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

// --- PatternFilter Edge Cases ---

func TestPatternFilter_InvalidPattern(t *testing.T) {
	t.Parallel()

	_, err := content.NewPatternFilter(map[string]string{
		"bad": `[invalid`,
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid pattern")
}

func TestPatternFilter_EmptyPatterns(t *testing.T) {
	t.Parallel()

	f, err := content.NewPatternFilter(map[string]string{})
	require.NoError(t, err)

	result, err := f.Check("anything")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestPatternFilter_SpecialRegexCharsInInput(t *testing.T) {
	t.Parallel()

	patterns := map[string]string{
		"test": `test_pattern`,
	}
	f, err := content.NewPatternFilter(patterns)
	require.NoError(t, err)

	// Input with regex metacharacters should not cause errors
	regexInputs := []string{
		"Price is $100.00 (50% off)",
		"Pattern: [a-z]+ matches lowercase",
		"Use ^ and $ for anchors",
		"Star * and plus +",
		"Braces {1,3}",
		"Pipe | for alternation",
	}

	for _, input := range regexInputs {
		result, err := f.Check(input)
		require.NoError(t, err)
		assert.True(t, result.Allowed)
	}
}

// --- FilterResult Score Values ---

func TestFilterResult_ScoreValues(t *testing.T) {
	t.Parallel()

	// Allowed result has score 0
	f := content.NewLengthFilter(0, 100)
	result, err := f.Check("ok")
	require.NoError(t, err)
	assert.Equal(t, 0.0, result.Score)

	// Rejected result has score > 0
	result, err = f.Check(strings.Repeat("x", 200))
	require.NoError(t, err)
	assert.Equal(t, 1.0, result.Score)
}
