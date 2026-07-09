package content

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLengthFilter(t *testing.T) {
	tests := []struct {
		name    string
		min     int
		max     int
		input   string
		allowed bool
	}{
		{"within bounds", 1, 100, "hello", true},
		{"too short", 5, 100, "hi", false},
		{"too long", 1, 5, "too long", false},
		{"at min", 5, 100, "hello", true},
		{"at max", 1, 5, "hello", true},
		{"empty with zero min", 0, 100, "", true},
		{"empty with nonzero min", 1, 100, "", false},
		{"no max limit", 1, 0, "any length is fine here", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := NewLengthFilter(tc.min, tc.max)
			result, err := f.Check(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.allowed, result.Allowed)
			if !tc.allowed {
				assert.NotEmpty(t, result.Reason)
				assert.Greater(t, result.Score, 0.0)
			}
		})
	}
}

func TestPatternFilter(t *testing.T) {
	patterns := map[string]string{
		"sql_injection": `(?i)(DROP\s+TABLE|DELETE\s+FROM)`,
		"script_tag":    `(?i)<script`,
	}
	f, err := NewPatternFilter(patterns)
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"clean content", "hello world", true},
		{"sql injection", "DROP TABLE users", false},
		{"xss attempt", "<script>alert(1)</script>", false},
		{"case insensitive", "drop table users", false},
		{"empty input", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := f.Check(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.allowed, result.Allowed)
		})
	}
}

func TestPatternFilter_InvalidPattern(t *testing.T) {
	_, err := NewPatternFilter(map[string]string{
		"bad": `[invalid`,
	})
	assert.Error(t, err)
}

func TestKeywordFilter_CaseInsensitive(t *testing.T) {
	f := NewKeywordFilter(
		[]string{"forbidden", "blocked"},
		false,
	)

	tests := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"clean", "hello world", true},
		{"contains keyword", "this is forbidden", false},
		{"case variation", "this is FORBIDDEN", false},
		{"partial match", "this is forbiddenness", false},
		{"blocked keyword", "this is blocked content", false},
		{"empty input", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := f.Check(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.allowed, result.Allowed)
		})
	}
}

func TestKeywordFilter_CaseSensitive(t *testing.T) {
	f := NewKeywordFilter(
		[]string{"FORBIDDEN"},
		true,
	)

	tests := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"exact match", "this is FORBIDDEN", false},
		{"wrong case", "this is forbidden", true},
		{"mixed case", "this is Forbidden", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := f.Check(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.allowed, result.Allowed)
		})
	}
}

func TestChainFilter_AllPass(t *testing.T) {
	chain := NewChainFilter(
		NewLengthFilter(1, 100),
		NewKeywordFilter([]string{"blocked"}, false),
	)

	result, err := chain.Check("hello world")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestChainFilter_FirstFails(t *testing.T) {
	chain := NewChainFilter(
		NewLengthFilter(100, 200),
		NewKeywordFilter([]string{"blocked"}, false),
	)

	result, err := chain.Check("short")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "below minimum")
}

func TestChainFilter_SecondFails(t *testing.T) {
	chain := NewChainFilter(
		NewLengthFilter(1, 100),
		NewKeywordFilter([]string{"blocked"}, false),
	)

	result, err := chain.Check("this is blocked content")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
	assert.Contains(t, result.Reason, "blocked")
}

func TestChainFilter_Empty(t *testing.T) {
	chain := NewChainFilter()
	result, err := chain.Check("anything")
	require.NoError(t, err)
	assert.True(t, result.Allowed)
}

func TestChainFilter_AddFilter(t *testing.T) {
	chain := NewChainFilter()
	chain.AddFilter(NewLengthFilter(1, 5))

	result, err := chain.Check("too long input")
	require.NoError(t, err)
	assert.False(t, result.Allowed)
}

func TestChainFilter_WithPatternFilter(t *testing.T) {
	pf, err := NewPatternFilter(map[string]string{
		"injection": `(?i)DROP\s+TABLE`,
	})
	require.NoError(t, err)

	chain := NewChainFilter(
		NewLengthFilter(1, 1000),
		pf,
		NewKeywordFilter([]string{"hack"}, false),
	)

	tests := []struct {
		name    string
		input   string
		allowed bool
	}{
		{"clean", "hello world", true},
		{"too long", "", false},
		{"injection", "DROP TABLE users", false},
		{"keyword", "lets hack the system", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result, err := chain.Check(tc.input)
			require.NoError(t, err)
			assert.Equal(t, tc.allowed, result.Allowed)
		})
	}
}

// errorFilter is a test filter that always returns an error.
type errorFilter struct{}

func (f *errorFilter) Check(_ string) (FilterResult, error) {
	return FilterResult{}, assert.AnError
}

func TestChainFilter_FilterReturnsError(t *testing.T) {
	chain := NewChainFilter(
		NewLengthFilter(1, 100),
		&errorFilter{},
	)

	result, err := chain.Check("hello")
	require.Error(t, err)
	assert.False(t, result.Allowed)
}
