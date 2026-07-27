// Package content provides content filtering capabilities with composable
// filter chains for validating and checking input content.
package content

import (
	"fmt"
	"regexp"
	"strings"
)

// FilterResult contains the result of a content filter check.
type FilterResult struct {
	Allowed bool    `json:"allowed"`
	Reason  string  `json:"reason,omitempty"`
	Score   float64 `json:"score"`
}

// Filter checks input content and returns a FilterResult.
type Filter interface {
	// Check evaluates the input content.
	Check(input string) (FilterResult, error)
}

// ChainFilter combines multiple filters. Content must pass all filters
// to be allowed.
type ChainFilter struct {
	filters []Filter
}

// NewChainFilter creates a new ChainFilter with the given filters.
func NewChainFilter(filters ...Filter) *ChainFilter {
	return &ChainFilter{filters: filters}
}

// AddFilter adds a filter to the chain.
func (c *ChainFilter) AddFilter(filter Filter) {
	c.filters = append(c.filters, filter)
}

// Check runs all filters in sequence. Returns the first rejection
// or an allowing result if all filters pass.
func (c *ChainFilter) Check(input string) (FilterResult, error) {
	for _, f := range c.filters {
		result, err := f.Check(input)
		if err != nil {
			return FilterResult{}, err
		}
		if !result.Allowed {
			return result, nil
		}
	}
	return FilterResult{
		Allowed: true,
		Score:   0.0,
	}, nil
}

// LengthFilter checks that input length is within bounds.
type LengthFilter struct {
	minLength int
	maxLength int
}

// NewLengthFilter creates a new LengthFilter.
func NewLengthFilter(minLength, maxLength int) *LengthFilter {
	return &LengthFilter{
		minLength: minLength,
		maxLength: maxLength,
	}
}

// Check validates that input length is within the configured bounds.
func (f *LengthFilter) Check(input string) (FilterResult, error) {
	length := len(input)

	if length < f.minLength {
		return FilterResult{
			Allowed: false,
			Reason: fmt.Sprintf(
				"input length %d is below minimum %d",
				length, f.minLength,
			),
			Score: 1.0,
		}, nil
	}

	if f.maxLength > 0 && length > f.maxLength {
		return FilterResult{
			Allowed: false,
			Reason: fmt.Sprintf(
				"input length %d exceeds maximum %d",
				length, f.maxLength,
			),
			Score: 1.0,
		}, nil
	}

	return FilterResult{Allowed: true, Score: 0.0}, nil
}

// PatternFilter rejects content matching any of the forbidden patterns.
type PatternFilter struct {
	patterns []*regexp.Regexp
	names    []string
}

// NewPatternFilter creates a new PatternFilter. The patterns map keys
// are descriptive names and values are regular expression strings.
func NewPatternFilter(
	patterns map[string]string,
) (*PatternFilter, error) {
	f := &PatternFilter{
		patterns: make([]*regexp.Regexp, 0, len(patterns)),
		names:    make([]string, 0, len(patterns)),
	}
	for name, pattern := range patterns {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf(
				"invalid pattern %q: %w", name, err,
			)
		}
		f.patterns = append(f.patterns, compiled)
		f.names = append(f.names, name)
	}
	return f, nil
}

// Check validates that input does not match any forbidden pattern.
func (f *PatternFilter) Check(input string) (FilterResult, error) {
	for i, pattern := range f.patterns {
		if pattern.MatchString(input) {
			return FilterResult{
				Allowed: false,
				Reason: fmt.Sprintf(
					"content matches forbidden pattern %q",
					f.names[i],
				),
				Score: 0.9,
			}, nil
		}
	}
	return FilterResult{Allowed: true, Score: 0.0}, nil
}

// KeywordFilter rejects content containing any of the blocked keywords.
type KeywordFilter struct {
	keywords      []string
	caseSensitive bool
}

// NewKeywordFilter creates a new KeywordFilter.
//
// Empty-string entries in keywords are skipped. strings.Contains(s, "") is
// true for every s, so a stored empty keyword would make Check reject every
// input unconditionally -- a real misconfiguration risk, since keyword lists
// are commonly assembled by splitting a config/CSV/YAML value (e.g.
// strings.Split("badword,", ",") yields []string{"badword", ""}). Silently
// ignoring the empty entry preserves the caller's real keywords instead of
// turning the filter into an unconditional block-all.
func NewKeywordFilter(
	keywords []string, caseSensitive bool,
) *KeywordFilter {
	stored := make([]string, 0, len(keywords))
	for _, kw := range keywords {
		if kw == "" {
			continue
		}
		if caseSensitive {
			stored = append(stored, kw)
		} else {
			stored = append(stored, strings.ToLower(kw))
		}
	}
	return &KeywordFilter{
		keywords:      stored,
		caseSensitive: caseSensitive,
	}
}

// Check validates that input does not contain any blocked keyword.
func (f *KeywordFilter) Check(input string) (FilterResult, error) {
	checkInput := input
	if !f.caseSensitive {
		checkInput = strings.ToLower(input)
	}

	for _, kw := range f.keywords {
		if strings.Contains(checkInput, kw) {
			return FilterResult{
				Allowed: false,
				Reason: fmt.Sprintf(
					"content contains blocked keyword %q", kw,
				),
				Score: 0.8,
			}, nil
		}
	}
	return FilterResult{Allowed: true, Score: 0.0}, nil
}
