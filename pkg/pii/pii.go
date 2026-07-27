// Package pii provides PII (Personally Identifiable Information) detection
// and redaction capabilities.
package pii

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Type represents a type of personally identifiable information.
type Type string

const (
	TypeEmail      Type = "email"
	TypePhone      Type = "phone"
	TypeSSN        Type = "ssn"
	TypeCreditCard Type = "credit_card"
	TypeIPAddress  Type = "ip_address"
)

// Match represents a detected PII occurrence.
type Match struct {
	Type       Type    `json:"type"`
	Value      string  `json:"value"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Confidence float64 `json:"confidence"`
}

// Detector detects PII in text.
type Detector interface {
	// Detect finds all PII occurrences in the given text.
	Detect(text string) []Match
}

// RedactionStrategy defines how detected PII should be redacted.
type RedactionStrategy string

const (
	StrategyMask   RedactionStrategy = "mask"
	StrategyHash   RedactionStrategy = "hash"
	StrategyRemove RedactionStrategy = "remove"
)

// Config configures PII detection and redaction.
type Config struct {
	// EnabledDetectors specifies which PII types to detect.
	EnabledDetectors []Type
	// RedactionStrategy specifies how to redact detected PII.
	RedactionStrategy RedactionStrategy
	// MaskChar is the character used for masking (default '*').
	MaskChar rune
}

// DefaultConfig returns a Config with all detectors enabled
// and mask redaction.
func DefaultConfig() *Config {
	return &Config{
		EnabledDetectors: []Type{
			TypeEmail, TypePhone, TypeSSN,
			TypeCreditCard, TypeIPAddress,
		},
		RedactionStrategy: StrategyMask,
		MaskChar:          '*',
	}
}

// regexDetector is a Detector that uses regular expressions.
type regexDetector struct {
	piiType    Type
	pattern    *regexp.Regexp
	confidence float64
}

func (d *regexDetector) Detect(text string) []Match {
	var matches []Match
	locs := d.pattern.FindAllStringIndex(text, -1)
	for _, loc := range locs {
		matches = append(matches, Match{
			Type:       d.piiType,
			Value:      text[loc[0]:loc[1]],
			Start:      loc[0],
			End:        loc[1],
			Confidence: d.confidence,
		})
	}
	return matches
}

// EmailDetector returns a Detector for email addresses.
func EmailDetector() Detector {
	return &regexDetector{
		piiType: TypeEmail,
		pattern: regexp.MustCompile(
			`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		),
		confidence: 0.9,
	}
}

// PhoneDetector returns a Detector for phone numbers.
func PhoneDetector() Detector {
	return &regexDetector{
		piiType: TypePhone,
		pattern: regexp.MustCompile(
			`(\+?1?[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}`,
		),
		confidence: 0.8,
	}
}

// SSNDetector returns a Detector for Social Security Numbers.
func SSNDetector() Detector {
	return &regexDetector{
		piiType: TypeSSN,
		pattern: regexp.MustCompile(
			`\b\d{3}[-]?\d{2}[-]?\d{4}\b`,
		),
		confidence: 0.85,
	}
}

// CreditCardDetector returns a Detector for credit card numbers.
func CreditCardDetector() Detector {
	return &creditCardDetector{}
}

type creditCardDetector struct{}

func (d *creditCardDetector) Detect(text string) []Match {
	pattern := regexp.MustCompile(
		`\b(?:4[0-9]{12}(?:[0-9]{3})?` +
			`|5[1-5][0-9]{14}` +
			`|3[47][0-9]{13}` +
			`|6(?:011|5[0-9]{2})[0-9]{12})\b`,
	)
	var matches []Match
	locs := pattern.FindAllStringIndex(text, -1)
	for _, loc := range locs {
		value := text[loc[0]:loc[1]]
		confidence := 0.7
		if validateLuhn(value) {
			confidence = 0.95
		}
		matches = append(matches, Match{
			Type:       TypeCreditCard,
			Value:      value,
			Start:      loc[0],
			End:        loc[1],
			Confidence: confidence,
		})
	}
	return matches
}

// IPAddressDetector returns a Detector for IP addresses.
func IPAddressDetector() Detector {
	return &regexDetector{
		piiType: TypeIPAddress,
		pattern: regexp.MustCompile(
			`\b(?:\d{1,3}\.){3}\d{1,3}\b`,
		),
		confidence: 0.75,
	}
}

// Redactor redacts PII from text using detected matches.
type Redactor struct {
	config    *Config
	detectors map[Type]Detector
}

// NewRedactor creates a new Redactor with the given config.
func NewRedactor(config *Config) *Redactor {
	if config == nil {
		config = DefaultConfig()
	}

	allDetectors := map[Type]Detector{
		TypeEmail:      EmailDetector(),
		TypePhone:      PhoneDetector(),
		TypeSSN:        SSNDetector(),
		TypeCreditCard: CreditCardDetector(),
		TypeIPAddress:  IPAddressDetector(),
	}

	enabled := make(map[Type]Detector)
	for _, t := range config.EnabledDetectors {
		if d, ok := allDetectors[t]; ok {
			enabled[t] = d
		}
	}

	return &Redactor{
		config:    config,
		detectors: enabled,
	}
}

// Detect detects all PII in the given text.
func (r *Redactor) Detect(text string) []Match {
	var allMatches []Match
	for _, detector := range r.detectors {
		matches := detector.Detect(text)
		allMatches = append(allMatches, matches...)
	}
	return allMatches
}

// Redact detects and redacts PII from text, returning the redacted text
// and the matches that were applied.
func (r *Redactor) Redact(text string) (string, []Match) {
	matches := r.Detect(text)
	if len(matches) == 0 {
		return text, nil
	}

	// Coalesce overlapping detections into deterministic, non-overlapping spans
	// before splicing. Detect() aggregates results from multiple detectors in Go
	// map-iteration order, and those spans can OVERLAP (e.g. a credit-card number
	// whose leading digits also match the phone pattern). Applying overlapping
	// spans with the descending-start splice below corrupts offsets and can
	// splice ORIGINAL PII bytes back into the "redacted" output, with the exact
	// result depending on nondeterministic map order. Resolving overlaps first
	// makes redaction deterministic and guarantees every detected byte is
	// covered by exactly one replacement.
	spans := resolveOverlaps(matches)

	// Apply spans from the highest start downward so an earlier splice never
	// invalidates the offsets of a later one.
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })

	result := text
	applied := make([]Match, 0, len(spans))
	for _, sp := range spans {
		rep := sp.rep
		replacement := r.redactValue(rep)
		result = result[:sp.start] + replacement + result[sp.end:]
		// Report the span actually redacted (union offsets, representative type).
		rep.Start, rep.End = sp.start, sp.end
		applied = append(applied, rep)
	}

	return result, applied
}

// mergedSpan is a maximal non-overlapping region to redact, together with the
// representative match whose type/value drives the replacement text.
type mergedSpan struct {
	start, end int
	rep        Match
	repLen     int // representative match's own length (for longest-wins selection)
}

// resolveOverlaps coalesces detector matches into deterministic, non-overlapping
// spans. Matches are ordered by (Start asc, End desc, Type asc) so the result
// never depends on detector map-iteration order; a linear sweep then merges any
// span that overlaps the previous one into a single union span, keeping the
// LONGEST contributing match as the representative (ties keep the earlier one).
// Merging (rather than dropping) overlapping matches guarantees no detected byte
// is left un-redacted even when neither match contains the other.
func resolveOverlaps(matches []Match) []mergedSpan {
	sorted := make([]Match, len(matches))
	copy(sorted, matches)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Start != sorted[j].Start {
			return sorted[i].Start < sorted[j].Start
		}
		if sorted[i].End != sorted[j].End {
			return sorted[i].End > sorted[j].End
		}
		return sorted[i].Type < sorted[j].Type
	})

	spans := make([]mergedSpan, 0, len(sorted))
	for _, m := range sorted {
		mLen := m.End - m.Start
		n := len(spans)
		if n == 0 || m.Start >= spans[n-1].end {
			spans = append(spans, mergedSpan{start: m.Start, end: m.End, rep: m, repLen: mLen})
			continue
		}
		s := &spans[n-1]
		if m.End > s.end {
			s.end = m.End // extend to the union
		}
		if mLen > s.repLen {
			s.rep = m // longest match drives the replacement
			s.repLen = mLen
		}
	}
	return spans
}

func (r *Redactor) redactValue(m Match) string {
	switch r.config.RedactionStrategy {
	case StrategyHash:
		hash := sha256.Sum256([]byte(m.Value))
		return fmt.Sprintf("[%s:%s]", m.Type, hex.EncodeToString(hash[:4]))
	case StrategyRemove:
		return fmt.Sprintf("[%s_REDACTED]", strings.ToUpper(string(m.Type)))
	case StrategyMask:
		fallthrough
	default:
		return maskValue(m, r.config.MaskChar)
	}
}

func maskValue(m Match, maskChar rune) string {
	mc := string(maskChar)
	switch m.Type {
	case TypeEmail:
		parts := strings.Split(m.Value, "@")
		if len(parts) == 2 {
			masked := maskStr(parts[0], 2, maskChar)
			return masked + "@" + parts[1]
		}
		return strings.Repeat(mc, len(m.Value))
	case TypePhone:
		cleaned := regexp.MustCompile(`\D`).
			ReplaceAllString(m.Value, "")
		if len(cleaned) >= 4 {
			return strings.Repeat(mc, 3) + "-" +
				strings.Repeat(mc, 3) + "-" +
				cleaned[len(cleaned)-4:]
		}
		return strings.Repeat(mc, len(m.Value))
	case TypeSSN:
		if len(m.Value) >= 4 {
			return strings.Repeat(mc, 3) + "-" +
				strings.Repeat(mc, 2) + "-" +
				m.Value[len(m.Value)-4:]
		}
		return strings.Repeat(mc, len(m.Value))
	case TypeCreditCard:
		cleaned := regexp.MustCompile(`\D`).
			ReplaceAllString(m.Value, "")
		if len(cleaned) >= 4 {
			return strings.Repeat(mc, 4) + "-" +
				strings.Repeat(mc, 4) + "-" +
				strings.Repeat(mc, 4) + "-" +
				cleaned[len(cleaned)-4:]
		}
		return strings.Repeat(mc, len(m.Value))
	case TypeIPAddress:
		return strings.Repeat(mc, 3) + "." +
			strings.Repeat(mc, 3) + "." +
			strings.Repeat(mc, 3) + "." +
			strings.Repeat(mc, 3)
	default:
		return strings.Repeat(mc, len(m.Value))
	}
}

func maskStr(s string, keepFirst int, maskChar rune) string {
	if len(s) <= keepFirst {
		return strings.Repeat(string(maskChar), len(s))
	}
	return s[:keepFirst] + strings.Repeat(string(maskChar), len(s)-keepFirst)
}

func validateLuhn(number string) bool {
	cleaned := regexp.MustCompile(`\D`).ReplaceAllString(number, "")
	if len(cleaned) < 13 || len(cleaned) > 19 {
		return false
	}

	sum := 0
	alternate := false
	for i := len(cleaned) - 1; i >= 0; i-- {
		digit := int(cleaned[i] - '0')
		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		alternate = !alternate
	}
	return sum%10 == 0
}
