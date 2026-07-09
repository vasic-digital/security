package pii

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailDetector(t *testing.T) {
	detector := EmailDetector()

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{"single email", "contact user@example.com now", 1},
		{"multiple emails", "a@b.com and c@d.org", 2},
		{"no email", "no email here", 0},
		{"email at start", "user@test.com is valid", 1},
		{"complex email", "test.user+tag@example.co.uk", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := detector.Detect(tc.text)
			assert.Len(t, matches, tc.expected)
			for _, m := range matches {
				assert.Equal(t, TypeEmail, m.Type)
				assert.Greater(t, m.Confidence, 0.0)
			}
		})
	}
}

func TestPhoneDetector(t *testing.T) {
	detector := PhoneDetector()

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{"US phone", "call 555-123-4567", 1},
		{"phone with parens", "call (555) 123-4567", 1},
		{"no phone", "no phone here", 0},
		{"phone with dots", "555.123.4567 is the number", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := detector.Detect(tc.text)
			assert.Len(t, matches, tc.expected)
			for _, m := range matches {
				assert.Equal(t, TypePhone, m.Type)
			}
		})
	}
}

func TestSSNDetector(t *testing.T) {
	detector := SSNDetector()

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{"SSN with dashes", "SSN: 123-45-6789", 1},
		{"SSN no dashes", "SSN: 123456789", 1},
		{"no SSN", "no ssn here", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := detector.Detect(tc.text)
			assert.Len(t, matches, tc.expected)
			for _, m := range matches {
				assert.Equal(t, TypeSSN, m.Type)
			}
		})
	}
}

func TestCreditCardDetector(t *testing.T) {
	detector := CreditCardDetector()

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{
			"Visa",
			"card: 4111111111111111",
			1,
		},
		{
			"no card",
			"no credit card here",
			0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := detector.Detect(tc.text)
			assert.Len(t, matches, tc.expected)
			for _, m := range matches {
				assert.Equal(t, TypeCreditCard, m.Type)
			}
		})
	}
}

func TestIPAddressDetector(t *testing.T) {
	detector := IPAddressDetector()

	tests := []struct {
		name     string
		text     string
		expected int
	}{
		{"IPv4", "server at 192.168.1.1", 1},
		{"multiple IPs", "10.0.0.1 and 10.0.0.2", 2},
		{"no IP", "no ip address here", 0},
		{"localhost", "connect to 127.0.0.1", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := detector.Detect(tc.text)
			assert.Len(t, matches, tc.expected)
			for _, m := range matches {
				assert.Equal(t, TypeIPAddress, m.Type)
			}
		})
	}
}

func TestRedactor_Detect(t *testing.T) {
	redactor := NewRedactor(nil)
	text := "Email: user@example.com, IP: 10.0.0.1"
	matches := redactor.Detect(text)
	assert.GreaterOrEqual(t, len(matches), 2)
}

func TestRedactor_Redact_Mask(t *testing.T) {
	config := &Config{
		EnabledDetectors:  []Type{TypeEmail},
		RedactionStrategy: StrategyMask,
		MaskChar:          '*',
	}
	redactor := NewRedactor(config)

	text := "contact user@example.com please"
	redacted, matches := redactor.Redact(text)

	require.Len(t, matches, 1)
	assert.NotContains(t, redacted, "user@example.com")
	assert.Contains(t, redacted, "@example.com")
}

func TestRedactor_Redact_Hash(t *testing.T) {
	config := &Config{
		EnabledDetectors:  []Type{TypeEmail},
		RedactionStrategy: StrategyHash,
		MaskChar:          '*',
	}
	redactor := NewRedactor(config)

	text := "contact user@example.com please"
	redacted, matches := redactor.Redact(text)

	require.Len(t, matches, 1)
	assert.NotContains(t, redacted, "user@example.com")
	assert.Contains(t, redacted, "[email:")
}

func TestRedactor_Redact_Remove(t *testing.T) {
	config := &Config{
		EnabledDetectors:  []Type{TypeEmail},
		RedactionStrategy: StrategyRemove,
		MaskChar:          '*',
	}
	redactor := NewRedactor(config)

	text := "contact user@example.com please"
	redacted, matches := redactor.Redact(text)

	require.Len(t, matches, 1)
	assert.NotContains(t, redacted, "user@example.com")
	assert.Contains(t, redacted, "[EMAIL_REDACTED]")
}

func TestRedactor_NoMatches(t *testing.T) {
	redactor := NewRedactor(nil)
	text := "no PII here at all"
	redacted, matches := redactor.Redact(text)
	assert.Equal(t, text, redacted)
	assert.Nil(t, matches)
}

func TestRedactor_MultiplePII(t *testing.T) {
	config := &Config{
		EnabledDetectors:  []Type{TypeEmail, TypeIPAddress},
		RedactionStrategy: StrategyRemove,
		MaskChar:          '*',
	}
	redactor := NewRedactor(config)

	text := "user@test.com accessed from 192.168.1.1"
	redacted, matches := redactor.Redact(text)

	assert.GreaterOrEqual(t, len(matches), 2)
	assert.NotContains(t, redacted, "user@test.com")
	assert.NotContains(t, redacted, "192.168.1.1")
}

func TestRedactor_SpecificDetectorsOnly(t *testing.T) {
	config := &Config{
		EnabledDetectors:  []Type{TypeEmail},
		RedactionStrategy: StrategyMask,
		MaskChar:          '*',
	}
	redactor := NewRedactor(config)

	text := "user@test.com at 192.168.1.1"
	matches := redactor.Detect(text)

	// Should only detect email, not IP
	emailCount := 0
	ipCount := 0
	for _, m := range matches {
		if m.Type == TypeEmail {
			emailCount++
		}
		if m.Type == TypeIPAddress {
			ipCount++
		}
	}
	assert.Equal(t, 1, emailCount)
	assert.Equal(t, 0, ipCount)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()
	assert.NotNil(t, config)
	assert.Len(t, config.EnabledDetectors, 5)
	assert.Equal(t, StrategyMask, config.RedactionStrategy)
	assert.Equal(t, '*', config.MaskChar)
}

func TestValidateLuhn(t *testing.T) {
	tests := []struct {
		name     string
		number   string
		expected bool
	}{
		{"valid Visa", "4111111111111111", true},
		{"invalid number", "1234567890123456", false},
		{"too short", "123", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, validateLuhn(tc.number))
		})
	}
}

func TestMaskValue_Phone(t *testing.T) {
	m := Match{
		Type:  TypePhone,
		Value: "555-123-4567",
	}
	result := maskValue(m, '*')
	assert.Contains(t, result, "4567")
	assert.Contains(t, result, "***")
}

func TestMaskValue_SSN(t *testing.T) {
	m := Match{
		Type:  TypeSSN,
		Value: "123-45-6789",
	}
	result := maskValue(m, '*')
	assert.Contains(t, result, "6789")
	assert.Contains(t, result, "***")
}

func TestMaskValue_CreditCard(t *testing.T) {
	m := Match{
		Type:  TypeCreditCard,
		Value: "4111111111111111",
	}
	result := maskValue(m, '*')
	assert.Contains(t, result, "1111")
	assert.Contains(t, result, "****")
}

func TestMaskValue_IPAddress(t *testing.T) {
	m := Match{
		Type:  TypeIPAddress,
		Value: "192.168.1.1",
	}
	result := maskValue(m, '*')
	assert.NotContains(t, result, "192")
	assert.Contains(t, result, "***")
}

func TestMaskValue_DefaultType(t *testing.T) {
	// Test the default case (unknown type)
	m := Match{
		Type:  Type("unknown_type"),
		Value: "some_value",
	}
	result := maskValue(m, '*')
	// Default case should mask entire value
	assert.Equal(t, "**********", result)
	assert.Len(t, result, len("some_value"))
}

func TestMaskValue_ShortValues(t *testing.T) {
	tests := []struct {
		name     string
		match    Match
		maskChar rune
	}{
		{
			name: "short phone",
			match: Match{
				Type:  TypePhone,
				Value: "123",
			},
			maskChar: '*',
		},
		{
			name: "short ssn",
			match: Match{
				Type:  TypeSSN,
				Value: "12",
			},
			maskChar: '#',
		},
		{
			name: "short credit card",
			match: Match{
				Type:  TypeCreditCard,
				Value: "123",
			},
			maskChar: 'X',
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskValue(tt.match, tt.maskChar)
			// Short values should get full mask
			assert.NotEmpty(t, result)
			assert.Equal(t, len(tt.match.Value), len(result))
		})
	}
}

func TestMaskValue_EmailNoAt(t *testing.T) {
	// Edge case: email without @ (should not happen but tests default path)
	m := Match{
		Type:  TypeEmail,
		Value: "invalidemail",
	}
	result := maskValue(m, '*')
	// Should mask the whole value (length of "invalidemail" is 12)
	assert.Len(t, result, len("invalidemail"))
	assert.NotContains(t, result, "invalidemail")
}

func TestMaskStr_ShortString(t *testing.T) {
	// Test maskStr with string shorter than keepFirst
	result := maskStr("ab", 5, '*')
	assert.Equal(t, "**", result)
}

func TestMaskStr_ExactKeepFirst(t *testing.T) {
	// Test maskStr with string exactly equal to keepFirst
	result := maskStr("abc", 3, '*')
	assert.Equal(t, "***", result)
}
