// SPDX-FileCopyrightText: 2026 Milos Vasic
// SPDX-License-Identifier: Apache-2.0

package ssrf

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// These tests close genuine coverage gaps in the SSRF guard's edge/error
// branches: malformed URLs, empty host, the checkIP rejection classes that
// the existing suite did not reach (IPv6 ULA, link-local-multicast,
// interface-local & global multicast), and the alternative-IP-encoding parser
// bounds (overflow / out-of-range octets / oversized absorbing parts). Each
// case asserts a concrete user-visible outcome: a would-be-internal target is
// BLOCKED (ErrBlocked), a genuine public/DNS name is allowed through, and a
// non-IP string is correctly rejected by the numeric parsers (returns nil so
// it takes the DNS path) — never silently dialled.

func TestValidate_RejectsMalformedURL(t *testing.T) {
	// control character in the URL makes url.Parse fail.
	err := Validate("http://exa\x7fmple\n.com/", Config{})
	if err == nil || !errors.Is(err, ErrBlocked) {
		t.Fatalf("malformed URL must be blocked, got %v", err)
	}
	if !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse reason, got %v", err)
	}
}

func TestValidate_RejectsEmptyHost(t *testing.T) {
	// A scheme with no host (e.g. "http:///path") yields an empty hostname.
	err := Validate("http:///just/a/path", Config{})
	if err == nil || !errors.Is(err, ErrBlocked) {
		t.Fatalf("empty host must be blocked, got %v", err)
	}
	if !strings.Contains(err.Error(), "host") {
		t.Errorf("expected host reason, got %v", err)
	}
}

func TestValidate_RejectsZeroIPsFromResolver(t *testing.T) {
	r := stubResolver{ips: map[string][]net.IP{"weird.example.com": {}}}
	err := Validate("http://weird.example.com/", Config{Resolver: r})
	if err == nil || !errors.Is(err, ErrBlocked) {
		t.Fatalf("zero-IP resolution must be blocked, got %v", err)
	}
	if !strings.Contains(err.Error(), "zero IPs") {
		t.Errorf("expected zero-IPs reason, got %v", err)
	}
}

func TestValidate_AllowsPublicResolvedHost(t *testing.T) {
	r := stubResolver{ips: map[string][]net.IP{
		"public.example.com": {net.ParseIP("93.184.216.34")},
	}}
	if err := Validate("https://public.example.com/", Config{Resolver: r}); err != nil {
		t.Fatalf("genuine public host must be allowed, got %v", err)
	}
}

func TestValidate_AllowsPrivateWhenOptedIn(t *testing.T) {
	// The AllowPrivateNetworks opt-in early-returns in checkIP for a
	// loopback/private literal — exercised here to prove the opt-in path.
	if err := Validate("http://127.0.0.1/", Config{AllowPrivateNetworks: true}); err != nil {
		t.Fatalf("opt-in private must be allowed, got %v", err)
	}
	if err := Validate("http://10.0.0.5/", Config{AllowPrivateNetworks: true}); err != nil {
		t.Fatalf("opt-in RFC1918 must be allowed, got %v", err)
	}
}

func TestCheckIP_RejectionClasses(t *testing.T) {
	tests := []struct {
		name   string
		ip     string
		reason string
	}{
		// NOTE: Go's net.IP.IsPrivate() already covers fc00::/7, so ULAs are
		// rejected by the "private" branch before the dedicated ULA check.
		// What matters for SSRF safety is that they are BLOCKED — asserted here.
		{"ipv6 ULA fc00::/7", "fc00::1", "private"},
		{"ipv6 ULA fd00::/8", "fd12:3456:789a::1", "private"},
		{"ipv6 link-local unicast", "fe80::1", "link-local"},
		{"ipv6 link-local multicast", "ff02::1", "link-local"},
		{"ipv6 interface-local multicast", "ff01::1", "multicast"},
		{"ipv4 global multicast", "239.255.0.1", "multicast"},
		{"ipv4 unspecified", "0.0.0.0", "unspecified"},
		{"ipv6 unspecified", "::", "unspecified"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			if ip == nil {
				t.Fatalf("test setup: %q not parseable", tc.ip)
			}
			err := checkIP(ip, Config{})
			if err == nil || !errors.Is(err, ErrBlocked) {
				t.Fatalf("ip %q must be blocked, got %v", tc.ip, err)
			}
			if !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("ip %q: expected reason %q, got %v", tc.ip, tc.reason, err)
			}
		})
	}
}

// 0.0.0.0 / :: are caught earlier in Validate as the unspecified host literal;
// this confirms checkIP itself also rejects them defensively.
func TestCheckIP_AllowsGlobalUnicast(t *testing.T) {
	for _, s := range []string{"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"} {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("test setup: %q not parseable", s)
		}
		if err := checkIP(ip, Config{}); err != nil {
			t.Errorf("global unicast %q must be allowed, got %v", s, err)
		}
	}
}

// isIPv6UniqueLocal is defense-in-depth (net.IP.IsPrivate already covers
// fc00::/7 in checkIP), but the predicate itself must be correct. Covered
// directly so the function is exercised honestly rather than left as a
// never-reached branch.
func TestIsIPv6UniqueLocal(t *testing.T) {
	tests := []struct {
		ip   string
		want bool
	}{
		{"fc00::1", true},
		{"fd12:3456:789a::1", true},
		{"fe80::1", false},     // link-local, not ULA
		{"2001:db8::1", false}, // global
		{"127.0.0.1", false},   // IPv4 loopback — To4() != nil
		{"10.0.0.1", false},    // IPv4 private — not IPv6 ULA
	}
	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test setup: %q not parseable", tc.ip)
		}
		if got := isIPv6UniqueLocal(ip); got != tc.want {
			t.Errorf("isIPv6UniqueLocal(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
	// nil-safe: a non-16-byte slice must not panic and must be false.
	if isIPv6UniqueLocal(net.IP{0xfc}) {
		t.Error("malformed IP must not be classified as ULA")
	}
}

func TestParseIntegerIP_Bounds(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string // "" means expect nil (not an integer IP)
	}{
		{"loopback as int", "2130706433", "127.0.0.1"},
		{"non-digit", "12a4", ""},
		{"empty", "", ""},
		{"too long (>10 digits)", "12345678901", ""},
		{"overflow > uint32", "4294967296", ""},
		{"max uint32", "4294967295", "255.255.255.255"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseIntegerIP(tc.host)
			assertParsed(t, got, tc.want)
		})
	}
}

func TestParseShortDottedIP_Bounds(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"two-part", "127.1", "127.0.0.1"},
		{"three-part", "192.168.1", "192.168.0.1"},
		{"empty component", "127..1", ""},
		{"non-digit component", "127.x", ""},
		{"component overflow uint32 (>10 digits)", "127.99999999999", ""},
		{"component overflow uint32 (10 digits)", "1.9999999999", ""},
		{"leading octet > 255", "999.1", ""},
		{"two-part absorbing > 0xFFFFFF", "10.16777216", ""},
		{"three-part absorbing > 0xFFFF", "10.0.65536", ""},
		{"single part rejected (handled by IntegerIP)", "127", ""},
		{"four parts rejected", "1.2.3.4", ""},
		{"component too long", "1.12345678901", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseShortDottedIP(tc.host)
			assertParsed(t, got, tc.want)
		})
	}
}

func TestParseInetAtonIP_Bounds(t *testing.T) {
	tests := []struct {
		name string
		host string
		want string
	}{
		{"octal loopback", "0177.0.0.1", "127.0.0.1"},
		{"hex loopback last octet", "127.0.0.0x1", "127.0.0.1"},
		{"octal first octet (010 = 8 decimal)", "010.0.0.1", "8.0.0.1"},
		{"empty", "", ""},
		{"five parts", "1.2.3.4.5", ""},
		{"bare 0x part", "0x.0.0.1", ""},
		{"non-hex digit in hex part", "0xZ.0.0.1", ""},
		{"non-octal digit in octal part", "08.0.0.1", ""},
		{"leading octet overflow > 255", "256.0.0.1", ""},
		{"two-part absorbing overflow", "10.0x1000000", ""},   // > 0xFFFFFF
		{"three-part absorbing overflow", "10.0.0x10000", ""}, // > 0xFFFF
		{"four-part absorbing overflow", "10.0.0.0x100", ""},  // > 0xFF
		{"part overflow > uint32", "0x100000000.0.0.1", ""},
		{"two-part hex", "0x7f.0x1", "127.0.0.1"},
		{"uppercase hex octet", "0xFF.0.0.1", "255.0.0.1"},
		{"uppercase X prefix", "0X7F.0.0.1", "127.0.0.1"},
		{"single decimal part", "16777217", "1.0.0.1"},
		{"valid three-part", "10.0.5", "10.0.0.5"},
		{"empty middle part", "10..1", ""},
		{"hex-range digit in decimal part", "1a.0.0.1", ""},
		{"out-of-range char in part", "1g.0.0.1", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseInetAtonIP(tc.host)
			assertParsed(t, got, tc.want)
		})
	}
}

func assertParsed(t *testing.T, got net.IP, want string) {
	t.Helper()
	if want == "" {
		if got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
		return
	}
	if got == nil {
		t.Fatalf("expected %s, got nil", want)
	}
	if got.String() != want {
		t.Fatalf("expected %s, got %s", want, got.String())
	}
}
