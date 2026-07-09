package ssrf

import (
	"net"
	"testing"
)

// TestValidate_BlocksNAT64EncodedLoopbackAndMetadata is the permanent
// regression guard for an SSRF-guard bypass found by security audit
// (2026-07-10): the guard decodes several alternative IPv4 textual encodings
// that libc/cgo dialers accept (all-integer, short-dotted, and the full
// inet_aton octal/hex grammar -- see ParseIntegerIP / ParseShortDottedIP /
// ParseInetAtonIP), but never unwrapped the RFC 6052 "Well-Known Prefix"
// (64:ff9b::/96) used by NAT64/DNS64 to embed an IPv4 address inside an IPv6
// literal.
//
// On any host reachable via a NAT64 gateway (common on IPv6-only corporate,
// mobile-carrier, and cloud networks that run DNS64/NAT64 for legacy-v4
// reachability -- e.g. GCP's IPv6-only subnets, many mobile carriers, and
// Happy-Eyeballs-style dual-stack fallbacks), the OS resolver/dialer routes a
// literal like "64:ff9b::a9fe:a9fe" transparently to 169.254.169.254 (a
// canonical cloud metadata / credential-theft SSRF target) or
// "64:ff9b::7f00:1" to 127.0.0.1 (loopback). Before this fix, Validate/checkIP
// parsed these as ordinary global-unicast IPv6 literals (net.IP's IsPrivate /
// IsLoopback / IsLinkLocalUnicast do NOT recognize the NAT64 prefix -- only
// the ::ffff:0:0/96 "IPv4-mapped" prefix is v4-aware in the stdlib) and let
// them straight through as "public", exactly the class of alternate-encoding
// bypass every other Parse*IP helper in this file exists to close.
//
// MUTATION THAT FAILS THIS: remove the unwrapNAT64 call from checkIP (or the
// unwrapNAT64 function itself) -- both cases below revert to ErrBlocked==nil
// (ALLOWED), failing the "must be blocked" assertions.
func TestValidate_BlocksNAT64EncodedLoopbackAndMetadata(t *testing.T) {
	cases := []struct {
		name   string
		host   string // NAT64 (64:ff9b::/96) literal
		embeds string // the IPv4 address it decodes to, for the failure message
	}{
		{"nat64-loopback", "64:ff9b::7f00:1", "127.0.0.1"},
		{"nat64-cloud-metadata", "64:ff9b::a9fe:a9fe", "169.254.169.254 (cloud metadata)"},
		{"nat64-rfc1918-10", "64:ff9b::a00:1", "10.0.0.1"},
		{"nat64-rfc1918-192-168", "64:ff9b::c0a8:1", "192.168.0.1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := "http://[" + tc.host + "]/"
			err := Validate(target, Config{})
			if err == nil {
				t.Fatalf("CRITICAL SSRF BYPASS: Validate(%q) allowed a NAT64-encoded "+
					"address that unwraps to %s -- the guard treated it as public IPv6",
					target, tc.embeds)
			}
			t.Logf("blocked NAT64-encoded %s (%s): %v", tc.host, tc.embeds, err)
		})
	}
}

// TestValidate_AllowsGenuineGlobalUnicastIPv6NotInNAT64Range proves the fix is
// scoped precisely to the 64:ff9b::/96 well-known prefix and does not
// misclassify ordinary global-unicast IPv6 addresses (including ones that
// happen to share the leading "64:" group) as NAT64-encoded.
func TestValidate_AllowsGenuineGlobalUnicastIPv6NotInNAT64Range(t *testing.T) {
	cases := []string{
		"2001:4860:4860::8888", // Google public DNS, genuine global unicast
		"64:ff9c::7f00:1",      // one bit off the well-known prefix -- must NOT unwrap
		"164:ff9b::7f00:1",     // different prefix entirely
	}
	for _, host := range cases {
		ip := net.ParseIP(host)
		if ip == nil {
			t.Fatalf("test setup error: %q did not parse as an IP", host)
		}
		if err := checkIP(ip, Config{}); err != nil {
			t.Fatalf("checkIP(%q) unexpectedly blocked a genuine global-unicast address: %v", host, err)
		}
	}
}
