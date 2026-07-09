// SPDX-FileCopyrightText: 2026 Milos Vasic
// SPDX-License-Identifier: Apache-2.0

// Package ssrf is the canonical Server-Side Request Forgery guard
// for the digital.vasic.* ecosystem. It mirrors the
// tldrsec/awesome-secure-defaults "SSRF Defense" row: block private,
// loopback, link-local, metadata, ULA, multicast, and unspecified
// addresses by default; allow opt-in for trusted on-prem endpoints;
// canonicalise alternative IP encodings that libc/cgo can still dial.
//
// Consumers:
//   - catalog-api internal/services/ssrf_guard.go (Catalogizer)
//   - HelixQA pkg/nexus/ai/ssrf_guard.go
//
// Keep those copies in sync with this one. When either changes, port
// the change here and run both downstream test suites. A future
// refactor can migrate both consumers to import this package
// directly — until then, this file is the source of truth for the
// algorithm.
package ssrf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ErrBlocked is returned when the guard rejects a target URL. Wrap
// with fmt.Errorf("%w: <reason>", ErrBlocked) for a typed reason.
var ErrBlocked = errors.New("ssrf blocked")

// Config tunes guard behaviour. Zero value = safe defaults: public
// hosts only, http+https only.
type Config struct {
	// AllowPrivateNetworks lets requests reach RFC1918 / loopback /
	// link-local destinations. Only flip on for a trusted endpoint.
	AllowPrivateNetworks bool

	// AllowedSchemes lists accepted URI schemes. Empty = http+https.
	AllowedSchemes []string

	// Resolver overrides the default DNS resolver. Tests inject a
	// deterministic stub so they run offline.
	Resolver Resolver
}

// Resolver is the narrow DNS contract the guard needs. *net.Resolver
// and net.DefaultResolver both satisfy it via LookupIP.
type Resolver interface {
	LookupIP(network, host string) ([]net.IP, error)
}

type stdlibResolver struct{}

func (stdlibResolver) LookupIP(network, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(context.Background(), network, host)
}

// Validate parses target and runs every guard check. Returns
// ErrBlocked (wrapped with a reason) on rejection, nil on pass.
func Validate(target string, cfg Config) error {
	if target == "" {
		return fmt.Errorf("%w: empty url", ErrBlocked)
	}
	u, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("%w: parse: %v", ErrBlocked, err)
	}
	if err := validateScheme(u.Scheme, cfg); err != nil {
		return err
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrBlocked)
	}
	if host == "0.0.0.0" || host == "::" {
		return fmt.Errorf("%w: unspecified address %q", ErrBlocked, host)
	}

	// Direct IP literal — no DNS needed.
	if ip := net.ParseIP(host); ip != nil {
		return checkIP(ip, cfg)
	}

	// Alternative IP encodings libc/cgo can still dial even though
	// net.ParseIP rejects them. Catch before the DNS path.
	if ip := ParseIntegerIP(host); ip != nil {
		return checkIP(ip, cfg)
	}
	if ip := ParseShortDottedIP(host); ip != nil {
		return checkIP(ip, cfg)
	}
	// libc inet_aton (used by cgo getaddrinfo and tools like curl) accepts
	// octal- (leading 0) and hex- (leading 0x) prefixed octets in any of the
	// 1/2/3/4-part dotted forms. The decimal-only parsers above miss these, so
	// e.g. http://010.0.0.1/ (=10.0.0.1) or http://0177.0.0.1/ (=127.0.0.1)
	// would otherwise fall through to the DNS path and be dialled internally.
	if ip := ParseInetAtonIP(host); ip != nil {
		return checkIP(ip, cfg)
	}

	// Hostname path: resolve + reject if any returned IP is private.
	resolver := cfg.Resolver
	if resolver == nil {
		resolver = stdlibResolver{}
	}
	ips, lookupErr := resolver.LookupIP("ip", host)
	if lookupErr != nil {
		return fmt.Errorf("%w: lookup %s: %v", ErrBlocked, host, lookupErr)
	}
	if len(ips) == 0 {
		return fmt.Errorf("%w: host %q resolves to zero IPs", ErrBlocked, host)
	}
	for _, ip := range ips {
		if err := checkIP(ip, cfg); err != nil {
			return err
		}
	}
	return nil
}

func validateScheme(scheme string, cfg Config) error {
	scheme = strings.ToLower(scheme)
	allowed := cfg.AllowedSchemes
	if len(allowed) == 0 {
		allowed = []string{"http", "https"}
	}
	for _, s := range allowed {
		if scheme == strings.ToLower(s) {
			return nil
		}
	}
	return fmt.Errorf("%w: scheme %q not in allow list", ErrBlocked, scheme)
}

func checkIP(ip net.IP, cfg Config) error {
	if ip.IsUnspecified() {
		return fmt.Errorf("%w: unspecified address %s", ErrBlocked, ip)
	}
	// RFC 6052 NAT64 "Well-Known Prefix" (64:ff9b::/96) embeds an IPv4 address
	// in the low 32 bits of an IPv6 literal. On any NAT64/DNS64-enabled network
	// (common on IPv6-only corporate/carrier/cloud networks) the OS resolver
	// and dialer route such a literal transparently to the embedded IPv4
	// destination, so a literal that unwraps to loopback/private/link-local/
	// metadata must be judged by the SAME rules as its embedded address, not
	// treated as an ordinary global-unicast IPv6 address. This mirrors the
	// alternate-encoding handling ParseIntegerIP/ParseShortDottedIP/
	// ParseInetAtonIP already do for IPv4 literals.
	if embedded := unwrapNAT64(ip); embedded != nil {
		return checkIP(embedded, cfg)
	}
	if cfg.AllowPrivateNetworks {
		return nil
	}
	if ip.IsLoopback() {
		return fmt.Errorf("%w: loopback %s", ErrBlocked, ip)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: link-local %s", ErrBlocked, ip)
	}
	if ip.IsPrivate() {
		return fmt.Errorf("%w: private address %s", ErrBlocked, ip)
	}
	if isIPv6UniqueLocal(ip) {
		return fmt.Errorf("%w: ULA fc00::/7 %s", ErrBlocked, ip)
	}
	if ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return fmt.Errorf("%w: multicast %s", ErrBlocked, ip)
	}
	return nil
}

func isIPv6UniqueLocal(ip net.IP) bool {
	v6 := ip.To16()
	if v6 == nil || ip.To4() != nil {
		return false
	}
	return v6[0]&0xfe == 0xfc
}

// nat64WellKnownPrefix is the RFC 6052 §2.1 "Well-Known Prefix" 64:ff9b::/96
// used by NAT64/DNS64 to embed an IPv4 address in the low 32 bits of an IPv6
// address.
var nat64WellKnownPrefix = []byte{0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}

// unwrapNAT64 returns the embedded IPv4 address if ip lies in the RFC 6052
// NAT64 Well-Known Prefix range 64:ff9b::/96, or nil if ip is not a NAT64
// literal (including any ordinary IPv4 or IPv4-mapped-IPv6 address, which
// ip.To4() already resolves without this helper). Only the well-known prefix
// is decoded generically here — locally-configured Network-Specific Prefixes
// (RFC 6052 §3.1) are, by definition, not universally known and are out of
// scope for a project-agnostic guard.
func unwrapNAT64(ip net.IP) net.IP {
	if ip.To4() != nil {
		return nil // ordinary IPv4 or IPv4-mapped-IPv6; not a NAT64 literal
	}
	v6 := ip.To16()
	if v6 == nil || len(v6) != net.IPv6len {
		return nil
	}
	for i, b := range nat64WellKnownPrefix {
		if v6[i] != b {
			return nil
		}
	}
	return net.IPv4(v6[12], v6[13], v6[14], v6[15])
}

// ParseIntegerIP treats an all-digit host as a 32-bit IPv4 value
// (e.g. "2130706433" → 127.0.0.1). Returns nil on non-digit or
// uint32 overflow — safe against DNS names that end in digits.
func ParseIntegerIP(host string) net.IP {
	if host == "" || len(host) > 10 {
		return nil
	}
	var v uint64
	for _, r := range host {
		if r < '0' || r > '9' {
			return nil
		}
		v = v*10 + uint64(r-'0')
		if v > 0xFFFFFFFF {
			return nil
		}
	}
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// ParseInetAtonIP parses a host using the libc inet_aton(3) grammar that
// cgo getaddrinfo (and curl, wget, and most C-based dialers) honour: 1 to 4
// dot-separated parts, each part a C-style integer where a "0x"/"0X" prefix is
// hexadecimal, a leading "0" is octal, and anything else is decimal. The last
// part absorbs the remaining low-order bytes (a, a.b, a.b.c, a.b.c.d forms).
// Returns nil when host is not a valid inet_aton numeric address (e.g. a real
// DNS name, an empty/oversized part, an out-of-range value, or any non-digit in
// the chosen base) so genuine hostnames still take the DNS path.
//
// This catches octal/hex-encoded loopback, private, and metadata addresses that
// the decimal-only ParseShortDottedIP / ParseIntegerIP miss but that libc will
// still dial — closing the SSRF bypass those alternative encodings open.
func ParseInetAtonIP(host string) net.IP {
	if host == "" {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return nil
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		v, ok := parseCInt(p)
		if !ok {
			return nil
		}
		nums[i] = v
	}
	// Every part except the final absorbing part is a single octet (< 256).
	for i := 0; i < len(nums)-1; i++ {
		if nums[i] > 0xFF {
			return nil
		}
	}
	last := nums[len(nums)-1]
	var full uint64
	switch len(nums) {
	case 1:
		full = nums[0]
	case 2:
		// a.b : b is the low 24 bits.
		if last > 0xFFFFFF {
			return nil
		}
		full = nums[0]<<24 | last
	case 3:
		// a.b.c : c is the low 16 bits.
		if last > 0xFFFF {
			return nil
		}
		full = nums[0]<<24 | nums[1]<<16 | last
	case 4:
		// a.b.c.d : d is the low 8 bits.
		if last > 0xFF {
			return nil
		}
		full = nums[0]<<24 | nums[1]<<16 | nums[2]<<8 | last
	}
	if full > 0xFFFFFFFF {
		return nil
	}
	return net.IPv4(byte(full>>24), byte(full>>16), byte(full>>8), byte(full))
}

// parseCInt parses one inet_aton part with C strtoul base auto-detection:
// "0x"/"0X" prefix => hex, a leading "0" => octal, otherwise decimal. It returns
// ok=false on an empty part, a bare/garbage prefix, any digit invalid for the
// chosen base, or overflow beyond 32 bits (no single libc part exceeds that).
func parseCInt(p string) (uint64, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	digits := p
	switch {
	case len(p) >= 2 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'):
		base = 16
		digits = p[2:]
		if digits == "" { // bare "0x" is not a valid octet
			return 0, false
		}
	case len(p) >= 2 && p[0] == '0':
		base = 8
		digits = p[1:]
	}
	var v uint64
	for _, r := range digits {
		var d uint64
		switch {
		case r >= '0' && r <= '9':
			d = uint64(r - '0')
		case r >= 'a' && r <= 'f':
			d = uint64(r-'a') + 10
		case r >= 'A' && r <= 'F':
			d = uint64(r-'A') + 10
		default:
			return 0, false
		}
		if d >= uint64(base) {
			return 0, false
		}
		v = v*uint64(base) + d
		if v > 0xFFFFFFFF {
			return 0, false
		}
	}
	return v, true
}

// ParseShortDottedIP expands a two- or three-octet dotted form to
// the canonical four-octet IPv4 address. "127.1" → 127.0.0.1,
// "10.1" → 10.0.0.1, "192.168.1" → 192.168.0.1. Returns nil if the
// form isn't a short dotted IPv4 or any component is out of range.
func ParseShortDottedIP(host string) net.IP {
	parts := strings.Split(host, ".")
	if len(parts) != 2 && len(parts) != 3 {
		return nil
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		if p == "" || len(p) > 10 {
			return nil
		}
		var v uint64
		for _, r := range p {
			if r < '0' || r > '9' {
				return nil
			}
			v = v*10 + uint64(r-'0')
			if v > 0xFFFFFFFF {
				return nil
			}
		}
		nums[i] = v
	}
	for i := 0; i < len(nums)-1; i++ {
		if nums[i] > 0xFF {
			return nil
		}
	}
	var full uint64
	switch len(nums) {
	case 2:
		if nums[1] > 0xFFFFFF {
			return nil
		}
		full = nums[0]<<24 | nums[1]
	case 3:
		if nums[2] > 0xFFFF {
			return nil
		}
		full = nums[0]<<24 | nums[1]<<16 | nums[2]
	}
	return net.IPv4(byte(full>>24), byte(full>>16), byte(full>>8), byte(full))
}
