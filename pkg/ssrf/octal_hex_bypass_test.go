// SPDX-FileCopyrightText: 2026 Milos Vasic
// SPDX-License-Identifier: Apache-2.0

package ssrf

import (
	"errors"
	"testing"
)

// TestValidate_BlocksOctalHexEncodedHosts is the reproduce-first RED test for the
// SSRF bypass where libc inet_aton(3) (used by cgo getaddrinfo and C-based
// dialers such as curl/wget) interprets octal- (leading 0) and hex- (leading 0x)
// prefixed dotted-quad octets, but the guard's ParseShortDottedIP /
// ParseIntegerIP only parse octets as DECIMAL. Such alternative encodings of
// loopback / private / metadata addresses slip past every literal-IP check and
// fall through to the DNS path, which a cgo resolver then dials internally.
//
// Each expected-IP below is the EXACT value real libc inet_aton produces for the
// host (verified against /usr/include/arpa/inet.h inet_aton on this host); every
// one is a loopback / private / metadata address the guard MUST block. The
// package doc promises: "canonicalise alternative IP encodings that libc/cgo can
// still dial" — octal and hex octets are exactly such encodings.
func TestValidate_BlocksOctalHexEncodedHosts(t *testing.T) {
	cases := []struct {
		url  string
		what string // inet_aton target
	}{
		{"http://0177.0.0.1/", "octal loopback -> 127.0.0.1"},
		{"http://0x7f.0.0.1/", "hex loopback -> 127.0.0.1"},
		{"http://0xa.0.0.1/", "hex private -> 10.0.0.1"},
		{"http://012.0.0.1/", "octal private -> 10.0.0.1 (012==10)"},
		{"http://0xa9fea9fe/", "hex 32-bit form (caught by ParseIntegerIP? no, has 0x)"},
		{"http://0xc0.0xa8.0.1/", "all-hex private -> 192.168.0.1"},
	}
	for _, c := range cases {
		err := Validate(c.url, Config{})
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s (%s): expected ErrBlocked, got err=%v -- SSRF BYPASS",
				c.url, c.what, err)
		}
	}
}
