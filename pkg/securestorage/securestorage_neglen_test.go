package securestorage

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// §11.4.43/§11.4.115 RED-baseline → GREEN-guard for the negative/malformed
// username-length panic in RetrieveCredentials.
//
// REAL DEFECT (reproduced): a credential blob whose username-length prefix is
// NEGATIVE (e.g. "-1:abc") passes the parser's only guard (the UPPER bound
// `len(rest) < usernameLen`, which is `3 < -1 == false`) and then panics at
// `rest[:usernameLen]` with "slice bounds out of range [:-1]". This is a
// DoS/panic on a public credential-parsing API for corrupted/crafted stored
// data. The fix rejects any negative length (and the symmetric trailing-junk
// case) with a clean error instead of panicking.
//
// Each sub-case calls RetrieveCredentials through the real Store→Retrieve
// (AES-256-GCM) round-trip, so the crafted blob travels the exact production
// decrypt path. Pre-fix these cases PANIC; post-fix they return a clean error.

func TestRetrieveCredentials_NegativeLength_ErrorsNotPanic(t *testing.T) {
	cases := []struct {
		name string
		blob string
	}{
		{"negative one", "-1:abc"},
		{"negative large", "-100:abc"},
		{"negative zero-ish", "-0:abc"}, // strconv/Sscanf parses "-0" as 0; must still round-trip safely
		{"negative with empty rest", "-5:"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fs := NewFileStorage(dir)
			require.NoError(t, fs.Store("svc_credentials", tc.blob))

			// MUST NOT panic. Pre-fix this line panics with
			// "slice bounds out of range [:-1]".
			u, p, err := fs.RetrieveCredentials("svc")

			if tc.blob == "-0:abc" {
				// "-0" == 0: a valid zero-length username, must round-trip
				// cleanly (username empty, password "abc") — no panic, no error.
				require.NoError(t, err)
				assert.Equal(t, "", u)
				assert.Equal(t, "abc", p)
				return
			}
			require.Error(t, err, "negative username-length prefix must error, not panic")
		})
	}
}

// TestRetrieveCredentials_ValidStillRoundTrips guards against the fix
// over-rejecting valid blobs — happy-path behaviour must be unchanged.
func TestRetrieveCredentials_ValidStillRoundTrips(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	require.NoError(t, fs.StoreCredentials("svc", "bob", "secret:value"))
	u, p, err := fs.RetrieveCredentials("svc")
	require.NoError(t, err)
	assert.Equal(t, "bob", u)
	assert.Equal(t, "secret:value", p)
}
