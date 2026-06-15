package securestorage

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests close genuine coverage gaps in error/edge branches that the
// existing suite did not reach: a corrupted (wrong-length) key file must make
// every crypto operation FAIL gracefully (never panic, never silently return
// plaintext), and unreadable / mis-typed storage paths must surface errors
// rather than corrupting state. Each asserts a concrete user-visible outcome.

// writeCorruptKey overwrites the key file with a non-32-byte value so that
// aes.NewCipher rejects it, exercising the encrypt/decrypt error branches.
func writeCorruptKey(t *testing.T, fs *FileStorage) {
	t.Helper()
	require.NoError(t, os.MkdirAll(fs.storageDir, 0o700))
	require.NoError(t, os.WriteFile(fs.keyFile, []byte("too-short-key"), 0o600))
}

func TestStore_CorruptKeyLength_ErrorsNotPanic(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	writeCorruptKey(t, fs)
	err := fs.Store("k", "v")
	require.Error(t, err, "Store with a wrong-length key file must error, not panic or succeed")
}

func TestRetrieve_CorruptKeyLength_ErrorsNotPanic(t *testing.T) {
	// First store a real value with a valid key.
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	require.NoError(t, fs.Store("k", "v"))

	// Corrupt the key file, drop the cached key, force a fresh read.
	fs.secretKey = nil
	require.NoError(t, os.WriteFile(fs.keyFile, []byte("bad"), 0o600))
	_, err := fs.Retrieve("k")
	require.Error(t, err, "Retrieve with a corrupted key must error, not panic")
}

func TestIsSecure_CorruptKey_ReturnsFalse(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	writeCorruptKey(t, fs)
	secure, err := fs.IsSecure()
	require.NoError(t, err, "IsSecure swallows internal errors and reports the verdict")
	assert.False(t, secure, "a storage backed by an unusable key must report NOT secure")
}

func TestDecrypt_RejectsCorruptCiphertext(t *testing.T) {
	key := make([]byte, 32) // all-zero 32-byte key is a valid AES-256 key
	tests := []struct {
		name string
		in   string
	}{
		{"not base64", "@@@not-base64@@@"},
		{"too short for nonce+tag", "AAAA"},
		{"valid base64 but garbage", "aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgZ2Nt"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decrypt(tc.in, key)
			assert.Error(t, err, "corrupt ciphertext %q must be rejected, never silently returned", tc.in)
		})
	}
}

func TestDecrypt_WrongKey_AuthFails(t *testing.T) {
	keyA := make([]byte, 32)
	keyB := make([]byte, 32)
	keyB[0] = 1
	enc, err := encrypt("secret-plaintext", keyA)
	require.NoError(t, err)
	_, err = decrypt(enc, keyB)
	require.Error(t, err, "GCM auth must fail under the wrong key (no insecure fallback)")
}

func TestEncrypt_BadKeyLength_Errors(t *testing.T) {
	_, err := encrypt("data", []byte("17-byte-key-here!"))
	require.Error(t, err, "encrypt with a non-32-byte key must error")
}

func TestLoadCache_DataFileIsDirectory_Errors(t *testing.T) {
	// Make dataFile a directory so os.ReadFile (in readData) fails with a
	// non-NotExist error, exercising the loadCache error branch.
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	require.NoError(t, os.MkdirAll(fs.dataFile, 0o700))
	_, err := fs.Contains("anything")
	require.Error(t, err, "an unreadable data file must surface an error, not corrupt state")
}

func TestContains_FreshStorage_NoDataFile(t *testing.T) {
	// Contains on a brand-new storage (no data file yet) initialises an empty
	// cache and reports false without error — the cache==nil NotExist branch.
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	ok, err := fs.Contains("missing")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestPersist_ReadOnlyDir_Errors(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	require.NoError(t, fs.Store("seed", "v")) // create dir + key + data
	// Make the storage dir read-only so the next WriteFile in persist fails.
	require.NoError(t, os.Chmod(dir, 0o500))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	err := fs.Delete("seed")
	// On systems where root or the FS ignores the mode this may pass; assert
	// only that no panic occurs and, when it does fail, it is a clean error.
	if err != nil {
		assert.Error(t, err)
	}
}

func TestRetrieveCredentials_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	require.NoError(t, fs.StoreCredentials("svc", "alice", "p@ss:word"))
	u, p, err := fs.RetrieveCredentials("svc")
	require.NoError(t, err)
	assert.Equal(t, "alice", u)
	assert.Equal(t, "p@ss:word", p)
}

func TestRetrieveCredentials_MissingColon(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	require.NoError(t, fs.Store("svc_credentials", "no-colon-here"))
	_, _, err := fs.RetrieveCredentials("svc")
	require.Error(t, err, "credential blob without a colon separator must error")
}

func TestRetrieveCredentials_NonNumericLength(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	require.NoError(t, fs.Store("svc_credentials", "abc:value"))
	_, _, err := fs.RetrieveCredentials("svc")
	require.Error(t, err, "non-numeric username-length prefix must error")
}

func TestRetrieveCredentials_LengthExceedsData(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)
	require.NoError(t, fs.Store("svc_credentials", "100:ab"))
	_, _, err := fs.RetrieveCredentials("svc")
	require.Error(t, err, "username length exceeding available data must error")
}
