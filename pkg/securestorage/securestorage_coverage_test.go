package securestorage

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newCoverageTestStorage(t *testing.T) *FileStorage {
	t.Helper()
	dir := t.TempDir()
	return NewFileStorage(dir)
}

// TestStore_EnsureDirFailure tests Store when the storage directory cannot
// be created (e.g., parent is a file, not a directory).
func TestStore_EnsureDirFailure(t *testing.T) {
	// Create a file where the directory should be
	tmpDir := t.TempDir()
	conflictPath := filepath.Join(tmpDir, "conflict")
	require.NoError(t, os.WriteFile(conflictPath, []byte("file"), 0600))

	fs := NewFileStorage(filepath.Join(conflictPath, "subdir"))
	err := fs.Store("key", "value")
	assert.Error(t, err)
}

// TestRetrieve_NonExistentKey tests Retrieve when the key doesn't exist in
// the cache, covering the "key not found" path returning empty string.
func TestRetrieve_NonExistentKey(t *testing.T) {
	fs := newCoverageTestStorage(t)
	// Store one key then retrieve another
	require.NoError(t, fs.Store("key1", "value1"))
	val, err := fs.Retrieve("key2")
	require.NoError(t, err)
	assert.Equal(t, "", val)
}

// TestDelete_WithExistingData tests Delete when there is data persisted,
// then verifying the data file is updated.
func TestDelete_WithExistingData(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.Store("key1", "value1"))
	require.NoError(t, fs.Store("key2", "value2"))

	require.NoError(t, fs.Delete("key1"))

	// Verify key1 is gone
	val, err := fs.Retrieve("key1")
	require.NoError(t, err)
	assert.Equal(t, "", val)

	// Verify key2 still exists
	val, err = fs.Retrieve("key2")
	require.NoError(t, err)
	assert.Equal(t, "value2", val)
}

// TestContains_WithEmptyStorage tests Contains on a fresh storage with no data.
func TestContains_WithEmptyStorage(t *testing.T) {
	fs := newCoverageTestStorage(t)
	exists, err := fs.Contains("anything")
	require.NoError(t, err)
	assert.False(t, exists)
}

// TestListKeys_EmptyStorage tests ListKeys on an empty storage.
func TestListKeys_EmptyStorage(t *testing.T) {
	fs := newCoverageTestStorage(t)
	keys, err := fs.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestClear_WhenNoDataFileExists tests Clear when there is no data file.
func TestClear_WhenNoDataFileExists(t *testing.T) {
	fs := newCoverageTestStorage(t)
	// Clear on empty storage should succeed
	err := fs.Clear()
	assert.NoError(t, err)
}

// TestClear_WhenDataFileExists tests Clear removes the data file.
func TestClear_WhenDataFileExists(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.Store("key", "value"))

	// Verify data file exists
	_, err := os.Stat(fs.dataFile)
	require.NoError(t, err)

	// Clear should remove it
	require.NoError(t, fs.Clear())

	// Data file should be gone
	_, err = os.Stat(fs.dataFile)
	assert.True(t, os.IsNotExist(err))
}

// TestIsSecure_WhenDirCannotBeCreated tests IsSecure when ensureDir fails.
func TestIsSecure_WhenDirCannotBeCreated(t *testing.T) {
	tmpDir := t.TempDir()
	conflictPath := filepath.Join(tmpDir, "conflict")
	require.NoError(t, os.WriteFile(conflictPath, []byte("file"), 0600))

	fs := NewFileStorage(filepath.Join(conflictPath, "subdir"))
	secure, err := fs.IsSecure()
	require.NoError(t, err)
	assert.False(t, secure)
}

// TestGetOrCreateKey_ExistingKeyFile tests getOrCreateKey when a valid key
// file already exists on disk (not in memory cache).
func TestGetOrCreateKey_ExistingKeyFile(t *testing.T) {
	fs := newCoverageTestStorage(t)
	// First call creates the key
	require.NoError(t, fs.Store("key", "value"))

	// Create a new FileStorage pointing to the same directory
	fs2 := NewFileStorage(fs.storageDir)
	// getOrCreateKey should read from the key file
	val, err := fs2.Retrieve("key")
	require.NoError(t, err)
	assert.Equal(t, "value", val)
}

// TestGetOrCreateKey_CachedKey tests getOrCreateKey when the secret key is
// already cached in memory.
func TestGetOrCreateKey_CachedKey(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.Store("key1", "value1"))

	// The key is now cached. Storing again should use the cached key.
	require.NoError(t, fs.Store("key2", "value2"))

	val, err := fs.Retrieve("key2")
	require.NoError(t, err)
	assert.Equal(t, "value2", val)
}

// TestLoadCache_NonExistentDataFile tests loadCache when the data file does
// not exist yet and cache is nil.
func TestLoadCache_NonExistentDataFile(t *testing.T) {
	fs := newCoverageTestStorage(t)
	// Directly call operations that trigger loadCache
	keys, err := fs.ListKeys()
	require.NoError(t, err)
	assert.Empty(t, keys)
}

// TestLoadCache_CacheHit tests loadCache when the cache is valid and the
// file hasn't been modified (mod time + size match).
func TestLoadCache_CacheHit(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.Store("key", "value"))

	// First read populates the cache
	val, err := fs.Retrieve("key")
	require.NoError(t, err)
	assert.Equal(t, "value", val)

	// Second read should hit the cache (same mod time and size)
	val, err = fs.Retrieve("key")
	require.NoError(t, err)
	assert.Equal(t, "value", val)
}

// TestLoadCache_StatError tests loadCache when os.Stat returns a non-NotExist
// error. We simulate this by making the data file path a directory.
func TestLoadCache_StatError(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.Store("key", "value"))

	// Now remove the data file and create a directory with the same name
	// that has permissions preventing stat (not easily done). Instead,
	// let's test that invalid data file paths are handled.
	// Remove data file and replace it with something broken
	os.Remove(fs.dataFile)
	os.MkdirAll(fs.dataFile, 0700) // data file path is now a directory

	// Invalidate cache to force re-read
	fs.cache = nil
	fs.lastMod = 0
	fs.lastSize = 0

	// readData should fail to read a directory
	_, err := fs.Retrieve("key")
	// Should get an error because we can't read a directory as a file
	// or it should handle gracefully
	// Actually, os.ReadFile on a directory returns an error
	assert.Error(t, err)
}

// TestReadData_EmptyFile tests readData when the data file is empty.
func TestReadData_EmptyFile(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.ensureDir())
	require.NoError(t, os.WriteFile(fs.dataFile, []byte{}, 0600))

	fs.cache = nil
	fs.lastMod = 0
	fs.lastSize = 0

	val, err := fs.Retrieve("key")
	require.NoError(t, err)
	assert.Equal(t, "", val)
}

// TestReadData_MalformedLines tests readData with malformed lines (no
// separator, invalid hex).
func TestReadData_MalformedLines(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.ensureDir())

	// Write data with various malformed lines
	content := "noseparator\n" +
		"invalidhex|somevalue\n" +
		hex.EncodeToString([]byte("valid")) + "|validvalue\n" +
		"\n" // empty line
	require.NoError(t, os.WriteFile(fs.dataFile, []byte(content), 0600))

	// Create a key so getOrCreateKey works
	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(fs.keyFile, key, 0600))

	fs.cache = nil
	fs.lastMod = 0
	fs.lastSize = 0

	// Contains should still work - malformed lines are skipped
	exists, err := fs.Contains("valid")
	require.NoError(t, err)
	assert.True(t, exists)
}

// TestPersist_UpdatesModTimeAndSize tests that persist updates lastMod and
// lastSize after writing.
func TestPersist_UpdatesModTimeAndSize(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.Store("key", "value"))
	assert.NotZero(t, fs.lastMod)
	assert.NotZero(t, fs.lastSize)
}

// TestEncrypt_InvalidKeyLength tests encrypt with a key that's too short
// for AES-256, covering the error branch.
func TestEncrypt_InvalidKeyLength(t *testing.T) {
	_, err := encrypt("plaintext", []byte("short"))
	assert.Error(t, err)
}

// TestDecrypt_InvalidBase64 tests decrypt with invalid base64 input.
func TestDecrypt_InvalidBase64(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	_, err := decrypt("not-valid-base64!@#$", key)
	assert.Error(t, err)
}

// TestDecrypt_InvalidKeyLength tests decrypt with a key that's too short.
func TestDecrypt_InvalidKeyLength(t *testing.T) {
	_, err := decrypt(base64.StdEncoding.EncodeToString([]byte("data")), []byte("short"))
	assert.Error(t, err)
}

// TestDecrypt_CiphertextTooShort tests decrypt when the ciphertext is
// shorter than the nonce size.
func TestDecrypt_CiphertextTooShort(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	// Encode very short data that's less than nonce size (12 bytes for GCM)
	shortData := base64.StdEncoding.EncodeToString([]byte("tiny"))
	_, err := decrypt(shortData, key)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

// TestDecrypt_TamperedCiphertext tests decrypt with valid-length but tampered
// ciphertext, which should fail authentication.
func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	// First encrypt something valid
	encrypted, err := encrypt("hello", key)
	require.NoError(t, err)

	// Decode, tamper, re-encode
	data, err := base64.StdEncoding.DecodeString(encrypted)
	require.NoError(t, err)
	// Tamper with the last byte
	data[len(data)-1] ^= 0xFF
	tampered := base64.StdEncoding.EncodeToString(data)

	_, err = decrypt(tampered, key)
	assert.Error(t, err)
}

// TestRetrieveCredentials_EmptyData tests RetrieveCredentials when there
// are no stored credentials.
func TestRetrieveCredentials_EmptyData(t *testing.T) {
	fs := newCoverageTestStorage(t)
	u, p, err := fs.RetrieveCredentials("nonexistent")
	require.NoError(t, err)
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)
}

// TestRetrieveCredentials_InvalidFormat_NoColon tests RetrieveCredentials
// with data that has no colon separator.
func TestRetrieveCredentials_InvalidFormat_NoColon(t *testing.T) {
	fs := newCoverageTestStorage(t)
	// Store raw data without the expected format
	require.NoError(t, fs.Store("test_credentials", "no-colon-here"))

	u, p, err := fs.RetrieveCredentials("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credential format")
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)
}

// TestRetrieveCredentials_InvalidFormat_BadLength tests RetrieveCredentials
// when the username length prefix is not a number.
func TestRetrieveCredentials_InvalidFormat_BadLength(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.Store("test_credentials", "abc:data"))

	u, p, err := fs.RetrieveCredentials("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credential format")
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)
}

// TestRetrieveCredentials_InvalidFormat_LengthExceedsData tests
// RetrieveCredentials when the username length exceeds available data.
func TestRetrieveCredentials_InvalidFormat_LengthExceedsData(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.Store("test_credentials", "100:ab"))

	u, p, err := fs.RetrieveCredentials("test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credential format")
	assert.Equal(t, "", u)
	assert.Equal(t, "", p)
}

// TestCopyMap_EmptyMap tests copyMap with an empty map.
func TestCopyMap_EmptyMap(t *testing.T) {
	m := make(map[string]string)
	result := copyMap(m)
	assert.NotNil(t, result)
	assert.Len(t, result, 0)
}

// TestCopyMap_Isolation tests that copyMap creates an independent copy.
func TestCopyMap_Isolation(t *testing.T) {
	m := map[string]string{"a": "1", "b": "2"}
	result := copyMap(m)
	result["c"] = "3"
	assert.Len(t, m, 2)      // Original unchanged
	assert.Len(t, result, 3) // Copy has new entry
}

// TestPersist_EnsureDirFailure tests persist when the directory cannot be
// created.
func TestPersist_EnsureDirFailure(t *testing.T) {
	tmpDir := t.TempDir()
	conflictPath := filepath.Join(tmpDir, "conflict")
	require.NoError(t, os.WriteFile(conflictPath, []byte("file"), 0600))

	fs := NewFileStorage(filepath.Join(conflictPath, "subdir"))
	// Set up key manually to avoid ensureDir issues in getOrCreateKey
	fs.secretKey = make([]byte, 32)
	fs.cache = map[string]string{"key": "value"}

	err := fs.persist(fs.cache)
	assert.Error(t, err)
}

// TestGetOrCreateKey_KeyFileReadError tests getOrCreateKey when the key file
// exists but cannot be read.
func TestGetOrCreateKey_KeyFileReadError(t *testing.T) {
	fs := newCoverageTestStorage(t)
	require.NoError(t, fs.ensureDir())

	// Create a key file as a directory (which can't be read as a file)
	require.NoError(t, os.MkdirAll(fs.keyFile, 0700))

	_, err := fs.getOrCreateKey()
	assert.Error(t, err)
}

// TestIsSecure_FullPath tests IsSecure performing the full encrypt/decrypt
// round trip on a valid storage.
func TestIsSecure_FullPath(t *testing.T) {
	fs := newCoverageTestStorage(t)
	secure, err := fs.IsSecure()
	require.NoError(t, err)
	assert.True(t, secure)
}

// TestMultipleStoresAndRetrieves tests multiple sequential stores and
// retrievals to exercise the cache invalidation and reload paths.
func TestMultipleStoresAndRetrieves(t *testing.T) {
	fs := newCoverageTestStorage(t)
	for i := 0; i < 10; i++ {
		key := "key" + string(rune('0'+i))
		value := "value" + string(rune('0'+i))
		require.NoError(t, fs.Store(key, value))
	}

	for i := 0; i < 10; i++ {
		key := "key" + string(rune('0'+i))
		expected := "value" + string(rune('0'+i))
		val, err := fs.Retrieve(key)
		require.NoError(t, err)
		assert.Equal(t, expected, val)
	}
}
