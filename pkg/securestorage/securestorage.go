package securestorage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Storage defines the interface for secure key-value storage.
type Storage interface {
	Store(key, value string) error
	Retrieve(key string) (string, error)
	Delete(key string) error
	Contains(key string) (bool, error)
	ListKeys() ([]string, error)
	Clear() error
	IsSecure() (bool, error)
}

// FileStorage implements Storage using AES-256-GCM encrypted file storage.
type FileStorage struct {
	mu         sync.RWMutex
	storageDir string
	keyFile    string
	dataFile   string
	cache      map[string]string
	secretKey  []byte
	lastMod    int64
	lastSize   int64
}

// NewFileStorage creates a new FileStorage at the given directory.
func NewFileStorage(storageDir string) *FileStorage {
	return &FileStorage{
		storageDir: storageDir,
		keyFile:    filepath.Join(storageDir, ".storage_key"),
		dataFile:   filepath.Join(storageDir, ".secure_storage"),
	}
}

func (fs *FileStorage) Store(key, value string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := fs.ensureDir(); err != nil {
		return err
	}
	secretKey, err := fs.getOrCreateKey()
	if err != nil {
		return err
	}
	encrypted, err := encrypt(value, secretKey)
	if err != nil {
		return err
	}
	data, err := fs.loadCache()
	if err != nil {
		return err
	}
	data[key] = encrypted
	fs.cache = data
	return fs.persist(data)
}

func (fs *FileStorage) Retrieve(key string) (string, error) {
	// Write lock (not RLock): getOrCreateKey + loadCache mutate shared
	// state (fs.secretKey, fs.cache, fs.lastMod, fs.lastSize). Holding
	// only an RLock here lets concurrent readers write those fields
	// simultaneously — a data race that can corrupt the cached key/state.
	fs.mu.Lock()
	defer fs.mu.Unlock()

	secretKey, err := fs.getOrCreateKey()
	if err != nil {
		return "", err
	}
	data, err := fs.loadCache()
	if err != nil {
		return "", err
	}
	encrypted, ok := data[key]
	if !ok {
		return "", nil
	}
	return decrypt(encrypted, secretKey)
}

func (fs *FileStorage) Delete(key string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := fs.loadCache()
	if err != nil {
		return err
	}
	delete(data, key)
	fs.cache = data
	return fs.persist(data)
}

func (fs *FileStorage) Contains(key string) (bool, error) {
	// Write lock (not RLock): loadCache mutates fs.cache/lastMod/lastSize.
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := fs.loadCache()
	if err != nil {
		return false, err
	}
	_, ok := data[key]
	return ok, nil
}

func (fs *FileStorage) ListKeys() ([]string, error) {
	// Write lock (not RLock): loadCache mutates fs.cache/lastMod/lastSize.
	fs.mu.Lock()
	defer fs.mu.Unlock()

	data, err := fs.loadCache()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	return keys, nil
}

func (fs *FileStorage) Clear() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fs.cache = make(map[string]string)
	if _, err := os.Stat(fs.dataFile); err == nil {
		return os.Remove(fs.dataFile)
	}
	return nil
}

func (fs *FileStorage) IsSecure() (bool, error) {
	// Lock: getOrCreateKey mutates fs.secretKey, which must not race with
	// concurrent Store/Retrieve/etc.
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := fs.ensureDir(); err != nil {
		return false, nil
	}
	secretKey, err := fs.getOrCreateKey()
	if err != nil {
		return false, nil
	}
	testData := "secure_test_check"
	encrypted, err := encrypt(testData, secretKey)
	if err != nil {
		return false, nil
	}
	decrypted, err := decrypt(encrypted, secretKey)
	if err != nil {
		return false, nil
	}
	return decrypted == testData, nil
}

// StoreCredentials stores username and password using length-prefixed format.
func (fs *FileStorage) StoreCredentials(service, username, password string) error {
	data := fmt.Sprintf("%d:%s%s", len(username), username, password)
	return fs.Store(service+"_credentials", data)
}

// RetrieveCredentials retrieves stored credentials.
func (fs *FileStorage) RetrieveCredentials(service string) (username, password string, err error) {
	data, err := fs.Retrieve(service + "_credentials")
	if err != nil || data == "" {
		return "", "", err
	}
	colonIdx := strings.Index(data, ":")
	if colonIdx < 0 {
		return "", "", fmt.Errorf("invalid credential format")
	}
	var usernameLen int
	if _, err := fmt.Sscanf(data[:colonIdx], "%d", &usernameLen); err != nil {
		return "", "", fmt.Errorf("invalid credential format: %w", err)
	}
	// Guard the length on BOTH ends before slicing: a negative prefix (e.g.
	// "-1:abc") passes the upper-bound check (len(rest) < -1 is false) and
	// then panics at rest[:usernameLen] with "slice bounds out of range".
	// Reject negative and over-long lengths with a clean error, never a panic.
	rest := data[colonIdx+1:]
	if usernameLen < 0 || usernameLen > len(rest) {
		return "", "", fmt.Errorf("invalid credential format")
	}
	return rest[:usernameLen], rest[usernameLen:], nil
}

// StoreToken stores an access token for a service.
func (fs *FileStorage) StoreToken(service, token string) error {
	return fs.Store(service+"_token", token)
}

// RetrieveToken retrieves a stored token.
func (fs *FileStorage) RetrieveToken(service string) (string, error) {
	return fs.Retrieve(service + "_token")
}

// StorePrivateKey stores a private key for a service.
func (fs *FileStorage) StorePrivateKey(service, privateKey string) error {
	return fs.Store(service+"_private_key", privateKey)
}

// RetrievePrivateKey retrieves a stored private key.
func (fs *FileStorage) RetrievePrivateKey(service string) (string, error) {
	return fs.Retrieve(service + "_private_key")
}

func (fs *FileStorage) ensureDir() error {
	return os.MkdirAll(fs.storageDir, 0700)
}

func (fs *FileStorage) getOrCreateKey() ([]byte, error) {
	if fs.secretKey != nil {
		return fs.secretKey, nil
	}
	if info, err := os.Stat(fs.keyFile); err == nil && info.Size() > 0 {
		key, err := os.ReadFile(fs.keyFile)
		if err != nil {
			return nil, err
		}
		fs.secretKey = key
		return key, nil
	}
	if err := fs.ensureDir(); err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(fs.keyFile, key, 0600); err != nil {
		return nil, err
	}
	fs.secretKey = key
	return key, nil
}

func (fs *FileStorage) loadCache() (map[string]string, error) {
	info, err := os.Stat(fs.dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			if fs.cache == nil {
				fs.cache = make(map[string]string)
			}
			return copyMap(fs.cache), nil
		}
		return nil, err
	}
	mod := info.ModTime().UnixNano()
	size := info.Size()
	if fs.cache != nil && mod == fs.lastMod && size == fs.lastSize {
		return copyMap(fs.cache), nil
	}
	data, err := fs.readData()
	if err != nil {
		return nil, err
	}
	fs.cache = data
	fs.lastMod = mod
	fs.lastSize = size
	return copyMap(data), nil
}

func (fs *FileStorage) readData() (map[string]string, error) {
	content, err := os.ReadFile(fs.dataFile)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, err
	}
	if len(content) == 0 {
		return make(map[string]string), nil
	}
	result := make(map[string]string)
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" {
			continue
		}
		sepIdx := strings.Index(line, "|")
		if sepIdx < 0 {
			continue
		}
		keyBytes, err := hex.DecodeString(line[:sepIdx])
		if err != nil {
			continue
		}
		result[string(keyBytes)] = line[sepIdx+1:]
	}
	return result, nil
}

func (fs *FileStorage) persist(data map[string]string) error {
	if err := fs.ensureDir(); err != nil {
		return err
	}
	var sb strings.Builder
	for k, v := range data {
		sb.WriteString(hex.EncodeToString([]byte(k)))
		sb.WriteByte('|')
		sb.WriteString(v)
		sb.WriteByte('\n')
	}
	if err := os.WriteFile(fs.dataFile, []byte(sb.String()), 0600); err != nil {
		return err
	}
	info, err := os.Stat(fs.dataFile)
	if err == nil {
		fs.lastMod = info.ModTime().UnixNano()
		fs.lastSize = info.Size()
	}
	return nil
}

func encrypt(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decrypt(encoded string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := aesGCM.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func copyMap(m map[string]string) map[string]string {
	result := make(map[string]string, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}
