package securestorage

import (
	"fmt"
	"sync"
	"testing"
)

// TestConcurrentRetrieve_NoDataRace proves the read-path methods are
// safe for concurrent callers. Retrieve/Contains/ListKeys take only an
// RLock, yet loadCache() (and getOrCreateKey()) mutate shared fields
// (fs.cache, fs.lastMod, fs.lastSize, fs.secretKey). Concurrent readers
// therefore write those fields simultaneously — a data race.
//
// RED on the pre-fix code under `go test -race`: the race detector
// reports a write/write (or read/write) data race on fs.cache /
// fs.lastMod / fs.lastSize / fs.secretKey. GREEN after the read-path
// methods are made genuinely concurrency-safe.
func TestConcurrentRetrieve_NoDataRace(t *testing.T) {
	dir := t.TempDir()
	fs := NewFileStorage(dir)

	// Seed several keys so loadCache has real content to parse.
	for i := 0; i < 20; i++ {
		if err := fs.Store(fmt.Sprintf("key-%d", i), fmt.Sprintf("value-%d", i)); err != nil {
			t.Fatalf("seed store: %v", err)
		}
	}

	// Force a cold cache so the FIRST concurrent reader path also has to
	// populate fs.cache/secretKey under RLock (the contended window).
	fs.cache = nil
	fs.secretKey = nil
	fs.lastMod = 0
	fs.lastSize = 0

	const readers = 32
	var wg sync.WaitGroup
	wg.Add(readers)
	for r := 0; r < readers; r++ {
		go func(r int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				key := fmt.Sprintf("key-%d", i)
				if _, err := fs.Retrieve(key); err != nil {
					t.Errorf("retrieve %s: %v", key, err)
					return
				}
				if _, err := fs.Contains(key); err != nil {
					t.Errorf("contains %s: %v", key, err)
					return
				}
				if _, err := fs.ListKeys(); err != nil {
					t.Errorf("listkeys: %v", err)
					return
				}
			}
		}(r)
	}
	wg.Wait()
}
