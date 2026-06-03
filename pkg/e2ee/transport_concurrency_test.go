package e2ee

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// TestTransportConcurrentRoundTripWithOversizeInjection is the HXC-1567 closure:
// many concurrent round-trips OVER THE FRAMED Transport (WriteRecord ->
// ReadRecord) complete intact while, concurrently, an injected oversize length
// prefix is rejected by the reader's guard — all under -race.
//
// This complements the existing Session-level TestConcurrentSealOpen and the
// single-threaded TestTransportRejectsOversizeLength by exercising the framing
// layer (length prefix + maxRecv guard) under concurrency in one test.
//
// MUTATION THAT FAILS THIS: drop the oversize guard in ReadRecord (change
// `if n == 0 || n > t.maxRecv` to `if n == 0`) — the oversize injection arm
// then reads a 5 MiB body instead of returning ErrRecordTooLarge.
func TestTransportConcurrentRoundTripWithOversizeInjection(t *testing.T) {
	const workers = 16
	const each = 50

	// Pre-build all session pairs on the test goroutine: handshake uses t.Fatalf,
	// which must not be called from a spawned goroutine.
	type pair struct{ i, r *Session }
	pairs := make([]pair, workers)
	for w := range pairs {
		i, r := handshake(t, SessionConfig{CounterNonce: true})
		pairs[w] = pair{i, r}
	}
	_, oversizeReader := handshake(t, SessionConfig{})

	var wg sync.WaitGroup
	errCh := make(chan error, workers+1)

	// Well-formed concurrent round-trips, one independent framed Transport pair
	// per worker (each worker owns its own buffer + session pair).
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int, p pair) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				var buf bytes.Buffer
				wt := NewTransport(p.i, &buf, 0)
				rt := NewTransport(p.r, &buf, 0)
				msg := []byte(fmt.Sprintf("w%d-i%d", w, i))
				if err := wt.WriteRecord(msg, nil); err != nil {
					errCh <- fmt.Errorf("worker %d write: %w", w, err)
					return
				}
				got, err := rt.ReadRecord(nil)
				if err != nil {
					errCh <- fmt.Errorf("worker %d read: %w", w, err)
					return
				}
				if !bytes.Equal(got, msg) {
					errCh <- fmt.Errorf("worker %d mismatch: got %q want %q", w, got, msg)
					return
				}
			}
		}(w, pairs[w])
	}

	// Concurrently: an injected oversize length prefix MUST be rejected by the
	// guard, not read as a 5 MiB body.
	wg.Add(1)
	go func() {
		defer wg.Done()
		var buf bytes.Buffer
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], 5<<20) // declare 5 MiB
		buf.Write(hdr[:])
		rt := NewTransport(oversizeReader, &buf, 1024) // but cap at 1 KiB
		if _, err := rt.ReadRecord(nil); !errors.Is(err, ErrRecordTooLarge) {
			errCh <- fmt.Errorf("oversize injection: expected ErrRecordTooLarge, got %v", err)
		}
	}()

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
}
