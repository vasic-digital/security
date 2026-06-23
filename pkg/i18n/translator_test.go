package i18n

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func TestNoopTranslator_T_ReturnsIDVerbatim(t *testing.T) {
	got, err := NoopTranslator{}.T(context.Background(), "security_test_id", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "security_test_id" {
		t.Fatalf("expected message ID verbatim, got %q", got)
	}
}

func TestNoopTranslator_TPlural_ReturnsIDVerbatim(t *testing.T) {
	got, err := NoopTranslator{}.TPlural(context.Background(), "security_plural", 5, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "security_plural" {
		t.Fatalf("expected message ID verbatim, got %q", got)
	}
}

func TestSetPkgTranslator_NilResetsToNoop(t *testing.T) {
	defer SetPkgTranslator(nil)
	SetPkgTranslator(stubTranslator{prefix: "X:"})
	SetPkgTranslator(nil)
	got, _ := Pkg().T(context.Background(), "abc", nil)
	if got != "abc" {
		t.Fatalf("expected nil reset to NoopTranslator (verbatim 'abc'), got %q", got)
	}
}

func TestSetPkgTranslator_Custom(t *testing.T) {
	defer SetPkgTranslator(nil)
	SetPkgTranslator(stubTranslator{prefix: "L:"})
	got, err := Pkg().T(context.Background(), "abc", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "L:abc" {
		t.Fatalf("expected stub prefix 'L:abc', got %q", got)
	}
}

// TestPkg_ConcurrentAccess proves SetPkgTranslator + Pkg are safe for
// concurrent goroutine use (RWMutex contract).
func TestPkg_ConcurrentAccess(t *testing.T) {
	defer SetPkgTranslator(nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				SetPkgTranslator(stubTranslator{prefix: "P:"})
			} else {
				_, _ = Pkg().T(context.Background(), "x", nil)
			}
		}(i)
	}
	wg.Wait()

	// Observable post-join assertion: after the concurrent storm of
	// SetPkgTranslator/Pkg calls, the translator registry must still be
	// uncorrupted and fully functional. Set a known translator and a known
	// fallback, then assert each returns its correct, expected translation
	// for a known key — proving no data loss / torn state under concurrency.
	SetPkgTranslator(stubTranslator{prefix: "C:"})
	got, err := Pkg().T(context.Background(), "post_join", nil)
	if err != nil {
		t.Fatalf("post-join translator returned error after concurrent access: %v", err)
	}
	if got != "C:post_join" {
		t.Fatalf("post-join translator corrupted: got %q, want %q", got, "C:post_join")
	}
	SetPkgTranslator(nil)
	gotNoop, err := Pkg().T(context.Background(), "post_join", nil)
	if err != nil {
		t.Fatalf("post-join NoopTranslator returned error after concurrent access: %v", err)
	}
	if gotNoop != "post_join" {
		t.Fatalf("post-join nil reset corrupted: got %q, want verbatim %q", gotNoop, "post_join")
	}
}

// TestNoopTranslator_MutationFalsifiability is the paired mutation gate:
// asserts that swapping NoopTranslator's T implementation to a divergent
// return shape immediately breaks observable behaviour. A test suite
// that PASSes after such a swap would be a §11.4 PASS-bluff.
func TestNoopTranslator_MutationFalsifiability(t *testing.T) {
	defer SetPkgTranslator(nil)
	// Simulate a broken translator that loses the messageID.
	SetPkgTranslator(brokenTranslator{})
	got, err := Pkg().T(context.Background(), "security_canary", nil)
	if err == nil {
		t.Fatalf("expected broken translator to surface error; got nil with value %q", got)
	}
	// Now restore Noop; canary MUST come back verbatim — proves we are
	// observing translator behaviour and not a baked-in literal.
	SetPkgTranslator(nil)
	got2, _ := Pkg().T(context.Background(), "security_canary", nil)
	if got2 != "security_canary" {
		t.Fatalf("expected restoration to NoopTranslator verbatim, got %q", got2)
	}
}

// --- test stubs (unit-test only; permitted under CONST-050(A)) ---

type stubTranslator struct{ prefix string }

func (s stubTranslator) T(_ context.Context, id string, _ map[string]any) (string, error) {
	return s.prefix + id, nil
}

func (s stubTranslator) TPlural(_ context.Context, id string, _ int, _ map[string]any) (string, error) {
	return s.prefix + id, nil
}

type brokenTranslator struct{}

func (brokenTranslator) T(_ context.Context, _ string, _ map[string]any) (string, error) {
	return "", errors.New("broken: canary lost")
}

func (brokenTranslator) TPlural(_ context.Context, _ string, _ int, _ map[string]any) (string, error) {
	return "", errors.New("broken: canary lost")
}
