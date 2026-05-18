// Package i18n is the security submodule's hardcoded-content
// abstraction layer for CONST-046 compliance.
//
// The security submodule is generic infrastructure consumed by
// many projects (CONST-051(B) — fully decoupled). It MUST NOT
// embed a project-specific i18n implementation. Instead, this
// package defines a minimal Translator interface that consumers
// inject at the parent-project boundary.
//
// Built-in: NoopTranslator returns each message ID verbatim,
// preserving the previous user-visible behaviour when no consumer
// translator is wired. Package-level translator state is set via
// SetPkgTranslator(); call sites consult Pkg() to translate.
package i18n

import (
	"context"
	"sync"
)

// Translator is the abstraction every CONST-046 migrated call
// site uses to externalise its user-facing strings. Consumers
// inject real implementations (e.g. a YAML-backed i18n adapter,
// an ICU-MessageFormat backend). Implementations MUST be safe
// for concurrent use by multiple goroutines.
type Translator interface {
	// T returns the user-facing string for messageID with
	// templateData substituted. It returns the substituted
	// string and a nil error on success, or an empty string
	// and a non-nil error if substitution failed.
	T(
		ctx context.Context,
		messageID string,
		templateData map[string]any,
	) (string, error)

	// TPlural returns the count-aware user-facing string for
	// messageID. count selects the plural form (CLDR rules).
	TPlural(
		ctx context.Context,
		messageID string,
		count int,
		templateData map[string]any,
	) (string, error)
}

// NoopTranslator is the safety default: it returns the message ID
// verbatim, ignoring templateData and count. This preserves the
// previous behaviour of code that has not yet been wired to a
// real translator (CONST-035 anti-bluff: no silent string
// substitution).
type NoopTranslator struct{}

// T returns the messageID verbatim.
func (NoopTranslator) T(
	_ context.Context,
	id string,
	_ map[string]any,
) (string, error) {
	return id, nil
}

// TPlural returns the messageID verbatim, ignoring count.
func (NoopTranslator) TPlural(
	_ context.Context,
	id string,
	_ int,
	_ map[string]any,
) (string, error) {
	return id, nil
}

var (
	pkgMu sync.RWMutex
	pkg   Translator = NoopTranslator{}
)

// SetPkgTranslator installs the package-level translator. Consumers
// call this at boot to inject their real Translator implementation.
// Passing nil resets to NoopTranslator{}.
func SetPkgTranslator(t Translator) {
	pkgMu.Lock()
	defer pkgMu.Unlock()
	if t == nil {
		pkg = NoopTranslator{}
		return
	}
	pkg = t
}

// Pkg returns the currently-installed package-level translator.
// Safe for concurrent use. Defaults to NoopTranslator{}.
func Pkg() Translator {
	pkgMu.RLock()
	defer pkgMu.RUnlock()
	return pkg
}
