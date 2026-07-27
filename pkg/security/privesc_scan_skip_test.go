package security

import (
	"path/filepath"
	"testing"
)

// These tests are the permanent regression guard for an anti-bluff defect
// found by security audit (2026-07-10): every proc/scan-path read failure in
// this file previously returned PrivEscCheck{Passed: true}, indistinguishable
// from a genuine clean scan. This directly contradicted the module's own
// README (§ "Anti-Bluff Guarantees", guarantee 5): "probes /proc/self/status,
// capability bitmasks, namespace cgroup hierarchy on the real host where
// executed. Skip-with-marker only on platforms lacking /proc — never a
// silent PASS." The struct had no marker field at all, so "we could not
// determine" and "we checked and it's fine" were the same bit pattern —
// exactly the metadata-only / absence-of-error PASS class the project's own
// anti-bluff covenant forbids. A consumer that gates an admission decision on
// PrivEscCheck.Passed (the only field that existed) would silently admit a
// container/host it could not actually evaluate, e.g. under a hidepid=2
// /proc mount, a restrictive LSM profile, or any sandboxing that hides
// /proc/1/* from an unprivileged process without removing /proc itself.
//
// Each test points the check at a path guaranteed not to exist (a path inside
// a fresh t.TempDir(), never created) rather than relying on any actual host
// permission state, so the RED/GREEN result is fully deterministic across
// any CI environment or operator's workstation.
//
// MUTATION THAT FAILS THIS: revert any Check* function's error branch to
// Passed: true (dropping the Skipped: true, Passed: false pairing) -- the
// corresponding assertion below fails immediately.

func TestCheckPrivilegedContainer_UnreadableProcSkipsNotPasses(t *testing.T) {
	orig := procOnePidStatusPath
	procOnePidStatusPath = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { procOnePidStatusPath = orig }()

	check := CheckPrivilegedContainer()
	if check.Passed {
		t.Fatalf("ANTI-BLUFF VIOLATION: /proc/1/status unreadable but check reported Passed=true " +
			"(silent PASS on inconclusive data)")
	}
	if !check.Skipped {
		t.Fatalf("expected Skipped=true when /proc/1/status cannot be read, got Skipped=false (Details=%q)", check.Details)
	}
	t.Logf("PASS: unreadable /proc/1/status correctly reports Skipped=true, Passed=false (Details=%q)", check.Details)
}

func TestCheckDangerousCapabilities_UnreadableProcSkipsNotPasses(t *testing.T) {
	orig := procSelfStatusPath
	procSelfStatusPath = filepath.Join(t.TempDir(), "does-not-exist")
	defer func() { procSelfStatusPath = orig }()

	check := CheckDangerousCapabilities()
	if check.Passed {
		t.Fatalf("ANTI-BLUFF VIOLATION: /proc/self/status unreadable but check reported Passed=true " +
			"(silent PASS on inconclusive data)")
	}
	if !check.Skipped {
		t.Fatalf("expected Skipped=true when /proc/self/status cannot be read, got Skipped=false (Details=%q)", check.Details)
	}
	t.Logf("PASS: unreadable /proc/self/status correctly reports Skipped=true, Passed=false (Details=%q)", check.Details)
}

func TestCheckHostNamespace_UnreadableCgroupSkipsNotPasses(t *testing.T) {
	origSelf := procSelfCgroupPath
	origRoot := procOnePidCgroupPath
	procSelfCgroupPath = filepath.Join(t.TempDir(), "does-not-exist-self")
	procOnePidCgroupPath = filepath.Join(t.TempDir(), "does-not-exist-root")
	defer func() {
		procSelfCgroupPath = origSelf
		procOnePidCgroupPath = origRoot
	}()

	check := CheckHostNamespace()
	if check.Passed {
		t.Fatalf("ANTI-BLUFF VIOLATION: cgroup files unreadable but check reported Passed=true " +
			"(silent PASS on inconclusive data)")
	}
	if !check.Skipped {
		t.Fatalf("expected Skipped=true when cgroup files cannot be read, got Skipped=false (Details=%q)", check.Details)
	}
	t.Logf("PASS: unreadable cgroup files correctly report Skipped=true, Passed=false (Details=%q)", check.Details)
}

func TestCheckSUIDBinaries_AllPathsUnreadableSkipsNotPasses(t *testing.T) {
	orig := suidScanPaths
	base := t.TempDir()
	suidScanPaths = []string{
		filepath.Join(base, "no-such-bin"),
		filepath.Join(base, "no-such-usr-bin"),
	}
	defer func() { suidScanPaths = orig }()

	check := CheckSUIDBinaries()
	if check.Passed {
		t.Fatalf("ANTI-BLUFF VIOLATION: every SUID-scan path unreadable but check reported Passed=true " +
			"(zero real evidence gathered, yet reported as a clean scan)")
	}
	if !check.Skipped {
		t.Fatalf("expected Skipped=true when no scan path is readable, got Skipped=false (Details=%q)", check.Details)
	}
	t.Logf("PASS: all-unreadable SUID scan paths correctly report Skipped=true, Passed=false (Details=%q)", check.Details)
}

// TestCheckSUIDBinaries_PartialReadabilityStillReportsRealFindings proves the
// fix does not regress the legitimate partial-visibility case: if AT LEAST
// ONE configured path is readable, the scan reports on real evidence (not
// Skipped), even though other configured paths were unreadable.
func TestCheckSUIDBinaries_PartialReadabilityStillReportsRealFindings(t *testing.T) {
	orig := suidScanPaths
	base := t.TempDir()
	// One real, readable (and almost certainly SUID-free) directory, plus one
	// deliberately missing path.
	suidScanPaths = []string{base, filepath.Join(base, "no-such-dir")}
	defer func() { suidScanPaths = orig }()

	check := CheckSUIDBinaries()
	if check.Skipped {
		t.Fatalf("expected Skipped=false when at least one scan path is readable, got Skipped=true (Details=%q)", check.Details)
	}
	t.Logf("PASS: partial readability still yields a real (non-skipped) result: passed=%v details=%q",
		check.Passed, check.Details)
}
