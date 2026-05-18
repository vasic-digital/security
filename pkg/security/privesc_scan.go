// Package security provides host and container security scanning utilities.
//
// CONST-046 (No-Hardcoded Content): every user-visible Description and
// Details field is sourced from the package-level translator. The default
// NoopTranslator returns each message ID verbatim, preserving deterministic
// behaviour for existing tests; consumer projects inject locale-aware
// implementations via i18n.SetPkgTranslator.
package security

import (
	"context"
	"fmt"
	"os"
	"strings"

	"digital.vasic.security/pkg/i18n"
)

// PrivEscCheck holds the result of a privilege escalation scan.
type PrivEscCheck struct {
	Name        string
	Description string
	Passed      bool
	Details     string
}

// tr translates the messageID via the package-level translator.
// On error it returns the messageID verbatim (CONST-035 anti-bluff:
// no silent string substitution).
func tr(id string) string {
	s, err := i18n.Pkg().T(context.Background(), id, nil)
	if err != nil || s == "" {
		return id
	}
	return s
}

// trf translates the messageID and substitutes a single positional
// integer (the count). NoopTranslator returns the ID verbatim, so we
// detect that path and apply Sprintf locally for the default case.
func trf(id, fallbackFmt string, n int) string {
	s, err := i18n.Pkg().T(context.Background(), id, map[string]any{"count": n})
	if err != nil || s == "" || s == id {
		return fmt.Sprintf(fallbackFmt, n)
	}
	return s
}

// ScanPrivilegeEscalation checks common container and host privilege escalation vectors.
func ScanPrivilegeEscalation() []PrivEscCheck {
	var checks []PrivEscCheck

	checks = append(checks, CheckPrivilegedContainer())
	checks = append(checks, CheckWritableRootFS())
	checks = append(checks, CheckDangerousCapabilities())
	checks = append(checks, CheckHostNamespace())
	checks = append(checks, CheckSUIDBinaries())

	return checks
}

func CheckPrivilegedContainer() PrivEscCheck {
	// Check if /proc/1/status exists and read capabilities
	data, err := os.ReadFile("/proc/1/status")
	if err != nil {
		return PrivEscCheck{
			Name:        "PrivilegedContainer",
			Description: tr(i18n.MsgPrivescPrivContainerDesc),
			Passed:      true,
			Details:     tr(i18n.MsgPrivescPrivContainerUnknownProcStatus),
		}
	}

	// In a privileged container, CapEff often contains all capabilities
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == "0000003fffffffff" {
				return PrivEscCheck{
					Name:        "PrivilegedContainer",
					Description: tr(i18n.MsgPrivescPrivContainerDesc),
					Passed:      false,
					Details:     tr(i18n.MsgPrivescPrivContainerFullCaps),
				}
			}
		}
	}

	return PrivEscCheck{
		Name:        "PrivilegedContainer",
		Description: tr(i18n.MsgPrivescPrivContainerDesc),
		Passed:      true,
		Details:     tr(i18n.MsgPrivescPrivContainerOK),
	}
}

func CheckWritableRootFS() PrivEscCheck {
	// Try to create a file in / to detect writable root filesystem
	f, err := os.Create("/.security_test_" + fmt.Sprintf("%d", os.Getpid()))
	if err == nil {
		f.Close()
		os.Remove(f.Name())
		return PrivEscCheck{
			Name:        "WritableRootFS",
			Description: tr(i18n.MsgPrivescWritableRootDesc),
			Passed:      false,
			Details:     tr(i18n.MsgPrivescWritableRootFail),
		}
	}

	return PrivEscCheck{
		Name:        "WritableRootFS",
		Description: tr(i18n.MsgPrivescWritableRootDesc),
		Passed:      true,
		Details:     tr(i18n.MsgPrivescWritableRootOK),
	}
}

func CheckDangerousCapabilities() PrivEscCheck {
	// Check for CAP_SYS_ADMIN which enables many escalation paths
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return PrivEscCheck{
			Name:        "DangerousCapabilities",
			Description: tr(i18n.MsgPrivescDangerousCapsDesc),
			Passed:      true,
			Details:     tr(i18n.MsgPrivescDangerousCapsUnknownProcStatus),
		}
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				capEff := fields[1]
				// CAP_SYS_ADMIN is bit 21; in hex cap data this is position-dependent
				// Full check would parse the cap value; here we flag full caps
				if capEff == "0000003fffffffff" {
					return PrivEscCheck{
						Name:        "DangerousCapabilities",
						Description: tr(i18n.MsgPrivescDangerousCapsDesc),
						Passed:      false,
						Details:     tr(i18n.MsgPrivescDangerousCapsFail),
					}
				}
			}
		}
	}

	return PrivEscCheck{
		Name:        "DangerousCapabilities",
		Description: tr(i18n.MsgPrivescDangerousCapsDesc),
		Passed:      true,
		Details:     tr(i18n.MsgPrivescDangerousCapsOK),
	}
}

func CheckHostNamespace() PrivEscCheck {
	// Compare /proc/self/cgroup with /proc/1/cgroup to detect host PID namespace
	selfCgroup, err1 := os.ReadFile("/proc/self/cgroup")
	rootCgroup, err2 := os.ReadFile("/proc/1/cgroup")

	if err1 != nil || err2 != nil {
		return PrivEscCheck{
			Name:        "HostNamespace",
			Description: tr(i18n.MsgPrivescHostNamespaceDesc),
			Passed:      true,
			Details:     tr(i18n.MsgPrivescHostNamespaceUnknownCgroup),
		}
	}

	if strings.TrimSpace(string(selfCgroup)) == strings.TrimSpace(string(rootCgroup)) {
		return PrivEscCheck{
			Name:        "HostNamespace",
			Description: tr(i18n.MsgPrivescHostNamespaceDesc),
			Passed:      false,
			Details:     tr(i18n.MsgPrivescHostNamespaceFail),
		}
	}

	return PrivEscCheck{
		Name:        "HostNamespace",
		Description: tr(i18n.MsgPrivescHostNamespaceDesc),
		Passed:      true,
		Details:     tr(i18n.MsgPrivescHostNamespaceOK),
	}
}

func CheckSUIDBinaries() PrivEscCheck {
	// Check common paths for unexpected SUID binaries
	paths := []string{"/bin", "/usr/bin", "/sbin", "/usr/sbin"}
	found := []string{}

	for _, dir := range paths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSetuid != 0 {
				found = append(found, entry.Name())
			}
		}
	}

	if len(found) > 0 {
		return PrivEscCheck{
			Name:        "SUIDBinaries",
			Description: tr(i18n.MsgPrivescSUIDDesc),
			Passed:      false,
			Details:     trf(i18n.MsgPrivescSUIDFail, "Found %d SUID binaries", len(found)),
		}
	}

	return PrivEscCheck{
		Name:        "SUIDBinaries",
		Description: tr(i18n.MsgPrivescSUIDDesc),
		Passed:      true,
		Details:     tr(i18n.MsgPrivescSUIDOK),
	}
}
