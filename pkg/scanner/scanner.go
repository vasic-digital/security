// Package scanner provides a vulnerability scanning interface with severity
// levels, findings, and aggregated reports.
package scanner

import (
	"context"
	"fmt"
	"time"

	"digital.vasic.security/pkg/i18n"
)

// Severity represents the severity level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Finding represents a single vulnerability or issue found by a scanner.
type Finding struct {
	Severity    Severity `json:"severity"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Location    string   `json:"location,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// Scanner scans a target for vulnerabilities.
type Scanner interface {
	// Scan scans the target and returns findings.
	Scan(ctx context.Context, target string) ([]Finding, error)
}

// Report aggregates findings from one or more scanners.
type Report struct {
	Findings    []Finding     `json:"findings"`
	TotalCount  int           `json:"total_count"`
	BySeverity  map[Severity]int `json:"by_severity"`
	ScannerName string        `json:"scanner_name,omitempty"`
	Target      string        `json:"target,omitempty"`
	Duration    time.Duration `json:"duration"`
	ScannedAt   time.Time     `json:"scanned_at"`
}

// NewReport creates a new Report from a set of findings.
func NewReport(
	findings []Finding, scannerName string,
	target string, duration time.Duration,
) *Report {
	bySeverity := make(map[Severity]int)
	for _, f := range findings {
		bySeverity[f.Severity]++
	}
	return &Report{
		Findings:    findings,
		TotalCount:  len(findings),
		BySeverity:  bySeverity,
		ScannerName: scannerName,
		Target:      target,
		Duration:    duration,
		ScannedAt:   time.Now(),
	}
}

// HasCritical returns true if the report contains critical findings.
func (r *Report) HasCritical() bool {
	return r.BySeverity[SeverityCritical] > 0
}

// HasHighOrAbove returns true if the report contains high or critical
// findings.
func (r *Report) HasHighOrAbove() bool {
	return r.BySeverity[SeverityCritical] > 0 ||
		r.BySeverity[SeverityHigh] > 0
}

// FilterBySeverity returns findings at or above the given severity.
func (r *Report) FilterBySeverity(minSeverity Severity) []Finding {
	minOrder := severityOrder(minSeverity)
	var filtered []Finding
	for _, f := range r.Findings {
		if severityOrder(f.Severity) >= minOrder {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// Summary returns a human-readable summary of the report.
//
// CONST-046: the format template is sourced from the package-level
// translator (NoopTranslator returns the message ID verbatim).
// Consumer projects inject locale-aware templates via i18n.SetPkgTranslator.
func (r *Report) Summary() string {
	tmpl, _ := i18n.Pkg().T(context.Background(), i18n.MsgScannerReportSummary, nil)
	if tmpl == i18n.MsgScannerReportSummary {
		// NoopTranslator path: provide the canonical English template so
		// existing consumers (and tests) see deterministic output.
		tmpl = "Scan Report: %d findings " +
			"(Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d)"
	}
	return fmt.Sprintf(
		tmpl,
		r.TotalCount,
		r.BySeverity[SeverityCritical],
		r.BySeverity[SeverityHigh],
		r.BySeverity[SeverityMedium],
		r.BySeverity[SeverityLow],
		r.BySeverity[SeverityInfo],
	)
}

// RunScanner runs a scanner against a target and produces a report.
func RunScanner(
	ctx context.Context, s Scanner,
	scannerName string, target string,
) (*Report, error) {
	start := time.Now()
	findings, err := s.Scan(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("scanner %q failed: %w",
			scannerName, err)
	}
	duration := time.Since(start)
	return NewReport(findings, scannerName, target, duration), nil
}

// MergeReports merges multiple reports into a single report.
func MergeReports(reports ...*Report) *Report {
	var allFindings []Finding
	var totalDuration time.Duration

	for _, r := range reports {
		if r != nil {
			allFindings = append(allFindings, r.Findings...)
			totalDuration += r.Duration
		}
	}

	return NewReport(allFindings, "merged", "", totalDuration)
}

func severityOrder(s Severity) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}
