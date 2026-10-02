// Package brief reproduces the operator brief lines in the report and
// op brief output. The intel-graph surface counts are always zero in Lite,
// which matches a session with no wiremap recon runs (host=unknown).
package brief

import (
	"fmt"

	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/validation"
)

// Brief holds the collected brief values.
type Brief struct {
	HostState       string
	ServiceCount    int
	WebCount        int
	LateralCount    int
	PostureCount    int
	EvidenceCount   int
	FindingCount    int
	ValidationCount int
	PlannedCount    int
	ApprovedCount   int
	ExecutedCount   int
	LatestFinding   *findings.Finding
	LatestVal       *validation.Plan
	NextStep        string
}

// Collect gathers the brief for an operation with an active operation.
func Collect(op *operation.Operation, evidenceCount int) (*Brief, error) {
	b := &Brief{HostState: "unknown", EvidenceCount: evidenceCount}
	var err error
	if b.FindingCount, err = findings.Count(op.Dir, op.Target); err != nil {
		return nil, err
	}
	if b.ValidationCount, err = validation.Count(op.Dir, op.Target); err != nil {
		return nil, err
	}
	if b.PlannedCount, err = validation.StatusCount(op.Dir, op.Target, "planned"); err != nil {
		return nil, err
	}
	if b.ApprovedCount, err = validation.StatusCount(op.Dir, op.Target, "approved"); err != nil {
		return nil, err
	}
	if b.ExecutedCount, err = validation.StatusCount(op.Dir, op.Target, "executed"); err != nil {
		return nil, err
	}
	if b.LatestFinding, err = findings.LatestFinding(op.Dir, op.Target); err != nil {
		return nil, err
	}
	b.LatestVal = validation.LatestPlan(op.Dir, op.Target)
	b.NextStep = b.nextStep()
	return b, nil
}

func (b *Brief) nextStep() string {
	switch {
	case b.ApprovedCount > 0:
		return "Run the approved validation plan and record the resulting evidence."
	case b.PlannedCount > 0:
		return "Approve, revise, or retire the planned validation before execution."
	case b.FindingCount > 0 && b.ValidationCount == 0:
		return "Create a validation plan for the highest-value finding."
	case b.ExecutedCount > 0:
		return "Review validation output, update finding status, and refresh the report."
	case b.ServiceCount > 0 || b.WebCount > 0:
		return "Review candidate lanes and record findings for material issues."
	}
	return "Run operation-aware recon to build evidence for this target."
}

// ReportMarkdown mirrors atlas_brief_report_markdown.
func (b *Brief) ReportMarkdown() []string {
	out := []string{
		fmt.Sprintf("- Surface: host=%s, services=%d, web=%d, lateral=%d, posture_findings=%d.", b.HostState, b.ServiceCount, b.WebCount, b.LateralCount, b.PostureCount),
		fmt.Sprintf("- Operation state: evidence=%d, findings=%d, validation_plans=%d.", b.EvidenceCount, b.FindingCount, b.ValidationCount),
		fmt.Sprintf("- Validation: planned=%d, approved=%d, executed=%d.", b.PlannedCount, b.ApprovedCount, b.ExecutedCount),
	}
	if b.LatestFinding != nil {
		f := b.LatestFinding
		out = append(out, fmt.Sprintf("- Latest finding: %s %s/%s/%s %s.", f.IDOr(), f.SeverityOr(), f.LevelOr(), f.StatusOr(), f.TitleOr()))
	}
	if b.LatestVal != nil {
		p := b.LatestVal
		out = append(out, fmt.Sprintf("- Latest validation: %s %s %s result=%s.", orq(p.ID), orq(p.Lane), orq(p.Status), p.Result()))
	}
	out = append(out, "- Next step: "+b.NextStep)
	return out
}

// Lines mirrors atlas_brief_print_lines (operation form).
func (b *Brief) Lines() []string {
	out := []string{
		fmt.Sprintf("Surface: host=%s, services=%d, web=%d, lateral=%d, posture_findings=%d", b.HostState, b.ServiceCount, b.WebCount, b.LateralCount, b.PostureCount),
		fmt.Sprintf("Operation State: evidence=%d, findings=%d, validation_plans=%d", b.EvidenceCount, b.FindingCount, b.ValidationCount),
		fmt.Sprintf("Validation: planned=%d, approved=%d, executed=%d", b.PlannedCount, b.ApprovedCount, b.ExecutedCount),
	}
	if b.LatestFinding != nil {
		f := b.LatestFinding
		out = append(out, fmt.Sprintf("Latest Finding: %s %s/%s/%s %s", f.IDOr(), f.SeverityOr(), f.LevelOr(), f.StatusOr(), f.TitleOr()))
	}
	if b.LatestVal != nil {
		p := b.LatestVal
		out = append(out, fmt.Sprintf("Latest Validation: %s %s %s result=%s", orq(p.ID), orq(p.Lane), orq(p.Status), p.Result()))
	}
	out = append(out, "Next Step: "+b.NextStep)
	return out
}

func orq(v string) string {
	if v == "" {
		return "?"
	}
	return v
}
