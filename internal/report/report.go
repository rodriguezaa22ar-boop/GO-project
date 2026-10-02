// Package report writes the operation report markdown, matching the shell
// build's write_operation_report byte for byte for a session Lite can drive.
package report

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/brief"
	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// Write generates the report file and returns its path.
func Write(op *operation.Operation, reportName string) (string, error) {
	if reportName == "" {
		reportName = op.Slug + "-report"
	}
	slug := state.Slugify(reportName)
	if slug == "" {
		return "", state.Failf("report name produced an empty slug")
	}
	if err := os.MkdirAll(op.Layout.ReportsDir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(op.Layout.ReportsDir, slug+".md")
	body, err := Render(op)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return "", err
	}
	if err := op.AppendLedger("report.generated", scope.ReadOnly, state.ToolName, "ok", path); err != nil {
		return "", err
	}
	return path, nil
}

// Render builds the report markdown.
func Render(op *operation.Operation) (string, error) {
	snap, err := op.Snapshot()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("# Atlas Operation Report\n\n")
	b.WriteString("Generated: " + state.Timestamp() + "\n")
	b.WriteString("Operation: " + op.Name + "\n")
	b.WriteString("Operation ID: " + op.Slug + "\n")
	b.WriteString("Target: " + op.Target + "\n")
	if op.TargetAddress != "" && op.TargetAddress != op.Target {
		b.WriteString("Address: " + op.TargetAddress + "\n")
	}
	b.WriteString("Target Scope Status: " + orUnknown(op.ScopeStatus) + "\n")
	b.WriteString("Target Criticality: " + orUnknown(op.Criticality) + "\n")
	if op.Owner != "" {
		b.WriteString("Target Owner: " + op.Owner + "\n")
	}
	if op.Tags != "" {
		b.WriteString("Target Tags: " + op.Tags + "\n")
	}
	b.WriteString("Status: " + op.Status + "\n")
	b.WriteString("Created: " + op.CreatedAt + "\n")
	if op.ClosedAt != "" {
		b.WriteString("Closed: " + op.ClosedAt + "\n")
	}
	if op.Notes != "" {
		b.WriteString("Notes: " + op.Notes + "\n")
	}

	b.WriteString("\n## Executive Summary\n\n")
	summary, err := executiveSummary(op)
	if err != nil {
		return "", err
	}
	b.WriteString(summary)

	b.WriteString("\n## Operator Brief\n\n")
	evCount, err := evidence.Count(op.Dir, op.Target)
	if err != nil {
		return "", err
	}
	br, err := brief.Collect(op, evCount)
	if err != nil {
		return "", err
	}
	b.WriteString(strings.Join(br.ReportMarkdown(), "\n") + "\n")

	b.WriteString("\n## Finding Review\n\n")
	review, err := findingReview(op)
	if err != nil {
		return "", err
	}
	b.WriteString(review)

	b.WriteString("\n## Remediation Priorities\n\n")
	rem, err := remediation(op)
	if err != nil {
		return "", err
	}
	b.WriteString(rem)

	b.WriteString("\n## Scope\n\n")
	b.WriteString(snap.Text + "\n\n")
	b.WriteString("## Allowed Actions\n\n")
	for _, l := range snap.AllowedActionLines() {
		b.WriteString("- " + l + "\n")
	}
	b.WriteString("\n## Explicitly Out Of Scope\n\n")
	for _, l := range snap.OutOfScopeLines() {
		b.WriteString("- " + l + "\n")
	}
	b.WriteString("\n## Commands Run\n\n")
	for _, l := range commandsRun(op) {
		b.WriteString("- `" + l + "`\n")
	}
	b.WriteString("\n## Artifacts\n\n")
	b.WriteString("- Operation directory: `" + op.Dir + "`\n")
	arts, err := reconArtifacts(op)
	if err != nil {
		return "", err
	}
	b.WriteString(arts)
	b.WriteString("\n## Validation Plans\n\n")
	b.WriteString("- No validation plans recorded yet.\n")
	b.WriteString("\n## Notes\n\n")
	b.WriteString("- Add operator notes here.\n")
	return b.String(), nil
}

func executiveSummary(op *operation.Operation) (string, error) {
	evCount, err := evidence.Count(op.Dir, op.Target)
	if err != nil {
		return "", err
	}
	fCount, err := findings.Count(op.Dir, op.Target)
	if err != nil {
		return "", err
	}
	observed, err := countLevel(op, "observed")
	if err != nil {
		return "", err
	}
	inferred, err := countLevel(op, "inferred")
	if err != nil {
		return "", err
	}
	validated, err := countLevel(op, "validated")
	if err != nil {
		return "", err
	}
	highest, err := findings.HighestSeverity(op.Dir, op.Target)
	if err != nil {
		return "", err
	}
	br, err := brief.Collect(op, evCount)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("This report summarizes the authorized Atlas operation \"" + op.Name + "\" for \"" + op.Target + "\".\n\n")
	b.WriteString(sprintf("- Evidence records: %d\n", evCount))
	b.WriteString(sprintf("- Findings: %d total, %d observed, %d inferred, %d validated\n", fCount, observed, inferred, validated))
	b.WriteString(sprintf("- Validation plans: %d\n", br.ValidationCount))
	b.WriteString("- Highest recorded severity: " + highest + "\n")
	b.WriteString("- Recommended next step: " + br.NextStep + "\n")
	return b.String(), nil
}

func countLevel(op *operation.Operation, level string) (int, error) {
	fs, err := findings.Latest(op.Dir, op.Target)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, f := range fs {
		if f.Level == level {
			n++
		}
	}
	return n, nil
}

func findingReview(op *operation.Operation) (string, error) {
	var b strings.Builder
	for _, lvl := range []struct{ level, title string }{{"observed", "Observed"}, {"inferred", "Inferred"}, {"validated", "Validated"}} {
		b.WriteString("### " + lvl.title + "\n\n")
		rows, err := findings.ByLevel(op.Dir, op.Target, lvl.level)
		if err != nil {
			return "", err
		}
		if len(rows) == 0 {
			b.WriteString("- No " + lvl.level + " findings recorded.\n")
		} else {
			for _, f := range rows {
				b.WriteString(f.ReviewLine() + "\n")
			}
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func remediation(op *operation.Operation) (string, error) {
	fs, err := findings.Latest(op.Dir, op.Target)
	if err != nil {
		return "", err
	}
	var withRec []findings.Finding
	for _, f := range fs {
		if f.Recommendation != "" {
			withRec = append(withRec, f)
		}
	}
	if len(withRec) == 0 {
		return "- No remediation priorities recorded yet.\n", nil
	}
	// severity weight desc, then updated/created desc
	sortRemediation(withRec)
	var b strings.Builder
	for _, f := range withRec {
		b.WriteString("- [" + f.SeverityOr() + "] " + f.TitleOr() + ": " + f.Recommendation)
		if len(f.Evidence) > 0 {
			b.WriteString(" Evidence: " + strings.Join(f.Evidence, ", ") + ".")
		}
		b.WriteString("\n")
	}
	return b.String(), nil
}

func commandsRun(op *operation.Operation) []string {
	historyFile := filepath.Join(op.Dir, "notes", "history.log")
	data, err := os.ReadFile(historyFile)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return []string{"atlas op start " + op.Slug + " " + op.Target}
	}
	var out []string
	for _, raw := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
		parts := strings.SplitN(raw, "\t", 3)
		if len(parts) < 2 {
			continue
		}
		event := parts[1]
		detail := ""
		if len(parts) == 3 {
			detail = parts[2]
		}
		out = append(out, commandForHistory(op, event, detail))
	}
	return out
}

func commandForHistory(op *operation.Operation, event, detail string) string {
	switch {
	case event == "start":
		if op.Notes != "" {
			return "atlas op start " + op.Slug + " " + op.Target + " " + op.Notes
		}
		return "atlas op start " + op.Slug + " " + op.Target
	case event == "resume":
		return "atlas op resume " + op.Slug
	case event == "close":
		return "atlas op close " + op.Slug
	case event == "handoff", event == "closeout", event == "audit-packet", event == "archive-packet":
		base := filepath.Base(detail)
		if strings.HasSuffix(base, ".json") {
			return "atlas op " + event + " --json " + op.Slug + " " + strings.TrimSuffix(base, ".json")
		}
		return "atlas op " + event + " " + op.Slug + " " + strings.TrimSuffix(base, ".md")
	}
	return "atlas op " + event
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// reconArtifacts lists evidence captured through adapters (tool runs) as
// metadata: id, kind, stored path and hash, never the output itself. With
// no adapter evidence it keeps the shell build's wording, so reports for
// operations without adapter runs stay byte-identical to the oracle.
func reconArtifacts(op *operation.Operation) (string, error) {
	recs, err := evidence.Latest(op.Dir, op.Target)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, r := range recs {
		if r.Kind != evidence.KindAdapterOutput {
			continue
		}
		b.WriteString("- Recon artifact: " + r.ID + " `" + r.Path + "` sha256=" + r.SHA256 + "\n")
	}
	if b.Len() == 0 {
		return "- No recon or action artifacts tracked yet.\n", nil
	}
	return b.String(), nil
}
