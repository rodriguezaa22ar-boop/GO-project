package packet

import (
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/readiness"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
	"github.com/rodriguezaa22ar-boop/go-project/internal/validation"
)

// Closeout writes the closeout manifest. The closeout.manifest.generated
// ledger event is appended before the manifest is rendered, matching
// cmd_op_closeout, so the manifest's ledger anchor includes it.
func Closeout(op *operation.Operation, manifestName string) (string, error) {
	if manifestName == "" {
		manifestName = op.Slug + "-closeout"
	}
	slug := state.Slugify(manifestName)
	if slug == "" {
		return "", state.Failf("closeout manifest name produced an empty slug")
	}
	dir := packetDir(op, "closeout")
	if err := state.MkdirAll(dir); err != nil {
		return "", err
	}
	path := dir + "/" + slug + ".md"
	if err := op.AppendLedger("closeout.manifest.generated", scope.ReadOnly, state.ToolName, "ok", path); err != nil {
		return "", err
	}
	body, err := renderCloseout(op)
	if err != nil {
		return "", err
	}
	if err := writeMarkdown(path, body); err != nil {
		return "", err
	}
	if err := state.RecordHistory(op.Dir, "closeout", path); err != nil {
		return "", err
	}
	return path, nil
}

func renderCloseout(op *operation.Operation) (string, error) {
	snap, err := op.Snapshot()
	if err != nil {
		return "", err
	}
	st, err := readiness.Collect(op)
	if err != nil {
		return "", err
	}
	reportAt, reportPath, reportSHA := reportFields(st)
	handoffAt, handoffPath, handoffSHA := handoffFields(st)

	ledgerPath := ledger.File(op.Dir)
	ledgerEvents := ledgerEventCount(ledgerPath)
	ledgerSHA := shaForFile(ledgerPath)

	var b strings.Builder
	b.WriteString("# Atlas Closeout Manifest\n\n")
	b.WriteString("Generated: " + state.Timestamp() + "\n")
	b.WriteString("Operation: " + op.Name + "\n")
	b.WriteString("Operation ID: " + op.Slug + "\n")
	b.WriteString("Operation Status: " + op.Status + "\n")
	if op.ClosedAt != "" {
		b.WriteString("Closed At: " + op.ClosedAt + "\n")
	} else {
		b.WriteString("Closed At: not closed\n")
	}
	b.WriteString("Target: " + op.Target + "\n")
	if op.TargetAddress != "" && op.TargetAddress != op.Target {
		b.WriteString("Address: " + op.TargetAddress + "\n")
	}
	b.WriteString("Profile: " + snap.Profile + "\n")
	b.WriteString("\nNo raw artifact contents are included in this closeout manifest.\n")

	b.WriteString("\n## Readiness Snapshot\n\n")
	b.WriteString("- Close readiness: " + st.Status + "\n")
	b.WriteString("- Next step: " + st.NextStep + "\n")
	b.WriteString(countLine("Evidence records", st.EvidenceCount))
	b.WriteString(countLine("Findings", st.FindingCount))
	b.WriteString(countLine("Open findings", st.OpenCount))
	b.WriteString(countLine("Expired accepted risks", st.ExpiredAccepted))
	b.WriteString(countLine("Validation plans", st.ValidationCount))
	b.WriteString(countLine("Pending validation", st.PendingCount))
	b.WriteString("- Report freshness: " + st.ReportFresh + "\n")
	b.WriteString("- Bundle freshness: " + st.BundleFresh + "\n")
	b.WriteString("- Handoff freshness: " + st.HandoffFresh + "\n")
	b.WriteString("- Closeout freshness: " + st.CloseoutFresh + "\n")

	b.WriteString("\n## Primary Artifacts\n\n")
	if reportPath != "" {
		b.WriteString("- Latest report: `" + reportPath + "` generated=" + reportAt + " sha256=" + reportSHA + "\n")
	} else {
		b.WriteString("- Latest report: none generated yet\n")
	}
	b.WriteString("- Evidence bundle: none generated yet\n")
	b.WriteString("- Evidence manifest: none\n")
	if handoffPath != "" {
		b.WriteString("- Latest handoff: `" + handoffPath + "` generated=" + handoffAt + " sha256=" + handoffSHA + "\n")
	} else {
		b.WriteString("- Latest handoff: none generated yet\n")
	}

	b.WriteString("\n## Integrity Anchors\n\n")
	b.WriteString("- Operation ledger: `" + ledgerPath + "` events=" + itoa(ledgerEvents) + " sha256=" + ledgerSHA + "\n")
	b.WriteString(hashLine("Operation env", op.File) + "\n")
	b.WriteString(hashLine("Scope snapshot", scope.SnapshotFile(op.Dir)) + "\n")
	b.WriteString(hashLine("Evidence index", evidence.IndexFile(op.Dir)) + "\n")
	b.WriteString(hashLine("Finding index", findings.IndexFile(op.Dir)) + "\n")
	b.WriteString(hashLine("Validation index", existingOrEmpty(validation.IndexFile(op.Dir))) + "\n")

	b.WriteString("\n## Closeout Notes\n\n")
	b.WriteString("- Verify copied report, handoff, and evidence bundle files against the hashes above.\n")
	b.WriteString("- Treat paths as local references; validate recipient and handling requirements before sharing artifacts.\n")
	return b.String(), nil
}

// existingOrEmpty returns path when the file exists, else "" so hashLine
// renders "none" (the shell passes the path but the file is absent).
func existingOrEmpty(path string) string {
	if state.FileExists(path) {
		return path
	}
	return ""
}
