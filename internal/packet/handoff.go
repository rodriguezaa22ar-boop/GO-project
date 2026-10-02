package packet

import (
	"strconv"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/readiness"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
	"github.com/rodriguezaa22ar-boop/go-project/internal/validation"
)

// Handoff writes the handoff packet and records handoff.generated. The
// ledger event is appended after the packet is written, matching
// cmd_op_handoff.
func Handoff(op *operation.Operation, packetName string) (string, error) {
	if packetName == "" {
		packetName = op.Slug + "-handoff"
	}
	slug := state.Slugify(packetName)
	if slug == "" {
		return "", state.Failf("handoff packet name produced an empty slug")
	}
	dir := packetDir(op, "handoff")
	if err := state.MkdirAll(dir); err != nil {
		return "", err
	}
	path := dir + "/" + slug + ".md"
	body, err := renderHandoff(op)
	if err != nil {
		return "", err
	}
	if err := writeMarkdown(path, body); err != nil {
		return "", err
	}
	if err := op.AppendLedger("handoff.generated", scope.ReadOnly, state.ToolName, "ok", path); err != nil {
		return "", err
	}
	if err := state.RecordHistory(op.Dir, "handoff", path); err != nil {
		return "", err
	}
	return path, nil
}

func renderHandoff(op *operation.Operation) (string, error) {
	st, err := readiness.Collect(op)
	if err != nil {
		return "", err
	}
	reportAt, reportPath, reportSHA := reportFields(st)

	var b strings.Builder
	b.WriteString("# Atlas Operation Handoff\n\n")
	b.WriteString("Generated: " + state.Timestamp() + "\n")
	b.WriteString("Operation: " + op.Name + "\n")
	b.WriteString("Operation ID: " + op.Slug + "\n")
	b.WriteString("Operation Status: " + op.Status + "\n")
	b.WriteString("Target: " + op.Target + "\n")
	if op.TargetAddress != "" && op.TargetAddress != op.Target {
		b.WriteString("Address: " + op.TargetAddress + "\n")
	}
	b.WriteString("\nNo raw artifact contents are included in this handoff packet.\n")

	b.WriteString("\n## Close Readiness\n\n")
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
	b.WriteString("- Handoff freshness before this packet: " + st.HandoffFresh + "\n")
	b.WriteString(changeLine("Latest state change", st.LatestChange))
	b.WriteString(changeLine("Latest evidence change", st.LatestEvidence))

	b.WriteString("\n## Primary Artifacts\n\n")
	if reportPath != "" {
		line := "- Latest report: `" + reportPath + "`"
		if reportAt != "" {
			line += " generated=" + reportAt
		}
		if reportSHA != "" {
			line += " sha256=" + reportSHA
		}
		b.WriteString(line + "\n")
	} else {
		b.WriteString("- Latest report: none generated yet\n")
	}
	b.WriteString("- Evidence bundle: none generated yet\n")
	b.WriteString("- Operation ledger: `" + ledger.File(op.Dir) + "`\n")
	b.WriteString("- Operation directory: `" + op.Dir + "`\n")

	b.WriteString("\n## Finding Index\n\n")
	index, err := handoffFindingIndex(op)
	if err != nil {
		return "", err
	}
	b.WriteString(index)

	b.WriteString("\n## Findings\n\n")
	fr, err := findings.ReportMarkdown(op.Dir)
	if err != nil {
		return "", err
	}
	b.WriteString(strings.Join(fr, "\n") + "\n")

	b.WriteString("\n## Validation Plans\n\n")
	vr, err := validation.ReportMarkdown(op.Dir)
	if err != nil {
		return "", err
	}
	b.WriteString(strings.Join(vr, "\n") + "\n")

	b.WriteString("\n## Handoff Notes\n\n")
	b.WriteString("- Validate recipient and handling requirements before sharing any bundle path.\n")
	b.WriteString("- Use manifest hashes to verify copied evidence bundle files.\n")
	return b.String(), nil
}

func handoffFindingIndex(op *operation.Operation) (string, error) {
	rows, err := findings.Rows(op.Dir, op.Target, 1000000)
	if err != nil {
		return "", err
	}
	if len(rows) == 0 {
		return "- No findings recorded.\n", nil
	}
	var b strings.Builder
	for _, f := range rows {
		ev := strings.Join(f.Evidence, ",")
		if ev == "" {
			ev = "-"
		}
		// "- ID / severity / level / status: TITLE Evidence: ev."
		b.WriteString("- " + f.IDOr() + " / " + f.SeverityOr() + " / " + f.LevelOr() + " / " + f.StatusOr() + ": " + f.TitleOr() + " Evidence: " + ev + ".\n")
	}
	return b.String(), nil
}

func countLine(label string, n int) string {
	return "- " + label + ": " + itoa(n) + "\n"
}

func changeLine(label string, m readiness.Marker) string {
	if m.Present() {
		return "- " + label + ": " + m.At + " " + m.Event + "\n"
	}
	return "- " + label + ": none\n"
}

func itoa(n int) string { return strconv.Itoa(n) }
