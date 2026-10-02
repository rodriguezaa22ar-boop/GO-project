package packet

import (
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/readiness"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// closeoutVerificationStatus resolves the latest closeout manifest and
// verifies it, returning status, path and problem count, matching
// atlas_audit_closeout_verification_status.
func closeoutVerificationStatus(op *operation.Operation, st *readiness.State) (status, path string, problems int) {
	if !st.Closeout.Present() {
		return "missing", "-", 0
	}
	path = st.Closeout.Detail
	if path == "" || !state.FileExists(path) {
		if path == "" {
			path = "-"
		}
		return "missing", path, 1
	}
	res, err := CloseoutVerify(op, path)
	if err != nil {
		return "attention-required", path, 1
	}
	return res.Status, path, res.Problems
}

// Audit writes the audit packet. audit.packet.generated is appended before
// the packet is rendered, matching cmd_op_audit_packet.
func Audit(op *operation.Operation, packetName string) (string, error) {
	if packetName == "" {
		packetName = op.Slug + "-audit"
	}
	slug := state.Slugify(packetName)
	if slug == "" {
		return "", state.Failf("audit packet name produced an empty slug")
	}
	if !state.FileExists(ledger.File(op.Dir)) {
		return "", state.Failf("operation ledger is empty or missing: %s", ledger.File(op.Dir))
	}
	dir := packetDir(op, "audit")
	if err := state.MkdirAll(dir); err != nil {
		return "", err
	}
	path := dir + "/" + slug + ".md"
	if err := op.AppendLedger("audit.packet.generated", scope.ReadOnly, state.ToolName, "ok", path); err != nil {
		return "", err
	}
	body, err := renderAudit(op)
	if err != nil {
		return "", err
	}
	if err := writeMarkdown(path, body); err != nil {
		return "", err
	}
	if err := state.RecordHistory(op.Dir, "audit-packet", path); err != nil {
		return "", err
	}
	return path, nil
}

func renderAudit(op *operation.Operation) (string, error) {
	st, err := readiness.Collect(op)
	if err != nil {
		return "", err
	}
	ledgerPath := ledger.File(op.Dir)
	ledgerSHA := shaForFile(ledgerPath)
	events, err := ledger.Read(op.Dir)
	if err != nil {
		return "", err
	}
	verStatus, verPath, verProblems := closeoutVerificationStatus(op, st)
	closeoutManifestSHA := ""
	if verPath != "" && verPath != "-" && state.FileExists(verPath) {
		closeoutManifestSHA = shaForFile(verPath)
	}

	var b strings.Builder
	b.WriteString("# Atlas Operation Audit Packet\n\n")
	b.WriteString("Generated: " + state.Timestamp() + "\n")
	b.WriteString("Operation: " + op.Name + "\n")
	b.WriteString("Operation ID: " + op.Slug + "\n")
	b.WriteString("Operation Status: " + op.Status + "\n")
	b.WriteString("Target: " + op.Target + "\n")
	b.WriteString("\nNo raw artifact contents are included in this audit packet.\n")

	b.WriteString("\n## Ledger\n\n")
	b.WriteString("- Operation ledger: `" + ledgerPath + "`\n")
	b.WriteString("- Events: " + itoa(len(events)) + "\n")
	b.WriteString("- Ledger SHA256: " + ledgerSHA + "\n")
	b.WriteString("- Closeout verification: " + verStatus + "\n")
	b.WriteString("- Closeout manifest: " + verPath + "\n")
	b.WriteString("- Closeout manifest SHA256: " + orNone(closeoutManifestSHA) + "\n")
	b.WriteString("- Closeout verification problems: " + itoa(verProblems) + "\n")
	b.WriteString(countLine("Accepted risks", st.AcceptedCount))
	b.WriteString("- Accepted-risk review packet: " + readiness.PathOr(st.ReviewPacket, "none") + "\n")
	b.WriteString("- Accepted-risk review packet freshness: " + st.ReviewFresh + "\n")
	b.WriteString("- Audit packet freshness: " + st.AuditFresh + "\n")

	b.WriteString("\n## Event Counts\n\n```text\n")
	for _, s := range ledger.CountByEvent(events) {
		b.WriteString(pad(s.Event, 32) + " " + itoa(s.Count) + "\n")
	}
	b.WriteString("```\n")

	b.WriteString("\n## Audit Flags\n\n```text\n")
	b.WriteString(auditFlags(op, st, events, verStatus, verPath, verProblems))
	b.WriteString("```\n")

	b.WriteString("\n## Timeline\n\n```text\n")
	b.WriteString(pad("TS", 20) + " " + pad("EVENT", 28) + " " + pad("STATUS", 12) + " " + pad("CAPABILITY", 16) + " " + pad("TOOL", 10) + " DETAIL\n")
	for _, e := range events {
		b.WriteString(e.Describe() + "\n")
	}
	b.WriteString("```\n")
	return b.String(), nil
}

func auditFlags(op *operation.Operation, st *readiness.State, events []ledger.Event, verStatus, verPath string, verProblems int) string {
	var lines []string
	for _, e := range events {
		if e.Event == "scope.preflight" && e.Status == "denied" {
			lines = append(lines, "denied preflight: "+e.TS+" "+e.Detail)
		}
	}
	for _, e := range events {
		if e.Event == "op.close.readiness" && contains(e.Detail, "force=1") {
			lines = append(lines, "forced close: "+e.TS+" readiness="+e.Status+" "+e.Detail)
		}
	}
	if st.ReportFresh == "stale" {
		lines = append(lines, "stale report: "+readiness.PathOr(st.Report, "none"))
	}
	if st.HandoffFresh == "stale" {
		lines = append(lines, "stale handoff: "+readiness.PathOr(st.Handoff, "none"))
	}
	if st.CloseoutFresh == "stale" {
		lines = append(lines, "stale closeout: "+readiness.PathOr(st.Closeout, "none"))
	}
	if st.AuditFresh == "stale" {
		lines = append(lines, "stale audit packet: "+readiness.PathOr(st.AuditPacket, "none"))
	}
	if st.ArchiveFresh == "stale" {
		lines = append(lines, "stale archive packet: "+readiness.PathOr(st.ArchivePacket, "none"))
	}
	var b strings.Builder
	if verStatus == "verified" {
		if len(lines) == 0 {
			// The shell still prints the verification note before the
			// "no audit flags" line is suppressed by the note's presence.
		}
	}
	for _, l := range lines {
		b.WriteString(l + "\n")
	}
	if verStatus == "verified" {
		b.WriteString("note: closeout verification: verified manifest=" + verPath + "\n")
	} else {
		b.WriteString("closeout verification: " + verStatus + " manifest=" + verPath + " problems=" + itoa(verProblems) + "\n")
	}
	if len(lines) == 0 && verStatus != "verified" {
		// problems already reported above
	}
	return b.String()
}

var auditAllowLater = []string{"archive.packet.generated"}

// AuditVerify reproduces atlas_audit_verify_markdown_packet's pass/fail.
func AuditVerify(op *operation.Operation, packetPath string) (*VerifyResult, error) {
	text, err := readPacket(packetPath)
	if err != nil {
		return nil, err
	}
	id := field(text, "Operation ID")
	if id == "" {
		return nil, state.Failf("audit packet is missing Operation ID: %s", packetPath)
	}
	if id != op.Slug {
		return nil, state.Failf("audit packet belongs to '%s', not '%s'", id, op.Slug)
	}
	v := &VerifyResult{}
	c := &anchorCheck{v: v}

	ledgerLine := anchorLine(text, "Operation ledger")
	ledgerFile := anchorPath(ledgerLine)
	expectedEvents := bulletValue(text, "Events")
	expectedSHA := bulletValue(text, "Ledger SHA256")
	switch {
	case ledgerFile == "" || expectedEvents == "" || expectedSHA == "":
		c.row("Operation Ledger", "unverifiable", orDash(ledgerFile), "missing events or sha256")
		v.Problems++
	case !state.FileExists(ledgerFile):
		c.row("Operation Ledger", "missing", ledgerFile, "expected events="+expectedEvents+" sha256="+expectedSHA)
		v.Problems++
	default:
		actualEvents := ledgerEventCount(ledgerFile)
		actualSHA := shaForFile(ledgerFile)
		exp := atoi(expectedEvents)
		if itoa(actualEvents) == expectedEvents && actualSHA == expectedSHA {
			c.row("Operation Ledger", "verified", ledgerFile, "events="+itoa(actualEvents))
			v.Verified++
		} else if exp >= 0 && actualEvents > exp {
			prefix, _ := ledger.PrefixSHA256(ledgerFile, exp)
			if prefix == expectedSHA && !hasDisallowedLater(ledgerFile, exp, auditAllowLater) {
				c.row("Operation Ledger", "verified", ledgerFile, "events="+itoa(actualEvents)+" anchored_events="+expectedEvents)
				v.Verified++
			} else {
				c.row("Operation Ledger", "changed", ledgerFile, "expected_events="+expectedEvents+" actual_events="+itoa(actualEvents))
				v.Problems++
			}
		} else {
			c.row("Operation Ledger", "changed", ledgerFile, "expected_events="+expectedEvents+" actual_events="+itoa(actualEvents))
			v.Problems++
		}
	}

	closeoutManifest := bulletValue(text, "Closeout manifest")
	expectedCloseoutSHA := bulletValue(text, "Closeout manifest SHA256")
	if closeoutManifest != "" && closeoutManifest != "-" && closeoutManifest != "none" {
		switch {
		case expectedCloseoutSHA == "" || expectedCloseoutSHA == "none":
			c.row("Closeout Manifest", "unverifiable", closeoutManifest, "missing sha256")
			v.Problems++
		case !state.FileExists(closeoutManifest):
			c.row("Closeout Manifest", "missing", closeoutManifest, "expected sha256="+expectedCloseoutSHA)
			v.Problems++
		default:
			if shaForFile(closeoutManifest) == expectedCloseoutSHA {
				c.row("Closeout Manifest", "verified", closeoutManifest, "")
				v.Verified++
			} else {
				c.row("Closeout Manifest", "changed", closeoutManifest, "expected sha256="+expectedCloseoutSHA)
				v.Problems++
			}
		}
	}
	finishStatus(v)
	return v, nil
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
