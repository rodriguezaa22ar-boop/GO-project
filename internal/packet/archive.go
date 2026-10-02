package packet

import (
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/readiness"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// auditPacketVerificationStatus verifies the latest audit packet.
func auditPacketVerificationStatus(op *operation.Operation, st *readiness.State) (status, path string) {
	if !st.AuditPacket.Present() {
		return "missing", "-"
	}
	path = st.AuditPacket.Detail
	if !state.FileExists(path) {
		return "missing", path
	}
	res, err := AuditVerify(op, path)
	if err != nil || res.Status != "verified" {
		return "attention-required", path
	}
	return "verified", path
}

func reviewPacketVerificationStatus(st *readiness.State) (status, path string) {
	if st.AcceptedCount == 0 {
		return "not-required", "-"
	}
	if !st.ReviewPacket.Present() {
		return "missing", "-"
	}
	return "verified", st.ReviewPacket.Detail // Lite has no review packets
}

func archiveStatus(st *readiness.State, closeoutStatus, auditStatus, reviewStatus string) string {
	switch {
	case st.Status != "ready":
		return "attention-required"
	case st.ReportFresh != "current":
		return "attention-required"
	case st.BundleFresh == "stale" || st.HandoffFresh == "stale" || st.CloseoutFresh == "stale" ||
		(st.AcceptedCount > 0 && st.ReviewFresh == "stale") || st.AuditFresh == "stale" || st.ArchiveFresh == "stale":
		return "attention-required"
	case !st.Closeout.Present() || (st.AcceptedCount > 0 && !st.ReviewPacket.Present()) ||
		!st.AuditPacket.Present() || !st.ArchivePacket.Present():
		return "incomplete"
	case closeoutStatus != "verified" || (st.AcceptedCount > 0 && reviewStatus != "verified") || auditStatus != "verified":
		return "attention-required"
	}
	return "current"
}

func archiveNextStep(st *readiness.State, closeoutStatus, auditStatus, reviewStatus string) string {
	switch {
	case st.Status != "ready":
		return st.NextStep
	case st.ReportFresh != "current":
		return "Refresh the operation report before archiving."
	case st.BundleFresh == "stale":
		return "Regenerate the evidence bundle if the archive includes handoff evidence."
	case st.HandoffFresh == "stale":
		return "Regenerate the handoff packet if the archive includes handoff materials."
	case !st.Closeout.Present():
		return "Generate a closeout manifest before final archive review."
	case st.CloseoutFresh == "stale":
		return "Regenerate the closeout manifest before final archive review."
	case closeoutStatus != "verified":
		return "Resolve closeout verification issues before final archive review."
	case st.AcceptedCount > 0 && !st.ReviewPacket.Present():
		return "Generate an accepted-risk review packet before final archive review."
	case st.AcceptedCount > 0 && st.ReviewFresh == "stale":
		return "Regenerate the accepted-risk review packet before final archive review."
	case st.AcceptedCount > 0 && reviewStatus != "verified":
		return "Resolve accepted-risk review packet verification issues before final archive review."
	case !st.AuditPacket.Present():
		return "Generate an audit packet before final archive review."
	case st.AuditFresh == "stale":
		return "Regenerate the audit packet before final archive review."
	case auditStatus != "verified":
		return "Resolve audit packet verification issues before final archive review."
	case !st.ArchivePacket.Present():
		return "Generate an archive packet before final archive review."
	case st.ArchiveFresh == "stale":
		return "Regenerate the archive packet before final archive review."
	}
	return "Archive snapshot is current."
}

// Archive writes the archive packet. archive.packet.generated is appended
// before rendering, matching cmd_op_archive_packet.
func Archive(op *operation.Operation, packetName string) (string, error) {
	if packetName == "" {
		packetName = op.Slug + "-archive"
	}
	slug := state.Slugify(packetName)
	if slug == "" {
		return "", state.Failf("archive packet name produced an empty slug")
	}
	dir := packetDir(op, "archive")
	if err := state.MkdirAll(dir); err != nil {
		return "", err
	}
	path := dir + "/" + slug + ".md"
	if err := op.AppendLedger("archive.packet.generated", scope.ReadOnly, state.ToolName, "ok", path); err != nil {
		return "", err
	}
	body, err := renderArchive(op)
	if err != nil {
		return "", err
	}
	if err := writeMarkdown(path, body); err != nil {
		return "", err
	}
	if err := state.RecordHistory(op.Dir, "archive-packet", path); err != nil {
		return "", err
	}
	return path, nil
}

func renderArchive(op *operation.Operation) (string, error) {
	st, err := readiness.Collect(op)
	if err != nil {
		return "", err
	}
	reportAt, reportPath, reportSHA := reportFields(st)
	closeoutStatus, closeoutPath, closeoutProblems := closeoutVerificationStatus(op, st)
	auditStatus, auditPath := auditPacketVerificationStatus(op, st)
	reviewStatus, reviewPath := reviewPacketVerificationStatus(st)
	archStatus := archiveStatus(st, closeoutStatus, auditStatus, reviewStatus)
	archNext := archiveNextStep(st, closeoutStatus, auditStatus, reviewStatus)

	ledgerPath := ledger.File(op.Dir)
	ledgerEvents := ledgerEventCount(ledgerPath)
	ledgerSHA := shaForFile(ledgerPath)
	handoffSHA := shaForFile(readiness.PathOr(st.Handoff, ""))
	closeoutSHA := shaForFile(readiness.PathOr(st.Closeout, ""))
	auditSHA := shaForFile(readiness.PathOr(st.AuditPacket, ""))

	var b strings.Builder
	b.WriteString("# Atlas Operation Archive Packet\n\n")
	b.WriteString("Generated: " + state.Timestamp() + "\n")
	b.WriteString("Operation: " + op.Name + "\n")
	b.WriteString("Operation ID: " + op.Slug + "\n")
	b.WriteString("Operation Status: " + op.Status + "\n")
	b.WriteString("Target: " + op.Target + "\n")
	if op.TargetAddress != "" && op.TargetAddress != op.Target {
		b.WriteString("Address: " + op.TargetAddress + "\n")
	}
	b.WriteString("\nNo raw artifact contents are included in this archive packet.\n")

	b.WriteString("\n## Archive Status\n\n")
	b.WriteString("- Archive status: " + archStatus + "\n")
	b.WriteString("- Next archive step: " + archNext + "\n")

	b.WriteString("\n## Readiness\n\n")
	b.WriteString("- Close readiness: " + st.Status + "\n")
	b.WriteString(countLine("Evidence records", st.EvidenceCount))
	b.WriteString(countLine("Open findings", st.OpenCount))
	b.WriteString(countLine("Accepted risks", st.AcceptedCount))
	b.WriteString(countLine("Expired accepted risks", st.ExpiredAccepted))
	b.WriteString(countLine("Pending validation", st.PendingCount))
	b.WriteString("- Report freshness: " + st.ReportFresh + "\n")
	b.WriteString("- Bundle freshness: " + st.BundleFresh + "\n")
	b.WriteString("- Handoff freshness: " + st.HandoffFresh + "\n")
	b.WriteString("- Closeout freshness: " + st.CloseoutFresh + "\n")
	b.WriteString("- Accepted-risk review packet freshness: " + st.ReviewFresh + "\n")
	b.WriteString("- Audit packet freshness: " + st.AuditFresh + "\n")
	b.WriteString("- Archive packet freshness: " + st.ArchiveFresh + "\n")

	b.WriteString("\n## Verification\n\n")
	b.WriteString("- Closeout verification: " + closeoutStatus + " manifest=" + closeoutPath + " problems=" + itoa(closeoutProblems) + "\n")
	b.WriteString("- Accepted-risk review packet verification: " + reviewStatus + " packet=" + reviewPath + "\n")
	b.WriteString("- Audit packet verification: " + auditStatus + " packet=" + auditPath + "\n")

	b.WriteString("\n## Archive Artifacts\n\n")
	if reportPath != "" {
		b.WriteString("- Latest report: `" + reportPath + "` generated=" + reportAt + " sha256=" + reportSHA + "\n")
	} else {
		b.WriteString("- Latest report: none generated yet\n")
	}
	b.WriteString("- Evidence bundle: none generated yet\n")
	b.WriteString("- Evidence manifest: none\n")
	b.WriteString(backtickShaLine("Latest handoff", readiness.PathOr(st.Handoff, "none"), handoffSHA))
	b.WriteString(backtickShaLine("Latest closeout", readiness.PathOr(st.Closeout, "none"), closeoutSHA))
	b.WriteString(backtickShaLine("Latest accepted-risk review packet", readiness.PathOr(st.ReviewPacket, "none"), shaForFile(readiness.PathOr(st.ReviewPacket, ""))))
	b.WriteString(backtickShaLine("Latest audit packet", readiness.PathOr(st.AuditPacket, "none"), auditSHA))
	b.WriteString("- Latest archive packet: `" + readiness.PathOr(st.ArchivePacket, "none") + "`\n")
	b.WriteString("- Operation ledger: `" + ledgerPath + "` events=" + itoa(ledgerEvents) + " sha256=" + ledgerSHA + "\n")
	b.WriteString("- Operation directory: `" + op.Dir + "`\n")

	b.WriteString("\n## Retention Notes\n\n")
	b.WriteString("- Treat paths as local references; verify copied files against the recorded hashes before retention or transfer.\n")
	b.WriteString("- Keep this packet with the closeout manifest and audit packet for final review.\n")
	return b.String(), nil
}

// backtickShaLine renders "- Label: `path`" plus " sha256=X" when present.
func backtickShaLine(label, path, sha string) string {
	line := "- " + label + ": `" + path + "`"
	if sha != "" {
		line += " sha256=" + sha
	}
	return line + "\n"
}

var archiveAllowLater []string // archive is the last packet: no later events

// ArchiveVerify reproduces atlas_archive_verify_markdown_packet's pass/fail.
func ArchiveVerify(op *operation.Operation, packetPath string) (*VerifyResult, error) {
	text, err := readPacket(packetPath)
	if err != nil {
		return nil, err
	}
	id := field(text, "Operation ID")
	if id == "" {
		return nil, state.Failf("archive packet is missing Operation ID: %s", packetPath)
	}
	if id != op.Slug {
		return nil, state.Failf("archive packet belongs to '%s', not '%s'", id, op.Slug)
	}
	v := &VerifyResult{}
	c := &anchorCheck{v: v}
	for _, a := range []struct{ label, display string }{
		{"Latest report", "Latest Report"},
		{"Evidence manifest", "Evidence Manifest"},
		{"Latest handoff", "Latest Handoff"},
		{"Latest closeout", "Latest Closeout"},
		{"Latest accepted-risk review packet", "Accepted Risk Review Packet"},
		{"Latest audit packet", "Latest Audit Packet"},
	} {
		c.hashAnchorArchive(text, a.label, a.display)
	}
	c.ledgerAnchor(text, archiveAllowLater)
	finishStatus(v)
	return v, nil
}

// hashAnchorArchive is the archive variant: a `none` path is a gap, not a
// problem, matching atlas_archive_verify_hash_anchor.
func (c *anchorCheck) hashAnchorArchive(text, manifestLabel, display string) {
	line := anchorLine(text, manifestLabel)
	if line == "" {
		c.row(display, "unverifiable", "-", "anchor missing from packet")
		c.v.Problems++
		return
	}
	path := anchorPath(line)
	if path == "" || path == "none" {
		c.row(display, "not-recorded", orDash(path), "")
		c.v.Gaps++
		return
	}
	expected := anchorToken(line, "sha256")
	if expected == "" {
		c.row(display, "unverifiable", path, "missing expected sha256")
		c.v.Problems++
		return
	}
	if !state.FileExists(path) {
		c.row(display, "missing", path, "expected sha256="+expected)
		c.v.Problems++
		return
	}
	if shaForFile(path) == expected {
		c.row(display, "verified", path, "")
		c.v.Verified++
	} else {
		c.row(display, "changed", path, "expected="+expected)
		c.v.Problems++
	}
}
