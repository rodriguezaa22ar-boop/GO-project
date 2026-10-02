// Package readiness derives the operation's close readiness and the
// freshness of each retention packet from the ledger, following the rules
// in the shell build's readiness.sh so both implementations agree.
package readiness

import (
	"fmt"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
	"github.com/rodriguezaa22ar-boop/go-project/internal/validation"
)

// Marker is a ledger event of interest.
type Marker struct {
	At     string
	Line   int
	Event  string
	Detail string
}

// Present reports whether the marker exists in the ledger.
func (m Marker) Present() bool { return m.At != "" }

func marker(e *ledger.Event) Marker {
	if e == nil {
		return Marker{}
	}
	return Marker{At: e.TS, Line: e.Line, Event: e.Event, Detail: e.Detail}
}

func after(candidate, baseline Marker) bool {
	if !candidate.Present() || !baseline.Present() {
		return false
	}
	if candidate.At > baseline.At {
		return true
	}
	return candidate.At == baseline.At && candidate.Line > 0 && baseline.Line > 0 && candidate.Line > baseline.Line
}

func freshness(packet Marker, changes ...Marker) string {
	if !packet.Present() {
		return "missing"
	}
	for _, c := range changes {
		if after(c, packet) {
			return "stale"
		}
	}
	return "current"
}

var materialEvents = []string{
	"tool.completed", "artifact.created", "artifact.redacted", "finding.recorded",
	"finding.updated", "finding.accepted", "finding.reviewed", "approval.granted",
	"validation.planned", "validation.approved", "validation.executed", "validation.retested",
}

var reviewChangeEvents = []string{"finding.recorded", "finding.updated", "finding.accepted", "finding.reviewed"}

// State holds the collected readiness values.
type State struct {
	EvidenceCount      int
	FindingCount       int
	ValidationCount    int
	OpenCount          int
	AcceptedCount      int
	ExpiredAccepted    int
	PendingCount       int
	Report             Marker
	Bundle             Marker
	Handoff            Marker
	Closeout           Marker
	AuditPacket        Marker
	ArchivePacket      Marker
	ReviewPacket       Marker
	LatestLedger       Marker
	LatestChange       Marker
	LatestEvidence     Marker
	LatestReviewChange Marker
	ReportFresh        string
	BundleFresh        string
	HandoffFresh       string
	CloseoutFresh      string
	AuditFresh         string
	ArchiveFresh       string
	ReviewFresh        string
	Status             string
	NextStep           string
	OpenFindings       []findings.Finding
	Expired            []findings.Finding
	Pending            []validation.Plan
}

// Collect computes readiness for the operation's own target.
func Collect(op *operation.Operation) (*State, error) {
	target := op.Target
	s := &State{}
	var err error
	if s.EvidenceCount, err = evidence.Count(op.Dir, target); err != nil {
		return nil, err
	}
	if s.FindingCount, err = findings.Count(op.Dir, target); err != nil {
		return nil, err
	}
	if s.ValidationCount, err = validation.Count(op.Dir, target); err != nil {
		return nil, err
	}
	if s.OpenFindings, err = findings.Open(op.Dir, target); err != nil {
		return nil, err
	}
	s.OpenCount = len(s.OpenFindings)
	accepted, err := findings.Accepted(op.Dir, target)
	if err != nil {
		return nil, err
	}
	s.AcceptedCount = len(accepted)
	if s.Expired, err = findings.ExpiredAccepted(op.Dir, target, state.Today()); err != nil {
		return nil, err
	}
	s.ExpiredAccepted = len(s.Expired)
	if s.Pending, err = validation.Pending(op.Dir, target); err != nil {
		return nil, err
	}
	s.PendingCount = len(s.Pending)

	events, err := ledger.Read(op.Dir)
	if err != nil {
		return nil, err
	}
	s.Report = marker(ledger.Latest(events, "report.generated"))
	s.Bundle = marker(ledger.Latest(events, "evidence.bundle.generated"))
	s.Handoff = marker(ledger.Latest(events, "handoff.generated"))
	s.Closeout = marker(ledger.Latest(events, "closeout.manifest.generated"))
	s.AuditPacket = marker(ledger.Latest(events, "audit.packet.generated"))
	s.ArchivePacket = marker(ledger.Latest(events, "archive.packet.generated"))
	s.ReviewPacket = marker(ledger.Latest(events, "finding.review_packet.generated"))
	if len(events) > 0 {
		s.LatestLedger = marker(&events[len(events)-1])
	}
	s.LatestChange = marker(ledger.Latest(events, materialEvents...))
	s.LatestEvidence = marker(ledger.Latest(events, "artifact.created", "artifact.redacted"))
	s.LatestReviewChange = marker(ledger.Latest(events, reviewChangeEvents...))
	auditChange := marker(ledger.LatestExcept(events, "archive.packet.generated"))

	s.ReportFresh = freshness(s.Report, s.LatestChange)
	s.BundleFresh = freshness(s.Bundle, s.LatestEvidence)
	s.HandoffFresh = freshness(s.Handoff, s.LatestChange, s.Report, s.Bundle)
	s.CloseoutFresh = freshness(s.Closeout, s.LatestChange, s.Report, s.Bundle, s.Handoff)
	s.AuditFresh = freshness(s.AuditPacket, auditChange)
	s.ArchiveFresh = freshness(s.ArchivePacket, s.LatestLedger)
	s.ReviewFresh = freshness(s.ReviewPacket, s.LatestReviewChange)

	if s.PendingCount > 0 || s.OpenCount > 0 || s.ExpiredAccepted > 0 || s.EvidenceCount == 0 || !s.Report.Present() || s.ReportFresh == "stale" {
		s.Status = "attention-required"
	} else {
		s.Status = "ready"
	}
	s.NextStep = s.nextStep()
	return s, nil
}

func (s *State) nextStep() string {
	switch {
	case s.PendingCount > 0:
		return "Run or retire pending validation before closure."
	case s.OpenCount > 0:
		return "Resolve, accept, or retest unresolved findings before closure."
	case s.ExpiredAccepted > 0:
		return "Review expired accepted risks before closure."
	case s.EvidenceCount == 0:
		return "Add at least one evidence record before closure."
	case !s.Report.Present():
		return "Generate an operation report before closure."
	case s.ReportFresh == "stale":
		return "Refresh the operation report before closure."
	case !s.Bundle.Present():
		return "Operation is ready to close; generate an evidence bundle if handoff is required."
	case s.BundleFresh == "stale":
		return "Operation is ready to close; regenerate the evidence bundle if handoff is required."
	case !s.Handoff.Present():
		return "Operation is ready to close; generate a handoff packet if handoff is required."
	case s.HandoffFresh == "stale":
		return "Operation is ready to close; regenerate the handoff packet if handoff is required."
	case !s.Closeout.Present():
		return "Operation is ready to close; generate a closeout manifest after closure if final audit is required."
	case s.CloseoutFresh == "stale":
		return "Operation is ready to close; regenerate the closeout manifest if final audit is required."
	case !s.AuditPacket.Present():
		return "Operation is ready to close; generate an audit packet if final audit is required."
	case s.AuditFresh == "stale":
		return "Operation is ready to close; regenerate the audit packet if final audit is required."
	case !s.ArchivePacket.Present():
		return "Operation is ready to close; generate an archive packet if final retention is required."
	case s.ArchiveFresh == "stale":
		return "Operation is ready to close; regenerate the archive packet if final retention is required."
	}
	return "Operation is ready to close."
}

// PathOr returns the marker's detail (a path) or fallback.
func PathOr(m Marker, fallback string) string {
	if m.Detail == "" {
		return fallback
	}
	return m.Detail
}

// LedgerDetail mirrors atlas_readiness_ledger_detail.
func (s *State) LedgerDetail(force bool) string {
	f := "0"
	if force {
		f = "1"
	}
	return fmt.Sprintf("readiness=%s evidence=%d open_findings=%d accepted_risks=%d expired_accepted_risks=%d pending_validation=%d report_freshness=%s bundle_freshness=%s handoff_freshness=%s closeout_freshness=%s review_packet_freshness=%s audit_packet_freshness=%s archive_packet_freshness=%s latest_report=%s latest_change=%s evidence_bundle=%s handoff=%s closeout=%s review_packet=%s audit_packet=%s archive_packet=%s force=%s",
		s.Status, s.EvidenceCount, s.OpenCount, s.AcceptedCount, s.ExpiredAccepted, s.PendingCount,
		s.ReportFresh, s.BundleFresh, s.HandoffFresh, s.CloseoutFresh, s.ReviewFresh, s.AuditFresh, s.ArchiveFresh,
		PathOr(s.Report, "none"), orNone(s.LatestChange.Event), PathOr(s.Bundle, "none"), PathOr(s.Handoff, "none"),
		PathOr(s.Closeout, "none"), PathOr(s.ReviewPacket, "none"), PathOr(s.AuditPacket, "none"), PathOr(s.ArchivePacket, "none"), f)
}

func orNone(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

// Lines renders the Operation Readiness block the shell build prints.
func (s *State) Lines(op *operation.Operation) []string {
	target := op.Target
	var out []string
	add := func(k, v string) { out = append(out, k+": "+v) }
	markerOr := func(m Marker) string {
		if m.Present() {
			return m.At + " " + m.Detail
		}
		return "none generated yet"
	}
	changeOr := func(m Marker) string {
		if m.Present() {
			return m.At + " " + m.Event
		}
		return "none"
	}
	out = append(out, "Operation Readiness", rule)
	add("Operation", op.Name)
	add("Operation Status", op.Status)
	add("Target", target)
	add("Evidence Records", fmt.Sprint(s.EvidenceCount))
	add("Findings", fmt.Sprint(s.FindingCount))
	add("Open Findings", fmt.Sprint(s.OpenCount))
	add("Accepted Risks", fmt.Sprint(s.AcceptedCount))
	add("Expired Accepted Risks", fmt.Sprint(s.ExpiredAccepted))
	add("Validation Plans", fmt.Sprint(s.ValidationCount))
	add("Pending Validation", fmt.Sprint(s.PendingCount))
	add("Latest Report", markerOr(s.Report))
	add("Report Freshness", s.ReportFresh)
	add("Latest State Change", changeOr(s.LatestChange))
	add("Evidence Bundle", markerOr(s.Bundle))
	add("Bundle Freshness", s.BundleFresh)
	add("Latest Evidence Change", changeOr(s.LatestEvidence))
	add("Latest Handoff", markerOr(s.Handoff))
	add("Handoff Freshness", s.HandoffFresh)
	add("Latest Closeout", markerOr(s.Closeout))
	add("Closeout Freshness", s.CloseoutFresh)
	add("Latest Accepted Risk Review Packet", markerOr(s.ReviewPacket))
	add("Accepted Risk Review Packet Freshness", s.ReviewFresh)
	add("Latest Accepted Risk Change", changeOr(s.LatestReviewChange))
	add("Latest Audit Packet", markerOr(s.AuditPacket))
	add("Audit Packet Freshness", s.AuditFresh)
	add("Latest Archive Packet", markerOr(s.ArchivePacket))
	add("Archive Packet Freshness", s.ArchiveFresh)
	if s.LatestLedger.Present() {
		add("Latest Ledger Event", s.LatestLedger.At+" "+s.LatestLedger.Event)
	} else {
		add("Latest Ledger Event", "none")
	}
	add("Close Readiness", s.Status)
	add("Next Step", s.NextStep)
	out = append(out, rule, "Open Findings")
	if len(s.OpenFindings) == 0 {
		out = append(out, "note: no unresolved findings remain")
	}
	for i, f := range s.OpenFindings {
		if i >= 8 {
			break
		}
		out = append(out, fmt.Sprintf("%-24s %-8s %-10s %-10s %s", f.IDOr(), f.SeverityOr(), f.LevelOr(), f.StatusOr(), f.TitleOr()))
	}
	out = append(out, rule, "Expired Accepted Risks")
	if len(s.Expired) == 0 {
		out = append(out, "note: no expired accepted risks detected")
	}
	for i, f := range s.Expired {
		if i >= 8 {
			break
		}
		owner, reason := f.AcceptedOwner, f.AcceptedReason
		if owner == "" {
			owner = "-"
		}
		if reason == "" {
			reason = "-"
		}
		until := f.AcceptedUntil
		if len(until) >= 10 {
			until = until[:10]
		}
		out = append(out, fmt.Sprintf("%-24s %-8s %-10s expires=%-10s owner=%-12s %s reason=%s", f.IDOr(), f.SeverityOr(), f.LevelOr(), until, owner, f.TitleOr(), reason))
	}
	out = append(out, rule, "Pending Validation")
	if len(s.Pending) == 0 {
		out = append(out, "note: no planned or approved validation is waiting")
	}
	for i, p := range s.Pending {
		if i >= 8 {
			break
		}
		finding := p.Finding
		if finding == "" {
			finding = "-"
		}
		out = append(out, fmt.Sprintf("%-24s %-12s %-10s %-24s %s", or(p.ID, "?"), or(p.Lane, "?"), or(p.Status, "?"), finding, p.Reason))
	}
	return out
}

const rule = "------------------------------------------------------------"

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// Join renders lines with newlines.
func Join(lines []string) string { return strings.Join(lines, "\n") + "\n" }
