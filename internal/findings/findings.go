// Package findings records findings in findings.ndjson and answers the
// count, sort and render questions the packets ask about them.
package findings

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ndjson"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// IndexFile returns findings.ndjson for an operation directory.
func IndexFile(opDir string) string { return filepath.Join(opDir, "findings.ndjson") }

// Dir returns the findings directory, used only to claim IDs.
func Dir(opDir string) string { return filepath.Join(opDir, "findings") }

// Finding is the latest state of one finding. Optional fields written by
// later lifecycle commands (update, accept, review) are kept so that
// packets render shell-build sessions faithfully.
type Finding struct {
	ID             string
	Operation      string
	Target         string
	Title          string
	Level          string
	Severity       string
	Confidence     string
	Status         string
	Source         string
	Impact         string
	Recommendation string
	Evidence       []string
	Validations    []string
	CreatedAt      string
	UpdatedAt      string
	AcceptedReason string
	AcceptedOwner  string
	AcceptedUntil  string
	AcceptedBy     string
	ReviewReason   string
	ReviewedBy     string
	Note           string
}

func ValidLevel(s string) bool {
	return s == "observed" || s == "inferred" || s == "validated"
}

func ValidSeverity(s string) bool {
	switch s {
	case "info", "low", "medium", "high", "critical":
		return true
	}
	return false
}

func ValidConfidence(s string) bool { return s == "low" || s == "medium" || s == "high" }

func ValidStatus(s string) bool {
	switch s {
	case "open", "accepted", "resolved", "validated":
		return true
	}
	return false
}

// SeverityWeight mirrors the jq severity_weight helper.
func SeverityWeight(s string) int {
	switch s {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	}
	return 0
}

// AddParams holds the inputs to Add.
type AddParams struct {
	Title          string
	Target         string
	Level          string
	Severity       string
	Confidence     string
	Status         string
	Source         string
	Impact         string
	Recommendation string
	Evidence       []string
}

// Add mirrors cmd_finding_add.
func Add(op *operation.Operation, p AddParams) (*Finding, error) {
	if p.Title == "" {
		return nil, state.Failf("finding title is required")
	}
	if p.Level == "" {
		p.Level = "inferred"
	}
	if p.Severity == "" {
		p.Severity = "info"
	}
	if p.Confidence == "" {
		p.Confidence = "medium"
	}
	if p.Source == "" {
		p.Source = state.ToolName
	}
	if !ValidLevel(p.Level) {
		return nil, state.Failf("expected finding level observed, inferred, or validated; got: %s", p.Level)
	}
	if !ValidSeverity(p.Severity) {
		return nil, state.Failf("expected severity info, low, medium, high, or critical; got: %s", p.Severity)
	}
	if !ValidConfidence(p.Confidence) {
		return nil, state.Failf("expected confidence low, medium, or high; got: %s", p.Confidence)
	}
	if p.Status == "" {
		if p.Level == "validated" {
			p.Status = "validated"
		} else {
			p.Status = "open"
		}
	}
	if !ValidStatus(p.Status) {
		return nil, state.Failf("expected status open, accepted, resolved, or validated; got: %s", p.Status)
	}
	if p.Target == "" {
		p.Target = op.Target
	}
	if err := op.Preflight(scope.ReadOnly, state.ToolName, p.Target, "record finding"); err != nil {
		return nil, err
	}
	var evidenceIDs []string
	for _, id := range p.Evidence {
		if id == "" {
			continue
		}
		ok, err := evidence.Exists(op.Dir, id)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, state.Failf("unknown evidence id for active operation: %s", id)
		}
		evidenceIDs = append(evidenceIDs, id)
	}
	root := Dir(op.Dir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	id := state.NextID(root, "finding")
	if err := os.Mkdir(filepath.Join(root, id), 0o700); err != nil {
		return nil, err
	}
	f := &Finding{ID: id, Operation: op.Slug, Target: p.Target, Title: p.Title, Level: p.Level,
		Severity: p.Severity, Confidence: p.Confidence, Status: p.Status, Source: p.Source,
		Impact: p.Impact, Recommendation: p.Recommendation, Evidence: evidenceIDs, CreatedAt: state.Timestamp()}
	if evidenceIDs == nil {
		evidenceIDs = []string{}
	}
	obj := ndjson.Object{
		{Key: "id", Value: f.ID},
		{Key: "operation", Value: f.Operation},
		{Key: "target", Value: f.Target},
		{Key: "title", Value: f.Title},
		{Key: "level", Value: f.Level},
		{Key: "severity", Value: f.Severity},
		{Key: "confidence", Value: f.Confidence},
		{Key: "status", Value: f.Status},
		{Key: "source", Value: f.Source},
		{Key: "impact", Value: f.Impact},
		{Key: "recommendation", Value: f.Recommendation},
		{Key: "evidence", Value: evidenceIDs},
		{Key: "created_at", Value: f.CreatedAt},
	}
	if err := ndjson.Append(IndexFile(op.Dir), obj); err != nil {
		return nil, err
	}
	detail := fmt.Sprintf("finding=%s level=%s severity=%s status=%s", id, p.Level, p.Severity, p.Status)
	if err := op.AppendLedger("finding.recorded", scope.ReadOnly, state.ToolName, "ok", detail); err != nil {
		return nil, err
	}
	return f, nil
}

func fromRecord(r ndjson.Record) Finding {
	return Finding{
		ID: r.String("id"), Operation: r.String("operation"), Target: r.String("target"),
		Title: r.String("title"), Level: r.String("level"), Severity: r.String("severity"),
		Confidence: r.String("confidence"), Status: r.String("status"), Source: r.String("source"),
		Impact: r.String("impact"), Recommendation: r.String("recommendation"),
		Evidence: r.Strings("evidence"), Validations: r.Strings("validations"),
		CreatedAt: r.String("created_at"), UpdatedAt: r.String("updated_at"),
		AcceptedReason: r.String("accepted_reason"), AcceptedOwner: r.String("accepted_owner"),
		AcceptedUntil: r.String("accepted_until"), AcceptedBy: r.String("accepted_by"),
		ReviewReason: r.String("review_reason"), ReviewedBy: r.String("reviewed_by"), Note: r.String("note"),
	}
}

// Latest returns the newest record per ID, filtered to target when
// non-empty, in first-seen order.
func Latest(opDir, target string) ([]Finding, error) {
	recs, err := ndjson.ReadFile(IndexFile(opDir))
	if err != nil {
		return nil, err
	}
	byID, order := ndjson.Latest(recs)
	var out []Finding
	for _, id := range order {
		f := fromRecord(byID[id])
		if target != "" && f.Target != target {
			continue
		}
		out = append(out, f)
	}
	return out, nil
}

// Count mirrors atlas_findings_count_for_target.
func Count(opDir, target string) (int, error) {
	fs, err := Latest(opDir, target)
	return len(fs), err
}

// OrDefault helpers reproduce the jq `// default` fallbacks.
func (f Finding) SeverityOr() string   { return or(f.Severity, "info") }
func (f Finding) LevelOr() string      { return or(f.Level, "inferred") }
func (f Finding) StatusOr() string     { return or(f.Status, "open") }
func (f Finding) ConfidenceOr() string { return or(f.Confidence, "medium") }
func (f Finding) TitleOr() string      { return or(f.Title, "untitled finding") }
func (f Finding) IDOr() string         { return or(f.ID, "?") }

// UpdatedOrCreated mirrors `.updated_at // .created_at // ""`.
func (f Finding) UpdatedOrCreated() string { return or(f.UpdatedAt, f.CreatedAt) }

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// Open mirrors atlas_readiness_open_findings_rows: not resolved, not
// accepted, sorted by severity weight, updated/created, id, reversed.
func Open(opDir, target string) ([]Finding, error) {
	fs, err := Latest(opDir, target)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, f := range fs {
		if s := f.StatusOr(); s == "resolved" || s == "accepted" {
			continue
		}
		out = append(out, f)
	}
	sortReverse(out, func(a, b Finding) int {
		if c := cmpInt(SeverityWeight(a.SeverityOr()), SeverityWeight(b.SeverityOr())); c != 0 {
			return c
		}
		if c := strings.Compare(a.UpdatedOrCreated(), b.UpdatedOrCreated()); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// Accepted returns findings whose status is accepted.
func Accepted(opDir, target string) ([]Finding, error) {
	fs, err := Latest(opDir, target)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, f := range fs {
		if f.StatusOr() == "accepted" {
			out = append(out, f)
		}
	}
	return out, nil
}

// ExpiredAccepted mirrors atlas_readiness_expired_accepted_risk_rows.
func ExpiredAccepted(opDir, target, today string) ([]Finding, error) {
	fs, err := Accepted(opDir, target)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, f := range fs {
		until := f.AcceptedUntil
		if len(until) >= 10 {
			until = until[:10]
		}
		if until != "" && until < today {
			out = append(out, f)
		}
	}
	sortReverse(out, func(a, b Finding) int {
		if c := strings.Compare(acceptedDate(a), acceptedDate(b)); c != 0 {
			return c
		}
		if c := cmpInt(SeverityWeight(a.SeverityOr()), SeverityWeight(b.SeverityOr())); c != 0 {
			return c
		}
		if c := strings.Compare(a.UpdatedOrCreated(), b.UpdatedOrCreated()); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

func acceptedDate(f Finding) string {
	if len(f.AcceptedUntil) >= 10 {
		return f.AcceptedUntil[:10]
	}
	return f.AcceptedUntil
}

// Rows mirrors atlas_findings_rows_for_target ordering: updated/created
// then id, reversed, limited.
func Rows(opDir, target string, limit int) ([]Finding, error) {
	fs, err := Latest(opDir, target)
	if err != nil {
		return nil, err
	}
	sortReverse(fs, func(a, b Finding) int {
		if c := strings.Compare(a.UpdatedOrCreated(), b.UpdatedOrCreated()); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	if limit > 0 && len(fs) > limit {
		fs = fs[:limit]
	}
	return fs, nil
}

// ByLevel mirrors atlas_report_finding_rows_by_level: severity weight then
// updated/created, reversed.
func ByLevel(opDir, target, level string) ([]Finding, error) {
	fs, err := Latest(opDir, target)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, f := range fs {
		if f.Level == level {
			out = append(out, f)
		}
	}
	sortReverse(out, func(a, b Finding) int {
		if c := cmpInt(SeverityWeight(a.SeverityOr()), SeverityWeight(b.SeverityOr())); c != 0 {
			return c
		}
		return strings.Compare(a.UpdatedOrCreated(), b.UpdatedOrCreated())
	})
	return out, nil
}

// LatestFinding mirrors atlas_brief_latest_finding: sort by updated/created
// then id, take last.
func LatestFinding(opDir, target string) (*Finding, error) {
	fs, err := Latest(opDir, target)
	if err != nil || len(fs) == 0 {
		return nil, err
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].UpdatedOrCreated() != fs[j].UpdatedOrCreated() {
			return fs[i].UpdatedOrCreated() < fs[j].UpdatedOrCreated()
		}
		return fs[i].ID < fs[j].ID
	})
	f := fs[len(fs)-1]
	return &f, nil
}

// HighestSeverity mirrors atlas_report_highest_severity.
func HighestSeverity(opDir, target string) (string, error) {
	fs, err := Latest(opDir, target)
	if err != nil {
		return "", err
	}
	if len(fs) == 0 {
		return "none", nil
	}
	best := ""
	bestW := -1
	for _, f := range fs {
		if w := SeverityWeight(f.SeverityOr()); w >= bestW {
			bestW = w
			best = f.SeverityOr()
		}
	}
	return best, nil
}

// ReportLine mirrors the jq rendering in atlas_findings_report_markdown.
func (f Finding) ReportLine() string {
	var b strings.Builder
	fmt.Fprintf(&b, "- %s / %s / %s: %s", f.SeverityOr(), f.LevelOr(), f.StatusOr(), f.TitleOr())
	if f.Impact != "" {
		b.WriteString(" Impact: " + f.Impact + ".")
	}
	if f.Recommendation != "" {
		b.WriteString(" Recommendation: " + f.Recommendation + ".")
	}
	if len(f.Evidence) > 0 {
		b.WriteString(" Evidence: " + strings.Join(f.Evidence, ", ") + ".")
	}
	if len(f.Validations) > 0 {
		b.WriteString(" Validation plans: " + strings.Join(f.Validations, ", ") + ".")
	}
	if f.AcceptedReason != "" {
		b.WriteString(" Accepted risk: " + f.AcceptedReason + ".")
		if f.AcceptedOwner != "" {
			b.WriteString(" Owner: " + f.AcceptedOwner + ".")
		}
		if f.AcceptedUntil != "" {
			b.WriteString(" Accepted until: " + f.AcceptedUntil + ".")
		}
		if f.AcceptedBy != "" {
			b.WriteString(" Accepted by: " + f.AcceptedBy + ".")
		}
		if f.ReviewReason != "" {
			b.WriteString(" Risk review: " + f.ReviewReason + ".")
		}
		if f.ReviewedBy != "" {
			b.WriteString(" Reviewed by: " + f.ReviewedBy + ".")
		}
	}
	if f.Note != "" {
		b.WriteString(" Latest note: " + f.Note + ".")
	}
	return b.String()
}

// ReviewLine mirrors the awk rendering in atlas_report_print_finding_level.
func (f Finding) ReviewLine() string {
	var b strings.Builder
	fmt.Fprintf(&b, "- %s / %s / %s: %s", f.SeverityOr(), f.ConfidenceOr(), f.StatusOr(), f.TitleOr())
	if f.Impact != "" {
		b.WriteString(" Impact: " + f.Impact + ".")
	}
	if f.Recommendation != "" {
		b.WriteString(" Recommendation: " + f.Recommendation + ".")
	}
	if len(f.Evidence) > 0 {
		b.WriteString(" Evidence: " + strings.Join(f.Evidence, ", ") + ".")
	}
	if len(f.Validations) > 0 {
		b.WriteString(" Validation plans: " + strings.Join(f.Validations, ", ") + ".")
	}
	if f.AcceptedReason != "" {
		b.WriteString(" Accepted risk: " + f.AcceptedReason + ".")
	}
	if f.AcceptedOwner != "" {
		b.WriteString(" Owner: " + f.AcceptedOwner + ".")
	}
	if f.AcceptedUntil != "" {
		b.WriteString(" Accepted until: " + f.AcceptedUntil + ".")
	}
	if f.AcceptedBy != "" {
		b.WriteString(" Accepted by: " + f.AcceptedBy + ".")
	}
	if f.ReviewReason != "" {
		b.WriteString(" Risk review: " + f.ReviewReason + ".")
	}
	if f.ReviewedBy != "" {
		b.WriteString(" Reviewed by: " + f.ReviewedBy + ".")
	}
	if f.Note != "" {
		b.WriteString(" Latest note: " + f.Note + ".")
	}
	return b.String()
}

// ReportMarkdown mirrors atlas_findings_report_markdown: sorted ascending by
// updated/created then id (no target filter).
func ReportMarkdown(opDir string) ([]string, error) {
	fs, err := Latest(opDir, "")
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return []string{"- No reviewed findings recorded yet."}, nil
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].UpdatedOrCreated() != fs[j].UpdatedOrCreated() {
			return fs[i].UpdatedOrCreated() < fs[j].UpdatedOrCreated()
		}
		return fs[i].ID < fs[j].ID
	})
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ReportLine())
	}
	return out, nil
}

func cmpInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// sortReverse sorts ascending by cmp then reverses, reproducing jq's
// `sort_by(...) | reverse` including its treatment of ties.
func sortReverse(fs []Finding, cmp func(a, b Finding) int) {
	sort.SliceStable(fs, func(i, j int) bool { return cmp(fs[i], fs[j]) < 0 })
	for i, j := 0, len(fs)-1; i < j; i, j = i+1, j-1 {
		fs[i], fs[j] = fs[j], fs[i]
	}
}
