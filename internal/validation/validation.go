// Package validation reads validation-plans.ndjson. Lite does not plan or
// run validation; it only reports plans the shell build recorded so that
// packets and readiness agree on sessions the shell build wrote.
package validation

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ndjson"
)

// IndexFile returns validation-plans.ndjson for an operation directory.
func IndexFile(opDir string) string { return filepath.Join(opDir, "validation-plans.ndjson") }

// Plan is the latest state of one validation plan.
type Plan struct {
	ID               string
	Target           string
	Lane             string
	Capability       string
	Status           string
	Finding          string
	Reason           string
	Evidence         []string
	ResultStatus     string
	RetestResult     string
	RetestNote       string
	SupersededBy     string
	SupersededReason string
	CreatedAt        string
	UpdatedAt        string
}

func fromRecord(r ndjson.Record) Plan {
	return Plan{
		ID: r.String("id"), Target: r.String("target"), Lane: r.String("lane"),
		Capability: r.String("capability"), Status: r.String("status"), Finding: r.String("finding"),
		Reason: r.String("reason"), Evidence: r.Strings("evidence"), ResultStatus: r.String("result_status"),
		RetestResult: r.String("retest_result"), RetestNote: r.String("retest_note"),
		SupersededBy: r.String("superseded_by_plan"), SupersededReason: r.String("superseded_reason"),
		CreatedAt: r.String("created_at"), UpdatedAt: r.String("updated_at"),
	}
}

// Latest returns the newest record per ID, filtered to target when set.
func Latest(opDir, target string) ([]Plan, error) {
	recs, err := ndjson.ReadFile(IndexFile(opDir))
	if err != nil {
		return nil, err
	}
	byID, order := ndjson.Latest(recs)
	var out []Plan
	for _, id := range order {
		p := fromRecord(byID[id])
		if target != "" && p.Target != target {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// Count mirrors atlas_validation_count_for_target.
func Count(opDir, target string) (int, error) {
	ps, err := Latest(opDir, target)
	return len(ps), err
}

// StatusCount mirrors atlas_brief_validation_status_count.
func StatusCount(opDir, target, status string) (int, error) {
	ps, err := Latest(opDir, target)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, p := range ps {
		if p.Status == status {
			n++
		}
	}
	return n, nil
}

// Pending mirrors atlas_cycle_validation_queue_rows (planned or approved).
func Pending(opDir, target string) ([]Plan, error) {
	ps, err := Latest(opDir, target)
	if err != nil {
		return nil, err
	}
	var out []Plan
	for _, p := range ps {
		if p.Status == "planned" || p.Status == "approved" {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := or(out[i].UpdatedAt, out[i].CreatedAt), or(out[j].UpdatedAt, out[j].CreatedAt)
		if ai != aj {
			return ai > aj
		}
		return out[i].ID > out[j].ID
	})
	return out, nil
}

// LatestPlan mirrors atlas_brief_latest_validation.
func LatestPlan(opDir, target string) *Plan {
	ps, err := Latest(opDir, target)
	if err != nil || len(ps) == 0 {
		return nil
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].UpdatedAt != ps[j].UpdatedAt {
			return ps[i].UpdatedAt < ps[j].UpdatedAt
		}
		return ps[i].ID < ps[j].ID
	})
	p := ps[len(ps)-1]
	return &p
}

// Result mirrors the brief's result column.
func (p Plan) Result() string {
	if p.Status == "superseded" {
		return "superseded-by=" + or(p.SupersededBy, "?")
	}
	return or(or(p.RetestResult, p.ResultStatus), "-")
}

// ReportMarkdown mirrors atlas_validation_report_markdown.
func ReportMarkdown(opDir string) ([]string, error) {
	ps, err := Latest(opDir, "")
	if err != nil {
		return nil, err
	}
	if len(ps) == 0 {
		return []string{"- No validation plans recorded yet."}, nil
	}
	sort.SliceStable(ps, func(i, j int) bool {
		if ps[i].CreatedAt != ps[j].CreatedAt {
			return ps[i].CreatedAt < ps[j].CreatedAt
		}
		return ps[i].ID < ps[j].ID
	})
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		var b strings.Builder
		b.WriteString("- " + or(p.ID, "?") + " / " + or(p.Lane, "?") + " / " + or(p.Capability, "?") + " / " + or(p.Status, "?"))
		if p.Finding != "" {
			b.WriteString(" Finding: " + p.Finding + ".")
		}
		if len(p.Evidence) > 0 {
			b.WriteString(" Evidence: " + strings.Join(p.Evidence, ", ") + ".")
		}
		if p.ResultStatus != "" {
			b.WriteString(" Result: " + p.ResultStatus + ".")
		}
		if p.RetestResult != "" {
			b.WriteString(" Retest: " + p.RetestResult + ".")
		}
		if p.RetestNote != "" {
			b.WriteString(" Retest note: " + p.RetestNote + ".")
		}
		if p.SupersededBy != "" {
			b.WriteString(" Superseded by: " + p.SupersededBy + ".")
		}
		if p.SupersededReason != "" {
			b.WriteString(" Superseded reason: " + p.SupersededReason + ".")
		}
		out = append(out, b.String())
	}
	return out, nil
}

func or(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
