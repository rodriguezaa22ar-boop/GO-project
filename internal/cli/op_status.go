package cli

import (
	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/validation"
)

func opStatus(ctx *Context, args []string) error {
	op, err := loadOp(ctx, args)
	if err != nil {
		return err
	}
	heading(ctx, "Operation Status")
	rule(ctx)
	if err := printOpSummary(ctx, op); err != nil {
		return err
	}
	rule(ctx)
	heading(ctx, "Tracked Recon Runs")
	note(ctx, "no recon runs tracked yet")
	rule(ctx)
	heading(ctx, "Tracked Action Sessions")
	note(ctx, "no action sessions tracked yet")
	line(ctx, "")
	heading(ctx, "Operation Evidence")
	rows, err := evidence.Rows(op.Dir, op.Target, 8)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		note(ctx, "no operation evidence recorded yet")
	}
	for _, r := range rows {
		redacted := "false"
		if r.Redacted {
			redacted = "true"
		}
		sha := r.SHA256
		if len(sha) > 20 {
			sha = sha[:20]
		}
		line(ctx, "%-22s %-16s %-14s %-8s %-20s %s", r.ID, r.Kind, r.Classification, redacted, sha, r.Path)
	}
	line(ctx, "")
	heading(ctx, "Operation Findings")
	frows, err := findings.Rows(op.Dir, op.Target, 8)
	if err != nil {
		return err
	}
	if len(frows) == 0 {
		note(ctx, "no operation findings recorded yet")
	}
	for _, f := range frows {
		ev := joinEvidence(f.Evidence)
		line(ctx, "%-24s %-10s %-8s %-10s %-32s %s", f.IDOr(), f.LevelOr(), f.SeverityOr(), f.StatusOr(), f.TitleOr(), ev)
	}
	line(ctx, "")
	heading(ctx, "Validation Plans")
	plans, err := validation.Latest(op.Dir, op.Target)
	if err != nil {
		return err
	}
	if len(plans) == 0 {
		note(ctx, "no operation validation plans recorded yet")
	}
	return nil
}

func opShow(ctx *Context, args []string) error {
	op, err := loadOp(ctx, args)
	if err != nil {
		return err
	}
	snap, err := op.Snapshot()
	if err != nil {
		return err
	}
	heading(ctx, "Operation Scope")
	rule(ctx)
	if err := printOpSummary(ctx, op); err != nil {
		return err
	}
	rule(ctx)
	heading(ctx, "Scope")
	line(ctx, "%s", snap.Text)
	rule(ctx)
	heading(ctx, "Allowed Actions")
	for _, l := range snap.AllowedActionLines() {
		line(ctx, "  - %s", l)
	}
	rule(ctx)
	heading(ctx, "Explicitly Out Of Scope")
	for _, l := range snap.OutOfScopeLines() {
		line(ctx, "  - %s", l)
	}
	rule(ctx)
	heading(ctx, "Artifacts")
	kv(ctx, "Operation Dir", op.Dir)
	kv(ctx, "Latest Recon", "")
	kv(ctx, "Latest Action", "none")
	return nil
}

func printOpSummary(ctx *Context, op *operation.Operation) error {
	snap, err := op.Snapshot()
	if err != nil {
		return err
	}
	active := "no"
	if operation.IsActive(ctx.Layout, op.Slug) {
		active = "yes"
	}
	kv(ctx, "Operation", op.Name)
	kv(ctx, "Target", op.FormatTarget())
	kv(ctx, "Target Scope", orUnknown(op.ScopeStatus))
	kv(ctx, "Target Criticality", orUnknown(op.Criticality))
	if op.Owner != "" {
		kv(ctx, "Target Owner", op.Owner)
	}
	if op.Tags != "" {
		kv(ctx, "Target Tags", op.Tags)
	}
	kv(ctx, "Status", op.Status)
	kv(ctx, "Profile", snap.Profile)
	kv(ctx, "Active", active)
	kv(ctx, "Created", op.CreatedAt)
	if op.ClosedAt != "" {
		kv(ctx, "Closed", op.ClosedAt)
	}
	if op.LastResumedAt != "" {
		kv(ctx, "Resumed", op.LastResumedAt)
	}
	if op.Notes != "" {
		kv(ctx, "Notes", op.Notes)
	}
	kv(ctx, "Recon Runs", "0")
	kv(ctx, "Action Sessions", "0")
	evCount, err := evidence.Count(op.Dir, op.Target)
	if err != nil {
		return err
	}
	kv(ctx, "Evidence", itoa(evCount))
	fCount, err := findings.Count(op.Dir, op.Target)
	if err != nil {
		return err
	}
	kv(ctx, "Findings", itoa(fCount))
	vCount, err := validation.Count(op.Dir, op.Target)
	if err != nil {
		return err
	}
	kv(ctx, "Validation Plans", itoa(vCount))
	kv(ctx, "Dir", op.Dir)
	kv(ctx, "Latest Recon", "none")
	kv(ctx, "Latest Action", "none")
	return nil
}

func joinEvidence(ev []string) string {
	if len(ev) == 0 {
		return "-"
	}
	out := ev[0]
	for _, e := range ev[1:] {
		out += "," + e
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}

var _ = scope.ReadOnly
