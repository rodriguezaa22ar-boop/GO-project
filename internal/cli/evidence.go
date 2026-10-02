package cli

import (
	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func runEvidence(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("evidence add|list|verify")
	}
	switch args[0] {
	case "add":
		return evidenceAdd(ctx, args[1:])
	case "list":
		return evidenceList(ctx, args[1:])
	case "verify":
		return evidenceVerify(ctx, args[1:])
	}
	return state.Failf("unknown evidence command: %s", args[0])
}

func evidenceAdd(ctx *Context, args []string) error {
	const usage = "evidence add <path> [--kind kind] [--target target] [--classification label] [--redacted true|false]"
	if err := needArgs(1, args, usage); err != nil {
		return err
	}
	p := evidence.AddParams{SourcePath: args[0]}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--kind", "--target", "--classification", "--redacted":
			v, err := option(rest, i, "evidence add <path> "+rest[i]+" <value>")
			if err != nil {
				return err
			}
			switch rest[i] {
			case "--kind":
				p.Kind = v
			case "--target":
				p.Target = v
			case "--classification":
				p.Classification = v
			case "--redacted":
				if v != "true" && v != "false" {
					return state.Failf("expected boolean true or false, got: %s", v)
				}
				p.Redacted = v == "true"
			}
			i++
		default:
			return state.Failf("unknown evidence add option: %s", rest[i])
		}
	}
	op, err := operation.LoadActive(ctx.Layout)
	if err != nil {
		return err
	}
	rec, err := evidence.Add(op, p)
	if err != nil {
		return err
	}
	ok(ctx, "evidence added")
	kv(ctx, "id", rec.ID)
	kv(ctx, "kind", rec.Kind)
	kv(ctx, "target", rec.Target)
	kv(ctx, "sha256", rec.SHA256)
	kv(ctx, "path", op.Dir+"/"+rec.Path)
	return nil
}

func evidenceList(ctx *Context, args []string) error {
	op, err := loadReadOnlyOp(ctx, args, "evidence list [operation]")
	if err != nil {
		return err
	}
	rows, err := evidence.Rows(op.Dir, op.Target, 1000000)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		note(ctx, "no evidence recorded yet")
		return nil
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
	return nil
}

// evidenceVerify re-hashes every stored evidence artifact and exits 1 if
// any artifact is missing or changed since capture.
func evidenceVerify(ctx *Context, args []string) error {
	op, err := loadOp(ctx, args)
	if err != nil {
		return err
	}
	checks, problems, err := evidence.VerifyArtifacts(op.Dir)
	if err != nil {
		return err
	}
	heading(ctx, "Evidence Artifact Verification")
	rule(ctx)
	kv(ctx, "Operation", op.Name)
	for _, c := range checks {
		detail := c.Path
		if c.Status == "changed" {
			detail += " expected_sha=" + c.Expected + " actual_sha=" + c.Actual
		}
		line(ctx, "%-26s %-9s %s", c.ID, c.Status, detail)
	}
	status := "verified"
	if problems > 0 {
		status = "attention-required"
	}
	kv(ctx, "Artifacts Checked", itoa(len(checks)))
	kv(ctx, "Artifact Problems", itoa(problems))
	kv(ctx, "Verification Status", status)
	if problems > 0 {
		return &ExitError{Code: 1}
	}
	return nil
}
