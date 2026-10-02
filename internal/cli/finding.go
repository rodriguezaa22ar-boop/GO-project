package cli

import (
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func runFinding(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("finding add|list")
	}
	switch args[0] {
	case "add":
		return findingAdd(ctx, args[1:])
	case "list":
		return findingList(ctx, args[1:])
	}
	return state.Failf("unknown finding command: %s", args[0])
}

func findingAdd(ctx *Context, args []string) error {
	const usage = "finding add <title> [--level observed|inferred|validated] [--severity severity] [--confidence confidence] [--evidence id]"
	if err := needArgs(1, args, usage); err != nil {
		return err
	}
	p := findings.AddParams{Title: args[0]}
	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--target", "--level", "--severity", "--confidence", "--status", "--source", "--impact", "--recommendation", "--evidence":
			v, err := option(rest, i, "finding add <title> "+rest[i]+" <value>")
			if err != nil {
				return err
			}
			switch rest[i] {
			case "--target":
				p.Target = v
			case "--level":
				p.Level = v
			case "--severity":
				p.Severity = v
			case "--confidence":
				p.Confidence = v
			case "--status":
				p.Status = v
			case "--source":
				p.Source = v
			case "--impact":
				p.Impact = v
			case "--recommendation":
				p.Recommendation = v
			case "--evidence":
				p.Evidence = append(p.Evidence, v)
			}
			i++
		default:
			return state.Failf("unknown finding add option: %s", rest[i])
		}
	}
	op, err := operation.LoadActive(ctx.Layout)
	if err != nil {
		return err
	}
	f, err := findings.Add(op, p)
	if err != nil {
		return err
	}
	ok(ctx, "finding added")
	kv(ctx, "id", f.ID)
	kv(ctx, "title", f.Title)
	kv(ctx, "level", f.Level)
	kv(ctx, "severity", f.Severity)
	kv(ctx, "confidence", f.Confidence)
	kv(ctx, "status", f.Status)
	kv(ctx, "target", f.Target)
	if len(f.Evidence) > 0 {
		kv(ctx, "evidence", strings.Join(f.Evidence, " "))
	}
	return nil
}

func findingList(ctx *Context, args []string) error {
	op, err := loadReadOnlyOp(ctx, args, "finding list [operation]")
	if err != nil {
		return err
	}
	rows, err := findings.Rows(op.Dir, op.Target, 1000000)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		note(ctx, "no findings recorded yet")
		return nil
	}
	for _, f := range rows {
		ev := strings.Join(f.Evidence, ",")
		if ev == "" {
			ev = "-"
		}
		line(ctx, "%-24s %-10s %-8s %-10s %-32s %s", f.IDOr(), f.LevelOr(), f.SeverityOr(), f.StatusOr(), f.TitleOr(), ev)
	}
	return nil
}
