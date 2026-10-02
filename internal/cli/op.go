package cli

import (
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/brief"
	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/readiness"
	"github.com/rodriguezaa22ar-boop/go-project/internal/report"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func runOp(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("op start|resume|list|status|show|readiness|close|report|brief|handoff|closeout|audit|audit-packet|archive|archive-packet|verify|audit-verify|archive-verify|trust-chain")
	}
	verb, rest := args[0], args[1:]
	switch verb {
	case "start":
		return opStart(ctx, rest)
	case "resume":
		return opResume(ctx, rest)
	case "list":
		return opList(ctx)
	case "status":
		return opStatus(ctx, rest)
	case "show":
		return opShow(ctx, rest)
	case "readiness":
		return opReadiness(ctx, rest)
	case "close":
		return opClose(ctx, rest)
	case "report":
		return opReport(ctx, rest)
	case "brief":
		return opBrief(ctx, rest)
	case "handoff":
		return opHandoff(ctx, rest)
	case "closeout":
		return opCloseout(ctx, rest)
	case "audit":
		return opAudit(ctx, rest)
	case "audit-packet":
		return opAuditPacket(ctx, rest)
	case "archive":
		return opArchive(ctx, rest)
	case "archive-packet":
		return opArchivePacket(ctx, rest)
	case "verify":
		return opVerify(ctx, rest)
	case "audit-verify":
		return opAuditVerify(ctx, rest)
	case "archive-verify":
		return opArchiveVerify(ctx, rest)
	case "trust-chain":
		return opTrustChain(ctx, rest)
	}
	return state.Failf("unknown op command: %s", verb)
}

func opStart(ctx *Context, args []string) error {
	const usage = "op start [--profile profile] <name> <target> [notes...]"
	p := operation.StartParams{Profile: "default"}
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--profile":
			v, err := option(args, i, usage)
			if err != nil {
				return err
			}
			p.Profile = v
			i += 2
		case "--":
			i++
			goto positional
		default:
			if strings.HasPrefix(args[i], "--") {
				return state.Failf("unknown op start option: %s", args[i])
			}
			goto positional
		}
	}
positional:
	pos := args[i:]
	if err := needArgs(2, pos, usage); err != nil {
		return err
	}
	p.Name = pos[0]
	p.Target = pos[1]
	p.Notes = strings.Join(pos[2:], " ")

	op, profile, err := operation.Start(ctx.Layout, p)
	if err != nil {
		return err
	}
	ok(ctx, "operation ready")
	kv(ctx, "operation", op.Name)
	kv(ctx, "profile", profile.Name)
	kv(ctx, "target", op.Target)
	if op.TargetAddress != op.Target {
		kv(ctx, "address", op.TargetAddress)
	}
	kv(ctx, "scope_status", op.ScopeStatus)
	kv(ctx, "criticality", op.Criticality)
	if op.Tags != "" {
		kv(ctx, "tags", op.Tags)
	}
	if op.Owner != "" {
		kv(ctx, "owner", op.Owner)
	}
	kv(ctx, "op_dir", op.Dir)
	kv(ctx, "active_operation", op.Slug)
	return nil
}

func opResume(ctx *Context, args []string) error {
	if err := needArgs(1, args, "op resume <name>"); err != nil {
		return err
	}
	op, err := operation.Resume(ctx.Layout, args[0])
	if err != nil {
		return err
	}
	ok(ctx, "operation active")
	kv(ctx, "operation", op.Name)
	kv(ctx, "target", op.Target)
	if op.TargetAddress != op.Target {
		kv(ctx, "address", op.TargetAddress)
	}
	kv(ctx, "active_operation", op.Slug)
	return nil
}

func opList(ctx *Context) error {
	ops, err := operation.List(ctx.Layout)
	if err != nil {
		return err
	}
	line(ctx, "%-24s %-16s %-24s %s", "OPERATION", "STATUS", "TARGET", "ACTIVE")
	if len(ops) == 0 {
		note(ctx, "no atlas operations recorded yet")
		return nil
	}
	for _, o := range ops {
		active := "no"
		if operation.IsActive(ctx.Layout, o.Slug) {
			active = "yes"
		}
		target := o.Target
		if o.TargetLabel != "" && o.TargetLabel != o.Target {
			target = o.TargetLabel
		}
		line(ctx, "%-24s %-16s %-24s %s", o.Name, o.Status, target, active)
	}
	return nil
}

func opBrief(ctx *Context, args []string) error {
	op, err := loadOp(ctx, args)
	if err != nil {
		return err
	}
	evCount, err := evidence.Count(op.Dir, op.Target)
	if err != nil {
		return err
	}
	b, err := brief.Collect(op, evCount)
	if err != nil {
		return err
	}
	heading(ctx, "Operator Brief")
	rule(ctx)
	for _, l := range b.Lines() {
		kvLine(ctx, l)
	}
	return nil
}

func opReadiness(ctx *Context, args []string) error {
	op, err := loadOp(ctx, args)
	if err != nil {
		return err
	}
	st, err := readiness.Collect(op)
	if err != nil {
		return err
	}
	printReadiness(ctx, op, st)
	return nil
}

func printReadiness(ctx *Context, op *operation.Operation, st *readiness.State) {
	for _, l := range st.Lines(op) {
		if l == "------------------------------------------------------------" {
			rule(ctx)
			continue
		}
		if idx := strings.Index(l, ": "); idx > 0 && !strings.HasPrefix(l, "note:") && isKVLabel(l[:idx]) {
			line(ctx, "%s", l)
			continue
		}
		line(ctx, "%s", l)
	}
}

func opClose(ctx *Context, args []string) error {
	force := false
	var name string
	for _, a := range args {
		switch {
		case a == "--force":
			force = true
		case strings.HasPrefix(a, "-"):
			return state.Failf("unknown op close option: %s", a)
		default:
			if name != "" {
				return state.Failf("unexpected op close argument: %s", a)
			}
			name = a
		}
	}
	op, err := operation.LoadNamedOrActive(ctx.Layout, name)
	if err != nil {
		return err
	}
	st, err := readiness.Collect(op)
	if err != nil {
		return err
	}
	detail := st.LedgerDetail(force)
	if st.Status != "ready" && !force {
		printReadiness(ctx, op, st)
		return state.Failf("operation is not ready to close; address readiness items or rerun with --force")
	}
	if err := op.Close(st.Status, detail); err != nil {
		return err
	}
	ok(ctx, "operation closed")
	kv(ctx, "operation", op.Name)
	line(ctx, "status: closed")
	kv(ctx, "readiness", st.Status)
	f := "0"
	if force {
		f = "1"
	}
	kv(ctx, "force", f)
	return nil
}

func opReport(ctx *Context, args []string) error {
	name, reportName := twoNames(args)
	op, err := operation.LoadNamedOrActive(ctx.Layout, name)
	if err != nil {
		return err
	}
	path, err := report.Write(op, reportName)
	if err != nil {
		return err
	}
	ok(ctx, "operation report written")
	kv(ctx, "report", path)
	return nil
}

// Helpers shared by op subcommands.

// loadReadOnlyOp loads the named operation (open or closed) or, with no
// name, the active one. It accepts at most one positional argument, so a
// typo is reported rather than silently ignored.
func loadReadOnlyOp(ctx *Context, args []string, usage string) (*operation.Operation, error) {
	if len(args) > 1 || (len(args) == 1 && strings.HasPrefix(args[0], "-")) {
		return nil, state.Failf("usage: %s", usage)
	}
	return loadOp(ctx, args)
}

func loadOp(ctx *Context, args []string) (*operation.Operation, error) {
	name := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		name = args[0]
	}
	return operation.LoadNamedOrActive(ctx.Layout, name)
}

func twoNames(args []string) (string, string) {
	var names []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	switch len(names) {
	case 0:
		return "", ""
	case 1:
		return names[0], ""
	default:
		return names[0], names[1]
	}
}

func kvLine(ctx *Context, l string) { line(ctx, "%s", l) }

func isKVLabel(s string) bool { return s != "" && s[0] >= 'A' && s[0] <= 'Z' }
