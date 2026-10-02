package cli

import (
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func runTarget(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("target add|show|list")
	}
	switch args[0] {
	case "add":
		return targetAdd(ctx, args[1:])
	case "show":
		return targetShow(ctx, args[1:])
	case "list":
		return targetList(ctx)
	}
	return state.Failf("unknown target command: %s", args[0])
}

func targetAdd(ctx *Context, args []string) error {
	const usage = "target add <name> <address> [--scope-status status] [--criticality level] [--tag tag] [--owner owner] [notes...]"
	if err := needArgs(2, args, usage); err != nil {
		return err
	}
	t := operation.Target{Name: args[0], Address: args[1], ScopeStatus: "unknown", Criticality: "unknown"}
	var tags, notes []string
	rest := args[2:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--scope-status", "--criticality", "--tag", "--owner", "--notes":
			v, err := option(rest, i, "target add <name> <address> "+rest[i]+" <value>")
			if err != nil {
				return err
			}
			switch rest[i] {
			case "--scope-status":
				t.ScopeStatus = v
			case "--criticality":
				t.Criticality = v
			case "--tag":
				if v == "" {
					return state.Failf("target tag cannot be empty")
				}
				if strings.ContainsAny(v, " \t\n") {
					return state.Failf("target tags cannot contain whitespace: %s", v)
				}
				tags = append(tags, v)
			case "--owner":
				t.Owner = v
			case "--notes":
				notes = append(notes, v)
			}
			i++
		case "--":
			notes = append(notes, rest[i+1:]...)
			i = len(rest)
		default:
			if strings.HasPrefix(rest[i], "--") {
				return state.Failf("unknown target add option: %s", rest[i])
			}
			notes = append(notes, rest[i])
		}
	}
	if !operation.ValidScopeStatus(t.ScopeStatus) {
		return state.Failf("expected target scope status unknown, review, in-scope, or out-of-scope; got: %s", t.ScopeStatus)
	}
	if !operation.ValidCriticality(t.Criticality) {
		return state.Failf("expected target criticality unknown, low, medium, high, or critical; got: %s", t.Criticality)
	}
	t.Tags = strings.Join(tags, " ")
	t.Notes = strings.Join(notes, " ")
	slug, err := operation.AddTarget(ctx.Layout, t)
	if err != nil {
		return err
	}
	line(ctx, "created target: %s", slug)
	return nil
}

func targetShow(ctx *Context, args []string) error {
	if err := needArgs(1, args, "target show <name>"); err != nil {
		return err
	}
	t, err := operation.LoadTarget(ctx.Layout, args[0])
	if err != nil {
		return err
	}
	if t == nil {
		return state.Failf("unknown target: %s", state.Slugify(args[0]))
	}
	kv(ctx, "Target", t.Name)
	kv(ctx, "Address", t.Address)
	kv(ctx, "Scope Status", orUnknown(t.ScopeStatus))
	kv(ctx, "Criticality", orUnknown(t.Criticality))
	if t.Tags != "" {
		kv(ctx, "Tags", t.Tags)
	}
	if t.Owner != "" {
		kv(ctx, "Owner", t.Owner)
	}
	if t.Notes != "" {
		kv(ctx, "Notes", t.Notes)
	}
	kv(ctx, "Created", t.CreatedAt)
	kv(ctx, "Record", t.File)
	return nil
}

func targetList(ctx *Context) error {
	targets, err := operation.ListTargets(ctx.Layout)
	if err != nil {
		return err
	}
	line(ctx, "%-24s %-24s %-12s %-10s %-18s %s", "TARGET", "ADDRESS", "SCOPE", "CRITICAL", "TAGS", "CREATED_AT")
	for _, t := range targets {
		line(ctx, "%-24s %-24s %-12s %-10s %-18s %s", t.Name, t.Address, orUnknown(t.ScopeStatus), orUnknown(t.Criticality), t.Tags, t.CreatedAt)
	}
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

func runProfile(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("profile list|show <name>")
	}
	switch args[0] {
	case "list":
		line(ctx, "%-24s %s", "PROFILE", "SUMMARY")
		line(ctx, "%-24s %s", "default", scope.DefaultSummary)
		files, err := scope.ListProfileFiles(ctx.Layout.ProfilesDir)
		if err != nil {
			return err
		}
		for _, f := range files {
			name := strings.TrimSuffix(f[strings.LastIndex(f, "/")+1:], ".env")
			p, err := scope.LoadProfile(ctx.Layout.ProfilesDir, name)
			if err != nil {
				return err
			}
			line(ctx, "%-24s %s", p.Name, p.Summary)
		}
		return nil
	case "show":
		if err := needArgs(1, args[1:], "profile show <name>"); err != nil {
			return err
		}
		p, err := scope.LoadProfile(ctx.Layout.ProfilesDir, args[1])
		if err != nil {
			return err
		}
		heading(ctx, "Atlas Profile")
		rule(ctx)
		kv(ctx, "Profile", p.Name)
		kv(ctx, "Summary", p.Summary)
		kv(ctx, "Allowed", p.AllowedCapabilities)
		kv(ctx, "Blocked", p.BlockedCapabilities)
		rule(ctx)
		heading(ctx, "Scope")
		line(ctx, "%s", p.ScopeText)
		rule(ctx)
		heading(ctx, "Allowed Actions")
		snap := &scope.Snapshot{AllowedActions: p.AllowedActions, OutOfScopeActions: p.OutOfScopeActions}
		for _, l := range snap.AllowedActionLines() {
			line(ctx, "%s", l)
		}
		rule(ctx)
		heading(ctx, "Explicitly Out Of Scope")
		for _, l := range snap.OutOfScopeLines() {
			line(ctx, "%s", l)
		}
		rule(ctx)
		heading(ctx, "Recommended Workflow")
		if lines := scope.PipeLines(p.RecommendedWorkflows); len(lines) > 0 {
			for _, l := range lines {
				line(ctx, "%s", l)
			}
		} else {
			note(ctx, "no profile-specific workflow configured")
		}
		return nil
	}
	return state.Failf("unknown profile command: %s", args[0])
}
