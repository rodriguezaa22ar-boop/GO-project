package cli

import (
	"time"

	"github.com/rodriguezaa22ar-boop/go-project/internal/adapter"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func runAdapter(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("adapter list|run <adapter> <target> [args]")
	}
	switch args[0] {
	case "list":
		return adapterList(ctx)
	case "run":
		return adapterRun(ctx, args[1:])
	}
	return state.Failf("unknown adapter command: %s", args[0])
}

func adapterList(ctx *Context) error {
	line(ctx, "%-12s %-16s %s", "ADAPTER", "MAX TIER", "NOTE")
	line(ctx, "%-12s %-16s %s", "nmap", "2 (active-recon)", "parses XML output into proposed findings")
	line(ctx, "%-12s %-16s %s", "script", "2 (declared)", "evidence capture only; --tier 1|2 required")
	note(ctx, "adapters above tier 2 are refused; metasploit is refused outright")
	return nil
}

func adapterRun(ctx *Context, args []string) error {
	const usage = "adapter run <adapter> <target> [--tier 1|2] [--timeout seconds] [--] [tool args...]"
	if err := needArgs(2, args, usage); err != nil {
		return err
	}
	p := adapter.RunParams{AdapterName: args[0], Target: args[1]}
	rest := args[2:]
	// A leading --timeout applies to the runner; everything after --, or any
	// non-runner flag, is passed to the adapter.
	i := 0
	for i < len(rest) {
		if rest[i] == "--timeout" {
			v, err := option(rest, i, usage)
			if err != nil {
				return err
			}
			secs := atoiCLI(v)
			if secs <= 0 {
				return state.Failf("adapter run --timeout must be a positive number of seconds")
			}
			p.Timeout = time.Duration(secs) * time.Second
			i += 2
			continue
		}
		if rest[i] == "--" {
			p.Args = append(p.Args, rest[i+1:]...)
			break
		}
		p.Args = append(p.Args, rest[i])
		i++
	}

	op, err := operation.LoadActive(ctx.Layout)
	if err != nil {
		return err
	}
	res, err := adapter.Run(op, p)
	if err != nil {
		return err
	}
	ok(ctx, "adapter run complete")
	kv(ctx, "adapter", res.Adapter)
	kv(ctx, "capability", res.Capability)
	kv(ctx, "tier", itoa(res.Tier))
	kv(ctx, "exit_code", itoa(res.ExitCode))
	kv(ctx, "duration_ms", itoa(int(res.DurationMS)))
	kv(ctx, "evidence", res.EvidenceID)
	kv(ctx, "sha256", res.SHA256)
	if len(res.Proposed) > 0 {
		line(ctx, "")
		heading(ctx, "Proposed Findings (confirm with finding add)")
		for _, f := range res.Proposed {
			line(ctx, "- %s / %s / %s: %s", f.Severity, f.Confidence, f.Title, f.Detail)
		}
	} else {
		note(ctx, "no proposed findings (confirm findings manually with finding add)")
	}
	return nil
}

func atoiCLI(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int(s[i]-'0')
	}
	if s == "" {
		return -1
	}
	return n
}
