// Package cli wires the lcoat command grammar (`lcoat <domain> <verb>`) to
// the internal packages and reproduces the shell build's plain-text output.
package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// Context carries the resolved layout and output streams.
type Context struct {
	Layout *state.Layout
	Out    io.Writer
	Err    io.Writer
}

// Run executes argv (without the program name) and returns the exit code.
func Run(args []string, out, errOut io.Writer) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		fmt.Fprint(out, usage)
		return 0
	}
	layout, err := state.Resolve()
	if err != nil {
		fmt.Fprintf(errOut, "error: %v\n", err)
		return 1
	}
	ctx := &Context{Layout: layout, Out: out, Err: errOut}
	if !skipsLayout(args) {
		if layout.RootFromCwd {
			// Field test: an unset LCOAT_ROOT silently scattered lab data
			// across the operator's home directory.
			fmt.Fprintf(errOut, "warning: LCOAT_ROOT is not set; using the current directory as the lab root (%s)\n  set it once: echo 'export LCOAT_ROOT=\"$HOME/lcoat-lab\"' >> ~/.bashrc\n", layout.Root)
		}
		if err := layout.EnsureLayout(); err != nil {
			fmt.Fprintf(errOut, "error: %v\n", err)
			return 1
		}
	}
	err = dispatch(ctx, args)
	if err == nil {
		return 0
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		if exit.Msg != "" {
			fmt.Fprintf(errOut, "%s\n", exit.Msg)
		}
		return exit.Code
	}
	fmt.Fprintf(errOut, "error: %v\n", err)
	return 1
}

// ExitError carries a non-zero exit code with an optional message that has
// already been formatted (used by verifiers that print `warn:` lines).
type ExitError struct {
	Code int
	Msg  string
}

func (e *ExitError) Error() string { return e.Msg }

func skipsLayout(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[0] {
	case "receipt":
		switch args[1] {
		case "create", "verify", "replay":
			return true
		}
	case "ledger":
		return args[1] == "verify" || args[1] == "checkpoint"
	case "version":
		return true
	}
	return false
}

func dispatch(ctx *Context, args []string) error {
	domain := args[0]
	rest := args[1:]
	switch domain {
	case "version":
		fmt.Fprintln(ctx.Out, "lcoat "+Version)
		return nil
	case "target":
		return runTarget(ctx, rest)
	case "profile":
		return runProfile(ctx, rest)
	case "op":
		return runOp(ctx, rest)
	case "scope":
		return runScope(ctx, rest)
	case "evidence":
		return runEvidence(ctx, rest)
	case "finding":
		return runFinding(ctx, rest)
	case "ledger":
		return runLedger(ctx, rest)
	case "receipt":
		return runReceipt(ctx, rest)
	case "adapter":
		return runAdapter(ctx, rest)
	}
	return state.Failf("unknown command: %s\n%s", strings.Join(args, " "), strings.TrimRight(usage, "\n"))
}

// Version is set at build time; the default marks a source build.
var Version = "0.1.4-dev"

const usage = `usage:
  lcoat help
  lcoat version
  lcoat target add <name> <address> [--scope-status status] [--criticality level] [--tag tag] [--owner owner] [notes...]
  lcoat target show <name>
  lcoat target list
  lcoat profile list
  lcoat profile show <name>
  lcoat op start [--profile profile] <name> <target> [notes...]
  lcoat op resume <name>
  lcoat op list
  lcoat op status [name]
  lcoat op show [name]
  lcoat op readiness [name]
  lcoat op close [name] [--force]
  lcoat op report [name] [report-name]
  lcoat op handoff [name] [handoff-name]
  lcoat op closeout [name] [manifest-name]
  lcoat op audit [name]
  lcoat op audit-packet [name] [packet-name]
  lcoat op archive [name]
  lcoat op archive-packet [name] [packet-name]
  lcoat op verify [name] [closeout-manifest]
  lcoat op audit-verify [name] [audit-packet]
  lcoat op archive-verify [name] [archive-packet]
  lcoat op trust-chain [name] [--strict]
  lcoat scope status [operation]
  lcoat scope check <capability> <target>
  lcoat evidence add <path> [--kind kind] [--target target] [--classification label] [--redacted true|false]
  lcoat evidence list [operation]
  lcoat evidence verify [operation]
  lcoat finding add <title> [--level observed|inferred|validated] [--severity severity] [--confidence confidence] [--status open|resolved|accepted] [--impact text] [--recommendation text] [--evidence id]...
  lcoat finding list [operation]
  lcoat ledger verify <ledger-file|-> [--json]
  lcoat ledger checkpoint <ledger-file|-> [--json]
  lcoat receipt create --action action --actor actor --subject-type type --subject ref [--prev-hash sha256] [--evidence-ref ref] [--artifact-ref path=sha256] [--approval-ref ref] [--limitation text] [--out receipt.json] [--json]
  lcoat receipt verify <receipt-file|-> [--json]
  lcoat receipt replay <receipt-file> [receipt-file ...] [--json]
  lcoat adapter list
  lcoat adapter run <adapter> <target> [--tier 1|2] [--timeout seconds] [--] [tool args...]
`

// Output helpers that mirror lib/common.sh ui_* without colour.

func kv(ctx *Context, key, value string) { fmt.Fprintf(ctx.Out, "%s: %s\n", key, value) }
func ok(ctx *Context, msg string)        { fmt.Fprintf(ctx.Out, "ok: %s\n", msg) }
func note(ctx *Context, msg string)      { fmt.Fprintf(ctx.Out, "note: %s\n", msg) }
func warn(ctx *Context, msg string)      { fmt.Fprintf(ctx.Out, "warn: %s\n", msg) }
func heading(ctx *Context, msg string)   { fmt.Fprintln(ctx.Out, msg) }
func rule(ctx *Context) {
	fmt.Fprintln(ctx.Out, "------------------------------------------------------------")
}
func line(ctx *Context, format string, args ...any) { fmt.Fprintf(ctx.Out, format+"\n", args...) }

// needArgs mirrors need_args.
func needArgs(min int, args []string, usage string) error {
	if len(args) < min {
		return state.Failf("%s", usage)
	}
	return nil
}

// option reads a flag value, failing with usage when missing.
func option(args []string, i int, usage string) (string, error) {
	if i+1 >= len(args) {
		return "", state.Failf("%s", usage)
	}
	return args[i+1], nil
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
