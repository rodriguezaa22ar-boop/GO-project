package cli

import "github.com/rodriguezaa22ar-boop/go-project/internal/state"

// Handlers still pending later build stages.

func notYet(verb string) error {
	return state.Failf("%s is not implemented in this build yet", verb)
}

func opAudit(ctx *Context, args []string) error      { return notYet("op audit") }
func opArchive(ctx *Context, args []string) error    { return notYet("op archive") }
func opTrustChain(ctx *Context, args []string) error { return notYet("op trust-chain") }

func runAdapter(ctx *Context, args []string) error { return notYet("adapter") }
