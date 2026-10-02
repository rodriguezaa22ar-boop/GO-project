package cli

import "github.com/rodriguezaa22ar-boop/go-project/internal/state"

// Handlers below are implemented in later build stages (packets, verifiers,
// receipts, adapters). Until then they report that the command is not yet
// available in this build rather than silently doing nothing.

func notYet(verb string) error {
	return state.Failf("%s is not implemented in this build yet", verb)
}

func opHandoff(ctx *Context, args []string) error       { return notYet("op handoff") }
func opCloseout(ctx *Context, args []string) error      { return notYet("op closeout") }
func opAudit(ctx *Context, args []string) error         { return notYet("op audit") }
func opAuditPacket(ctx *Context, args []string) error   { return notYet("op audit-packet") }
func opArchive(ctx *Context, args []string) error       { return notYet("op archive") }
func opArchivePacket(ctx *Context, args []string) error { return notYet("op archive-packet") }
func opVerify(ctx *Context, args []string) error        { return notYet("op verify") }
func opAuditVerify(ctx *Context, args []string) error   { return notYet("op audit-verify") }
func opArchiveVerify(ctx *Context, args []string) error { return notYet("op archive-verify") }
func opTrustChain(ctx *Context, args []string) error    { return notYet("op trust-chain") }

func runReceipt(ctx *Context, args []string) error { return notYet("receipt") }
func runAdapter(ctx *Context, args []string) error { return notYet("adapter") }
