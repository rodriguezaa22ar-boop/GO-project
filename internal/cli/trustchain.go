package cli

import (
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/packet"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func opTrustChain(ctx *Context, args []string) error {
	strict := false
	var name string
	for _, a := range args {
		switch {
		case a == "--strict":
			strict = true
		case a == "--json":
			return state.Failf("op trust-chain --json is not implemented in this build yet")
		case strings.HasPrefix(a, "-"):
			return state.Failf("unknown op trust-chain option: %s", a)
		default:
			if name != "" {
				return state.Failf("op trust-chain [name] [--strict]")
			}
			name = a
		}
	}
	op, err := operation.LoadNamedOrActive(ctx.Layout, name)
	if err != nil {
		return err
	}
	tc, err := packet.CollectTrustChain(op)
	if err != nil {
		return err
	}
	heading(ctx, "Operation Trust Chain")
	rule(ctx)
	kv(ctx, "Operation", op.Name)
	kv(ctx, "Operation Status", op.Status)
	kv(ctx, "Target", op.Target)
	kv(ctx, "Trust Chain Status", tc.Status)
	kv(ctx, "Next Trust Step", tc.NextStep)
	rule(ctx)
	heading(ctx, "Readiness")
	kv(ctx, "Close Readiness", tc.Readiness.Status)
	kv(ctx, "Evidence Records", itoa(tc.Readiness.EvidenceCount))
	kv(ctx, "Open Findings", itoa(tc.Readiness.OpenCount))
	kv(ctx, "Accepted Risks", itoa(tc.Readiness.AcceptedCount))
	kv(ctx, "Pending Validation", itoa(tc.Readiness.PendingCount))
	kv(ctx, "V1 Readiness", "not evaluated (Lite does not ship the v1 toolchain pillars)")
	rule(ctx)
	heading(ctx, "Verification")
	kv(ctx, "Closeout", tc.CloseoutVerification+" manifest="+tc.CloseoutPath+" problems="+itoa(tc.CloseoutProblems))
	kv(ctx, "Audit Packet", tc.AuditVerification+" packet="+tc.AuditPath)
	kv(ctx, "Archive Packet", tc.ArchiveVerification+" packet="+dash(tc.ArchivePath))
	kv(ctx, "Evidence Artifacts", tc.EvidenceVerification+" checked="+itoa(tc.EvidenceChecked)+" problems="+itoa(tc.EvidenceProblems))
	rule(ctx)
	heading(ctx, "Ledger")
	ledgerSHA, _ := state.SHA256File(op.LedgerFile())
	n, _ := ledger.Count(op.LedgerFile())
	kv(ctx, "Operation Ledger", op.LedgerFile()+" events="+itoa(n)+" sha256="+ledgerSHA)
	if strict && tc.Status != "current" {
		return &ExitError{Code: 1}
	}
	return nil
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
