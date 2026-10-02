package cli

import (
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func runScope(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("scope status [operation] | scope check <capability> <target>")
	}
	switch args[0] {
	case "status":
		return scopeStatus(ctx, args[1:])
	case "check":
		return scopeCheck(ctx, args[1:])
	}
	return state.Failf("unknown scope command: %s", args[0])
}

func scopeStatus(ctx *Context, args []string) error {
	op, err := loadReadOnlyOp(ctx, args, "scope status [operation]")
	if err != nil {
		return err
	}
	snap, err := op.Snapshot()
	if err != nil {
		return err
	}
	heading(ctx, "ScopeGuard")
	rule(ctx)
	kv(ctx, "Operation", op.Name)
	kv(ctx, "Profile", snap.Profile)
	kv(ctx, "Target", snap.Target)
	if snap.TargetAddress != "" && snap.TargetAddress != snap.Target {
		kv(ctx, "Address", snap.TargetAddress)
	}
	kv(ctx, "Target Scope", orUnknown(snap.TargetScopeStatus))
	kv(ctx, "Target Criticality", orUnknown(snap.TargetCriticality))
	if snap.TargetOwner != "" {
		kv(ctx, "Target Owner", snap.TargetOwner)
	}
	if snap.TargetTags != "" {
		kv(ctx, "Target Tags", snap.TargetTags)
	}
	kv(ctx, "Allowed", snap.Allowed)
	kv(ctx, "Blocked", snap.Blocked)
	rec := snap.RecommendedWorkflows
	if rec == "" {
		rec = "none"
	}
	kv(ctx, "Recommended", rec)
	kv(ctx, "Snapshot", scope.SnapshotFile(op.Dir))
	return nil
}

func scopeCheck(ctx *Context, args []string) error {
	if err := needArgs(2, args, "scope check <capability> <target>"); err != nil {
		return err
	}
	capability, target := args[0], args[1]
	op, err := operation.LoadActive(ctx.Layout)
	if err != nil {
		return err
	}
	if err := op.Preflight(capability, state.ToolName, target, "manual scope check"); err != nil {
		return err
	}
	ok(ctx, "scope allowed")
	kv(ctx, "capability", capability)
	kv(ctx, "tier", scope.TierString(capability))
	kv(ctx, "target", target)
	return nil
}
