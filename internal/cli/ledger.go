package cli

import (
	"io"
	"os"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ndjson"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func runLedger(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("ledger verify|checkpoint <ledger-file|-> [--json]")
	}
	switch args[0] {
	case "verify":
		return ledgerVerify(ctx, args[1:])
	case "checkpoint":
		return ledgerCheckpoint(ctx, args[1:])
	}
	return state.Failf("unknown ledger command: %s", args[0])
}

func ledgerInput(args []string, usage string) (path string, cleanup func(), json bool, err error) {
	if len(args) < 1 {
		return "", nil, false, state.Failf("%s", usage)
	}
	input := args[0]
	for _, a := range args[1:] {
		if a == "--json" {
			json = true
		} else {
			return "", nil, false, state.Failf("unknown ledger option: %s", a)
		}
	}
	if input == "-" {
		tmp, terr := os.CreateTemp("", "lcoat-ledger-*")
		if terr != nil {
			return "", nil, false, terr
		}
		if _, cerr := io.Copy(tmp, os.Stdin); cerr != nil {
			tmp.Close()
			os.Remove(tmp.Name())
			return "", nil, false, cerr
		}
		tmp.Close()
		return tmp.Name(), func() { os.Remove(tmp.Name()) }, json, nil
	}
	if !fileExists(input) {
		return "", nil, false, state.Failf("missing ledger: %s", input)
	}
	return input, func() {}, json, nil
}

func ledgerVerify(ctx *Context, args []string) error {
	path, cleanup, jsonOut, err := ledgerInput(args, "ledger verify <ledger-file|-> [--json]")
	if err != nil {
		return err
	}
	defer cleanup()
	res, err := ledger.VerifyOperationLedger(path)
	if err != nil {
		return err
	}
	if jsonOut {
		obj := ndjson.Object{
			{Key: "schema_version", Value: "atlas.ledger_verify.v1"},
			{Key: "status", Value: "ok"},
			{Key: "ledger_type", Value: "atlas.operation_ledger.v1"},
			{Key: "event_count", Value: res.EventCount},
			{Key: "head_event_hash", Value: res.HeadEventHash},
		}
		line(ctx, "%s", ndjson.Encode(obj))
	} else {
		line(ctx, "ledger: ok")
	}
	return nil
}

func ledgerCheckpoint(ctx *Context, args []string) error {
	path, cleanup, jsonOut, err := ledgerInput(args, "ledger checkpoint <ledger-file|-> [--json]")
	if err != nil {
		return err
	}
	defer cleanup()
	res, err := ledger.VerifyOperationLedger(path)
	if err != nil {
		return err
	}
	fileSHA, err := state.SHA256File(path)
	if err != nil {
		return err
	}
	ledgerRef := args[0]
	if jsonOut {
		obj := ndjson.Object{
			{Key: "schema_version", Value: "atlas.checkpoint.v1"},
			{Key: "checkpoint_id", Value: "checkpoint_" + fileSHA[:12]},
			{Key: "timestamp", Value: state.Timestamp()},
			{Key: "metadata_only", Value: true},
			{Key: "ledger_ref", Value: ledgerRef},
			{Key: "event_count", Value: res.EventCount},
			{Key: "head_event_hash", Value: res.HeadEventHash},
			{Key: "ledger_hash", Value: fileSHA},
		}
		line(ctx, "%s", ndjson.Encode(obj))
	} else {
		line(ctx, "ledger checkpoint: ok")
		line(ctx, "events: %d", res.EventCount)
		line(ctx, "head_event_hash: %s", res.HeadEventHash)
		line(ctx, "ledger_hash: %s", fileSHA)
	}
	return nil
}
