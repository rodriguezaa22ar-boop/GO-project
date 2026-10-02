package cli

import (
	"os"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ndjson"
	"github.com/rodriguezaa22ar-boop/go-project/internal/receipt"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func runReceipt(ctx *Context, args []string) error {
	if len(args) == 0 {
		return state.Failf("receipt create|verify|replay")
	}
	switch args[0] {
	case "verify":
		return receiptVerify(ctx, args[1:])
	case "replay":
		return receiptReplay(ctx, args[1:])
	case "create":
		return receiptCreate(ctx, args[1:])
	}
	return state.Failf("unknown receipt command: %s", args[0])
}

func receiptVerify(ctx *Context, args []string) error {
	if err := needArgs(1, args, "receipt verify <receipt-file|-> [--json]"); err != nil {
		return err
	}
	input := args[0]
	jsonOut := false
	for _, a := range args[1:] {
		if a == "--json" {
			jsonOut = true
		} else {
			return state.Failf("unknown receipt verify option: %s", a)
		}
	}
	res, _, err := receipt.VerifyFile(input)
	if err != nil {
		return err
	}
	if jsonOut {
		var prev any
		if res.PrevHash != "null" {
			prev = res.PrevHash
		} else {
			prev = "null"
		}
		obj := ndjson.Object{
			{Key: "schema_version", Value: "atlas.receipt_verify.v1"},
			{Key: "status", Value: "ok"},
			{Key: "receipt_id", Value: res.ReceiptID},
			{Key: "action", Value: res.Action},
			{Key: "event_hash", Value: res.EventHash},
			{Key: "prev_hash", Value: prev},
			{Key: "receipt_hash", Value: res.ReceiptHash},
			{Key: "evidence_ref_count", Value: res.EvidenceRefs},
			{Key: "artifact_ref_count", Value: res.ArtifactRefs},
			{Key: "approval_ref_count", Value: res.ApprovalRefs},
			{Key: "metadata_only", Value: true},
			{Key: "raw_artifacts_embedded", Value: false},
		}
		line(ctx, "%s", ndjson.Encode(obj))
	} else {
		line(ctx, "receipt: ok")
		line(ctx, "This receipt validates as a metadata-only proof record.")
		line(ctx, "It does not prove external artifact availability, human intent, legal compliance, or artifact correctness.")
	}
	return nil
}

func receiptReplay(ctx *Context, args []string) error {
	jsonOut := false
	var inputs []string
	i := 0
	for i < len(args) {
		switch args[i] {
		case "--json":
			jsonOut = true
			i++
		case "--":
			inputs = append(inputs, args[i+1:]...)
			i = len(args)
		default:
			if len(args[i]) > 1 && args[i][0] == '-' {
				return state.Failf("unknown receipt replay option: %s", args[i])
			}
			inputs = append(inputs, args[i])
			i++
		}
	}
	res, err := receipt.Replay(inputs)
	if err != nil {
		return err
	}
	if jsonOut {
		line(ctx, "%s", ndjson.Encode(replayObject(res)))
	} else {
		line(ctx, "receipt replay: ok")
		line(ctx, "receipts: %d", res.ReceiptCount)
		line(ctx, "ledger binding: ok prev_hash -> event_hash")
		line(ctx, "chain_head_event_hash: %s", res.ChainHeadEventHash)
		line(ctx, "chain_head_receipt_hash: %s", res.ChainHeadReceiptHash)
		line(ctx, "metadata-only boundary: ok")
		line(ctx, "This replay verifies receipt hashes and provided-order prev_hash linkage only.")
		line(ctx, "It does not prove external artifact availability, human intent, legal compliance, artifact correctness, authorization, or production readiness.")
	}
	return nil
}

func replayObject(res *receipt.ReplayResult) ndjson.Object {
	chain := make([]any, 0, len(res.Chain))
	for _, r := range res.Chain {
		var prev any
		if r.PrevHash == "" {
			prev = nil
		} else {
			prev = r.PrevHash
		}
		chain = append(chain, ndjson.Object{
			{Key: "index", Value: r.Index},
			{Key: "path", Value: r.Path},
			{Key: "receipt_id", Value: r.ReceiptID},
			{Key: "action", Value: r.Action},
			{Key: "prev_hash", Value: prev},
			{Key: "event_hash", Value: r.EventHash},
			{Key: "receipt_hash", Value: r.ReceiptHash},
			{Key: "linkage_status", Value: r.LinkageStatus},
		})
	}
	return ndjson.Object{
		{Key: "schema_version", Value: "atlas.receipt_replay.v1"},
		{Key: "status", Value: "ok"},
		{Key: "metadata_only", Value: true},
		{Key: "raw_artifacts_embedded", Value: false},
		{Key: "receipt_count", Value: res.ReceiptCount},
		{Key: "first_event_hash", Value: res.FirstEventHash},
		{Key: "chain_head_event_hash", Value: res.ChainHeadEventHash},
		{Key: "chain_head_receipt_hash", Value: res.ChainHeadReceiptHash},
	}
}

func receiptCreate(ctx *Context, args []string) error {
	p := receipt.CreateParams{}
	var outFile string
	jsonOut := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--receipt-id", "--timestamp", "--action", "--actor", "--subject-type",
			"--subject", "--prev-hash", "--evidence-ref", "--artifact-ref", "--approval-ref",
			"--limitation", "--out":
			v, err := option(args, i, "receipt create "+args[i]+" <value>")
			if err != nil {
				return err
			}
			switch args[i] {
			case "--receipt-id":
				p.ReceiptID = v
			case "--timestamp":
				p.Timestamp = v
			case "--action":
				p.Action = v
			case "--actor":
				p.Actor = v
			case "--subject-type":
				p.SubjectType = v
			case "--subject":
				p.SubjectRef = v
			case "--prev-hash":
				p.PrevHash = v
			case "--evidence-ref":
				p.EvidenceRefs = append(p.EvidenceRefs, v)
			case "--artifact-ref":
				p.ArtifactRefs = append(p.ArtifactRefs, v)
			case "--approval-ref":
				p.ApprovalRefs = append(p.ApprovalRefs, v)
			case "--limitation":
				p.Limitations = append(p.Limitations, v)
			case "--out":
				outFile = v
			}
			i++
		case "--json":
			jsonOut = true
		default:
			return state.Failf("unknown receipt create option: %s", args[i])
		}
	}
	body, err := receipt.Create(p)
	if err != nil {
		return err
	}
	if outFile != "" {
		if err := os.WriteFile(outFile, body, 0o600); err != nil {
			return err
		}
		if jsonOut {
			ctx.Out.Write(body)
		} else {
			kv(ctx, "receipt", outFile)
		}
	} else {
		ctx.Out.Write(body)
	}
	return nil
}
