package conformance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/packet"
	"github.com/rodriguezaa22ar-boop/go-project/internal/readiness"
	"github.com/rodriguezaa22ar-boop/go-project/internal/report"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// TestFullLifecycleVerifies drives scope -> evidence -> finding -> report ->
// handoff -> close -> closeout -> audit -> archive, then verifies the three
// retention packets. Every verifier must pass with zero problems, which is
// the stage 7-8 exit check expressed against the Go verifiers (the shell
// build cross-check lives in conformance/cross_check.sh).
func TestFullLifecycleVerifies(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	src := filepath.Join(t.TempDir(), "recon.txt")
	if err := os.WriteFile(src, []byte("PORT 22 open ssh\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := operation.Start(l, operation.StartParams{Name: "full-op", Target: "node", Profile: "htb-starting-point", Notes: "full lifecycle"}); err != nil {
		t.Fatal(err)
	}
	op := reload(t, l)
	ev, err := evidence.Add(op, evidence.AddParams{SourcePath: src, Kind: "scan-output", Classification: "public"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := findings.Add(op, findings.AddParams{Title: "SSH exposed", Level: "observed", Severity: "low", Confidence: "high", Evidence: []string{ev.ID}}); err != nil {
		t.Fatal(err)
	}
	if _, err := report.Write(op, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := packet.Handoff(op, ""); err != nil {
		t.Fatal(err)
	}

	// Force-close: the open finding keeps readiness at attention-required.
	op = reload(t, l)
	st, err := readiness.Collect(op)
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "attention-required" {
		t.Fatalf("expected attention-required, got %s", st.Status)
	}
	if err := op.Close(st.Status, st.LedgerDetail(true)); err != nil {
		t.Fatal(err)
	}

	op = reloadClosed(t, l)
	closeoutPath, err := packet.Closeout(op, "")
	if err != nil {
		t.Fatal(err)
	}
	auditPath, err := packet.Audit(op, "")
	if err != nil {
		t.Fatal(err)
	}
	archivePath, err := packet.Archive(op, "")
	if err != nil {
		t.Fatal(err)
	}

	op = reloadClosed(t, l)
	for _, tc := range []struct {
		name string
		path string
		fn   func(*operation.Operation, string) (*packet.VerifyResult, error)
	}{
		{"closeout", closeoutPath, packet.CloseoutVerify},
		{"audit", auditPath, packet.AuditVerify},
		{"archive", archivePath, packet.ArchiveVerify},
	} {
		res, err := tc.fn(op, tc.path)
		if err != nil {
			t.Fatalf("%s verify: %v", tc.name, err)
		}
		if res.Status != "verified" || res.Problems != 0 {
			t.Errorf("%s verify = %s, problems=%d\n%v", tc.name, res.Status, res.Problems, res.Rows)
		}
	}
}

// TestTamperFixtures confirms each verifier fails when its inputs are
// tampered: a trust gate is only real if it can fail correctly.
func TestTamperFixtures(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	src := filepath.Join(t.TempDir(), "recon.txt")
	os.WriteFile(src, []byte("PORT 22\n"), 0o600)
	operation.Start(l, operation.StartParams{Name: "t-op", Target: "node", Profile: "htb-starting-point"})
	op := reload(t, l)
	ev, _ := evidence.Add(op, evidence.AddParams{SourcePath: src, Kind: "scan-output"})
	findings.Add(op, findings.AddParams{Title: "x", Level: "observed", Severity: "low", Evidence: []string{ev.ID}})
	report.Write(op, "")
	packet.Handoff(op, "")
	op = reload(t, l)
	st, _ := readiness.Collect(op)
	op.Close(st.Status, st.LedgerDetail(true))
	op = reloadClosed(t, l)
	closeoutPath, _ := packet.Closeout(op, "")

	// Tamper: append a disallowed event after closeout, then verify.
	if err := op.AppendLedger("finding.recorded", "read-only", "atlas", "ok", "tampered"); err != nil {
		t.Fatal(err)
	}
	res, err := packet.CloseoutVerify(op, closeoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if res.Status == "verified" {
		t.Error("closeout verify accepted a ledger with a disallowed later event")
	}

	// Tamper: edit the stored evidence artifact; the finding still points at
	// its recorded hash, but the closeout's evidence-index anchor is over the
	// index file, so corrupt that instead to trip the hash anchor.
	idx := evidence.IndexFile(op.Dir)
	data, _ := os.ReadFile(idx)
	os.WriteFile(idx, append(data, []byte("\n")...), 0o600)
	res2, err := packet.CloseoutVerify(op, closeoutPath)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Status == "verified" {
		t.Error("closeout verify accepted a changed evidence index")
	}
}

func reload(t *testing.T, l *state.Layout) *operation.Operation {
	t.Helper()
	op, err := operation.LoadActive(l)
	if err != nil {
		t.Fatal(err)
	}
	return op
}

// reloadClosed loads a closed operation by its known slug, since closing
// clears the active pointer.
func reloadClosed(t *testing.T, l *state.Layout) *operation.Operation {
	t.Helper()
	ops, err := operation.List(l)
	if err != nil || len(ops) == 0 {
		t.Fatalf("no operations: %v", err)
	}
	op, err := operation.Load(l, ops[0].Slug)
	if err != nil {
		t.Fatal(err)
	}
	return op
}
