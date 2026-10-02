package conformance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/packet"
)

// Editing a stored evidence artifact must be caught even though the
// evidence index (which the packets anchor) is unchanged.
func TestEvidenceVerifyCatchesEditedArtifact(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	operation.Start(l, operation.StartParams{Name: "ev-op", Target: "node", Profile: "htb-starting-point"})
	op := reload(t, l)
	src := filepath.Join(t.TempDir(), "recon.txt")
	os.WriteFile(src, []byte("tcp LISTEN 0.0.0.0:2024\n"), 0o600)
	rec, err := evidence.Add(op, evidence.AddParams{SourcePath: src, Kind: "artifact"})
	if err != nil {
		t.Fatal(err)
	}

	if _, problems, _ := evidence.VerifyArtifacts(op.Dir); problems != 0 {
		t.Fatalf("fresh evidence reported %d problems", problems)
	}
	tc, err := packet.CollectTrustChain(op)
	if err != nil {
		t.Fatal(err)
	}
	if tc.EvidenceVerification != "verified" {
		t.Errorf("fresh trust chain evidence = %s", tc.EvidenceVerification)
	}

	art := filepath.Join(op.Dir, rec.Path)
	os.WriteFile(art, []byte("tcp LISTEN 127.0.0.1:2024\n"), 0o600)
	checks, problems, _ := evidence.VerifyArtifacts(op.Dir)
	if problems != 1 || checks[0].Status != "changed" {
		t.Fatalf("edited artifact: problems=%d checks=%+v", problems, checks)
	}
	tc, _ = packet.CollectTrustChain(op)
	if tc.Status != "attention-required" || tc.EvidenceProblems != 1 {
		t.Errorf("trust chain after edit: status=%s problems=%d", tc.Status, tc.EvidenceProblems)
	}

	os.Remove(art)
	if checks, _, _ := evidence.VerifyArtifacts(op.Dir); checks[0].Status != "missing" {
		t.Errorf("deleted artifact status = %s, want missing", checks[0].Status)
	}
}
