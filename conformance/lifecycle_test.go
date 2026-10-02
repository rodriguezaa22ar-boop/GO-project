// Package conformance holds cross-package tests that drive the control
// plane end to end, including checks against golden sessions captured from
// the Atlas shell build.
package conformance

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/findings"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

const golden = "../testdata/golden"

func freeze(t *testing.T, ts string) {
	prev := state.Now
	parsed, _ := time.Parse("2006-01-02T15:04:05Z", ts)
	state.Now = func() time.Time { return parsed }
	t.Cleanup(func() { state.Now = prev })
}

func setupLab(t *testing.T) *state.Layout {
	t.Helper()
	root := t.TempDir()
	profiles := filepath.Join(root, "tools", "atlas", "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(filepath.Join(golden, "profiles", "htb-starting-point.env"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profiles, "htb-starting-point.env"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LCOAT_ROOT", root)
	l, err := state.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if err := l.EnsureLayout(); err != nil {
		t.Fatal(err)
	}
	return l
}

// TestGoldenEvidenceHash is the stage 5-6 exit check: the stored artifact
// hashes to the value recorded in the shell build's evidence index.
func TestGoldenEvidenceHash(t *testing.T) {
	const want = "fa0def3c96e0f68e7fe02036187b47485ab9aabe60919692770bae396c1267ad"
	path := filepath.Join(golden, "learning-op-001", "evidence", "ev_20261002T054004Z", "recon-output.txt")
	got, err := state.SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("evidence sha256 = %s, want %s", got, want)
	}
}

func TestSameSecondIDCollision(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	src := filepath.Join(t.TempDir(), "recon.txt")
	if err := os.WriteFile(src, []byte("scan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := operation.Start(l, operation.StartParams{Name: "collide-op", Target: "node-a", Profile: "htb-starting-point"}); err != nil {
		t.Fatal(err)
	}
	op, err := operation.LoadActive(l)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for i := 0; i < 3; i++ {
		rec, err := evidence.Add(op, evidence.AddParams{SourcePath: src, Kind: "scan-output"})
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, rec.ID)
	}
	want := []string{"ev_20261002T074000Z", "ev_20261002T074000Z_02", "ev_20261002T074000Z_03"}
	for i := range want {
		if ids[i] != want[i] {
			t.Errorf("id[%d] = %s, want %s", i, ids[i], want[i])
		}
	}
	f1, err := findings.Add(op, findings.AddParams{Title: "one", Level: "observed", Severity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	f2, err := findings.Add(op, findings.AddParams{Title: "two", Level: "observed", Severity: "low"})
	if err != nil {
		t.Fatal(err)
	}
	if f1.ID == f2.ID {
		t.Errorf("finding IDs collided: %s", f1.ID)
	}
}

func TestStartWritesExpectedScope(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	op, profile, err := operation.Start(l, operation.StartParams{Name: "s-op", Target: "node-x", Profile: "htb-starting-point", Notes: "note"})
	if err != nil {
		t.Fatal(err)
	}
	if profile.Name != "htb-starting-point" || op.Status != "active" {
		t.Fatalf("profile=%s status=%s", profile.Name, op.Status)
	}
	snap, err := op.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if snap.Allowed != "read-only passive-recon active-recon safe-validation" {
		t.Errorf("allowed = %q", snap.Allowed)
	}
	if operation.ActiveSlug(l) != "s-op" {
		t.Errorf("active = %s", operation.ActiveSlug(l))
	}
}
