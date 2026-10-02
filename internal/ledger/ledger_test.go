package ledger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

const golden = "../../testdata/golden/learning-op-001"

// Values reported by the shell build (atlas ledger checkpoint --json and the
// archive packet) for the golden fixture. These are the day 1-2 exit check.
const (
	goldenEvents   = 18
	goldenFileSHA  = "ba36a56433f5a4153a1d430bb4632bfe7bdcc989adbf5438ba1ea667758f0c6f"
	goldenHeadHash = "abd88a7fe5dbf8b017a73a9a8ae5e84a1afb396bde656f2d0d558eb2bc6a1b75"
)

func TestGoldenLedgerMatchesShellBuild(t *testing.T) {
	path := File(golden)
	sum, err := state.SHA256File(path)
	if err != nil {
		t.Fatal(err)
	}
	if sum != goldenFileSHA {
		t.Errorf("file sha256 = %s, want %s", sum, goldenFileSHA)
	}
	n, err := Count(path)
	if err != nil {
		t.Fatal(err)
	}
	if n != goldenEvents {
		t.Errorf("event count = %d, want %d", n, goldenEvents)
	}
	res, err := VerifyOperationLedger(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.EventCount != goldenEvents || res.HeadEventHash != goldenHeadHash {
		t.Errorf("verify = %+v, want events=%d head=%s", res, goldenEvents, goldenHeadHash)
	}
	// Closeout anchored 16 events; the prefix hash must equal the hash the
	// closeout manifest recorded.
	prefix, err := PrefixSHA256(path, 16)
	if err != nil {
		t.Fatal(err)
	}
	manifest, _ := os.ReadFile(filepath.Join(golden, "closeout", "learning-op-001-closeout.md"))
	if !strings.Contains(string(manifest), "events=16 sha256="+prefix) {
		t.Errorf("prefix sha256 %s not found in closeout manifest", prefix)
	}
}

func TestAppendReproducesShellEncoding(t *testing.T) {
	dir := t.TempDir()
	state.Now = fixedClock("2026-10-02T05:39:55Z")
	defer func() { state.Now = defaultClock }()
	err := Append(dir, Event{
		Event: "op.started", Op: "learning-op-001", Target: "demo-learning-node",
		Capability: "read-only", Tool: "atlas", Status: "ok",
		Detail: "profile=htb-starting-point notes=authorized metadata-only learning operation using claude",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(File(dir))
	want, _ := os.ReadFile(File(golden))
	firstLine := strings.SplitN(string(want), "\n", 2)[0] + "\n"
	if string(got) != firstLine {
		t.Errorf("encoded event differs\n got: %s\nwant: %s", got, firstLine)
	}
}

func TestVerifyRejectsForbiddenContent(t *testing.T) {
	dir := t.TempDir()
	if err := Append(dir, Event{Event: "x", Op: "o", Target: "t", Capability: "read-only", Tool: "atlas", Status: "ok", Detail: "Authorization: Bearer abc"}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOperationLedger(File(dir)); err == nil {
		t.Fatal("expected forbidden content to fail verification")
	}
}

func TestVerifyRejectsTamperedLine(t *testing.T) {
	dir := t.TempDir()
	src, _ := os.ReadFile(File(golden))
	tampered := strings.Replace(string(src), `"status":"ok"`, `"status":""`, 1)
	if err := os.WriteFile(File(dir), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyOperationLedger(File(dir)); err == nil {
		t.Fatal("expected empty status to fail verification")
	}
}
