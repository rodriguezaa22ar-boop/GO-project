package conformance

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rodriguezaa22ar-boop/go-project/internal/cli"
)

// run drives the real CLI against LCOAT_ROOT and returns stdout, stderr and
// the exit code.
func run(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := cli.Run(args, &out, &errOut)
	return out.String(), errOut.String(), code
}

func mustRun(t *testing.T, args ...string) string {
	t.Helper()
	out, errOut, code := run(t, args...)
	if code != 0 {
		t.Fatalf("lcoat %s: exit %d\n%s%s", strings.Join(args, " "), code, out, errOut)
	}
	return out
}

// Read-only list commands must work on a closed operation by name; after
// op close there is no active operation to fall back on.
func TestListCommandsWorkOnClosedOperationByName(t *testing.T) {
	root := t.TempDir()
	t.Setenv("LCOAT_ROOT", root)
	src := filepath.Join(t.TempDir(), "recon.txt")
	os.WriteFile(src, []byte("tcp LISTEN 0.0.0.0:22\n"), 0o600)

	mustRun(t, "target", "add", "box", "127.0.0.1", "--scope-status", "in-scope")
	mustRun(t, "op", "start", "first-op", "box", "test")
	evOut := mustRun(t, "evidence", "add", src)
	mustRun(t, "finding", "add", "SSH reachable", "--level", "observed", "--status", "resolved")
	mustRun(t, "op", "close", "--force")

	// A second operation becomes active; listing first-op by name must still
	// show first-op's records, not the active operation's.
	mustRun(t, "op", "start", "second-op", "box", "test")

	evID := ""
	for _, l := range strings.Split(evOut, "\n") {
		if strings.HasPrefix(l, "id: ") {
			evID = strings.TrimPrefix(l, "id: ")
		}
	}
	if out := mustRun(t, "evidence", "list", "first-op"); !strings.Contains(out, evID) {
		t.Errorf("evidence list first-op missing %s:\n%s", evID, out)
	}
	if out := mustRun(t, "finding", "list", "first-op"); !strings.Contains(out, "SSH reachable") {
		t.Errorf("finding list first-op missing finding:\n%s", out)
	}
	if out := mustRun(t, "scope", "status", "first-op"); !strings.Contains(out, "Operation: first-op") {
		t.Errorf("scope status first-op shows wrong operation:\n%s", out)
	}
	// With no name they still default to the active operation.
	if out := mustRun(t, "finding", "list"); strings.Contains(out, "SSH reachable") {
		t.Errorf("finding list without a name should show the active operation (second-op):\n%s", out)
	}

	// Unknown names and stray arguments are errors, never silently ignored.
	if _, _, code := run(t, "finding", "list", "no-such-op"); code == 0 {
		t.Error("finding list no-such-op succeeded")
	}
	if _, _, code := run(t, "evidence", "list", "first-op", "extra"); code == 0 {
		t.Error("evidence list with two names succeeded")
	}
	if _, _, code := run(t, "scope", "status", "--bogus"); code == 0 {
		t.Error("scope status --bogus succeeded")
	}
}

// An empty $TARGET shifts the arguments left; the CLI must name the real
// problem instead of passing the shifted values to the adapter.
func TestAdapterRunMissingTargetIsReported(t *testing.T) {
	t.Setenv("LCOAT_ROOT", t.TempDir())
	mustRun(t, "target", "add", "box", "127.0.0.1", "--scope-status", "in-scope")
	mustRun(t, "op", "start", "op1", "box", "test")
	_, errOut, code := run(t, "adapter", "run", "nmap", "--timeout", "600", "--", "-sT")
	if code == 0 || !strings.Contains(errOut, "missing <target>") {
		t.Errorf("want missing-target error, got exit %d: %s", code, errOut)
	}
}

// Field test: with LCOAT_ROOT unset, lab data landed in the operator's home
// directory without a word. lcoat must say so.
func TestUnsetRootWarns(t *testing.T) {
	t.Setenv("LCOAT_ROOT", "")
	t.Setenv("LAB_ROOT", "")
	dir := t.TempDir()
	prev, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(prev) })

	_, errOut, _ := run(t, "target", "list")
	if !strings.Contains(errOut, "LCOAT_ROOT is not set") {
		t.Errorf("no warning with LCOAT_ROOT unset; stderr: %q", errOut)
	}
	t.Setenv("LCOAT_ROOT", dir)
	if _, errOut, _ := run(t, "target", "list"); strings.Contains(errOut, "LCOAT_ROOT is not set") {
		t.Errorf("warned even though LCOAT_ROOT is set: %q", errOut)
	}
}
