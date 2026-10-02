package adapter

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// Result is the outcome of an adapter run.
type Result struct {
	Adapter    string
	Capability string
	Tier       int
	Argv       []string
	ExitCode   int
	DurationMS int64
	EvidenceID string
	SHA256     string
	Proposed   []ProposedFinding
}

// RunParams holds the inputs to Run.
type RunParams struct {
	AdapterName string
	Target      string
	Args        []string
	Timeout     time.Duration
}

// Run classifies, preflights, executes the tool, captures its output as
// hashed evidence and records adapter.started/adapter.finished in the
// ledger. It refuses anything above Tier 2 before the tool is executed.
func Run(op *operation.Operation, p RunParams) (*Result, error) {
	a, ok := Lookup(p.AdapterName)
	if !ok {
		if p.AdapterName == "metasploit" {
			return nil, state.Failf("adapter 'metasploit' is refused: exploit modules are Tier 4 or above")
		}
		return nil, state.Failf("unknown adapter: %s", p.AdapterName)
	}
	capability, err := a.Capability(p.Args)
	if err != nil {
		return nil, err
	}
	tier := tierOf(capability)
	if tier < 0 {
		return nil, state.Failf("adapter %s produced an unknown capability", a.Name())
	}
	if tier > MaxTier {
		// Record the refusal intent so the attempt is auditable.
		if lerr := op.AppendLedger("adapter.refused", capability, a.Name(), "denied",
			"adapter="+a.Name()+" tier="+strconv.Itoa(tier)+" reason=above-max-tier"); lerr != nil {
			fmt.Fprintf(os.Stderr, "lcoat: warning: could not record adapter.refused: %v\n", lerr)
		}
		return nil, state.Failf("adapter %s classified as tier %d (%s); Lite refuses anything above tier %d", a.Name(), tier, capability, MaxTier)
	}

	target := p.Target
	if target == "" {
		target = op.Target
	}
	// Scope preflight records a scope.preflight event and fails on refusal.
	if err := op.Preflight(capability, a.Name(), target, "run adapter "+a.Name()); err != nil {
		return nil, err
	}

	ti, err := resolveTarget(op, target)
	if err != nil {
		return nil, err
	}
	argv, err := a.Command(ti, p.Args)
	if err != nil {
		return nil, err
	}

	// Resolve the tool through the same scrubbed PATH it will run with, and
	// fail before adapter.started if it is not installed, so a missing tool
	// is reported plainly instead of being recorded as an empty capture.
	resolved, err := lookPath(argv[0])
	if err != nil {
		return nil, err
	}
	argv[0] = resolved

	if err := op.AppendLedger("adapter.started", capability, a.Name(), "ok",
		"adapter="+a.Name()+" tier="+strconv.Itoa(tier)+" target="+target); err != nil {
		return nil, err
	}

	out, exitCode, dur, runErr := execute(argv, p.Timeout)
	// Capture output as evidence regardless of exit code, so a failed run is
	// still auditable.
	rec, err := captureEvidence(op, a.Name(), target, out)
	if err != nil {
		// Close the started event so the ledger never shows a run that began
		// and silently vanished.
		_ = op.AppendLedger("adapter.finished", capability, a.Name(), "error",
			"adapter="+a.Name()+" exit="+strconv.Itoa(exitCode)+" evidence=none reason=capture-failed")
		return nil, err
	}

	res := &Result{
		Adapter: a.Name(), Capability: capability, Tier: tier, Argv: argv,
		ExitCode: exitCode, DurationMS: dur.Milliseconds(),
		EvidenceID: rec.ID, SHA256: rec.SHA256, Proposed: a.Parse(out),
	}
	status := "ok"
	if runErr != nil || exitCode != 0 {
		status = "error"
	}
	detail := "adapter=" + a.Name() + " exit=" + strconv.Itoa(exitCode) + " duration_ms=" + strconv.FormatInt(res.DurationMS, 10) +
		" evidence=" + rec.ID + " sha256=" + rec.SHA256
	if err := op.AppendLedger("adapter.finished", capability, a.Name(), status, detail); err != nil {
		return nil, err
	}
	return res, nil
}

func resolveTarget(op *operation.Operation, target string) (Target, error) {
	snap, err := op.Snapshot()
	if err != nil {
		return Target{}, err
	}
	addr := target
	if snap.TargetMatches(target) && snap.TargetAddress != "" {
		addr = snap.TargetAddress
	}
	return Target{Name: target, Address: addr}, nil
}

// execute runs argv directly (never via a shell) with a scrubbed
// environment and a hard timeout, capturing combined stdout and stderr.
func execute(argv []string, timeout time.Duration) ([]byte, int, time.Duration, error) {
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now() // real elapsed time, not the frozen LCOAT_NOW clock
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"PATH=" + scrubbedPATH, "LC_ALL=C"}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	dur := time.Since(start)
	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			exitCode = -1
		}
	}
	return buf.Bytes(), exitCode, dur, err
}

// captureEvidence writes the tool output under a stable basename (so the
// stored artifact path is meaningful, not a temp-file name) and records it
// as evidence.
func captureEvidence(op *operation.Operation, adapterName, target string, out []byte) (*evidence.Record, error) {
	tmpDir, err := os.MkdirTemp("", "lcoat-adapter-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	capturePath := filepath.Join(tmpDir, adapterName+"-output.txt")
	if err := os.WriteFile(capturePath, out, 0o600); err != nil {
		return nil, err
	}
	return evidence.Add(op, evidence.AddParams{
		SourcePath: capturePath, Kind: EvidenceKind, Target: target,
		Classification: "internal", Tool: adapterName,
	})
}

// scrubbedPATH is the only PATH adapter tools see.
const scrubbedPATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// lookPath resolves name against scrubbedPATH (not the caller's PATH), or
// checks it directly when it contains a slash.
func lookPath(name string) (string, error) {
	isExec := func(p string) bool {
		fi, err := os.Stat(p)
		return err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0
	}
	if strings.Contains(name, "/") {
		if isExec(name) {
			return name, nil
		}
		return "", state.Failf("tool not found or not executable: %s", name)
	}
	for _, dir := range filepath.SplitList(scrubbedPATH) {
		if p := filepath.Join(dir, name); isExec(p) {
			return p, nil
		}
	}
	return "", state.Failf("tool %q not found in %s; install it or pass an absolute path", name, scrubbedPATH)
}
