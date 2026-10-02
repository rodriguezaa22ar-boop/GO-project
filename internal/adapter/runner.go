package adapter

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
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
		_ = op.AppendLedger("adapter.refused", capability, a.Name(), "denied",
			"adapter="+a.Name()+" tier="+itoa(tier)+" reason=above-max-tier")
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

	if err := op.AppendLedger("adapter.started", capability, a.Name(), "ok",
		"adapter="+a.Name()+" tier="+itoa(tier)+" target="+target); err != nil {
		return nil, err
	}

	out, exitCode, dur, runErr := execute(argv, p.Timeout)
	// Capture output as evidence regardless of exit code, so a failed run is
	// still auditable. Write it under a stable basename so the stored
	// artifact path is meaningful, not a temp-file name.
	tmpDir, err := os.MkdirTemp("", "lcoat-adapter-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)
	capturePath := filepath.Join(tmpDir, a.Name()+"-output.txt")
	if err := os.WriteFile(capturePath, out, 0o600); err != nil {
		return nil, err
	}

	rec, err := evidence.Add(op, evidence.AddParams{
		SourcePath: capturePath, Kind: "scan-output", Target: target,
		Classification: "internal", Tool: a.Name(),
	})
	if err != nil {
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
	detail := "adapter=" + a.Name() + " exit=" + itoa(exitCode) + " duration_ms=" + itoa64(res.DurationMS) +
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
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
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

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	if neg {
		d = append([]byte{'-'}, d...)
	}
	return string(d)
}

func itoa64(n int64) string { return itoa(int(n)) }
