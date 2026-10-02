// Package adapter wraps external tools (nmap, arbitrary scripts) as
// subprocesses behind a scope check. The tool never needs to know about
// Atlas: the runner supplies classification, the ledger entries and the
// evidence hashing around it. Nothing above Tier 2 is allowed.
package adapter

import (
	"github.com/rodriguezaa22ar-boop/go-project/internal/evidence"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
)

// Target is the subset of target metadata an adapter needs to build its
// command line.
type Target struct {
	Name    string
	Address string
}

// ProposedFinding is a finding an adapter suggests from its output. The
// runner prints these for the operator to confirm; nothing is recorded as a
// finding automatically.
type ProposedFinding struct {
	Title      string
	Severity   string
	Confidence string
	Detail     string
}

// Adapter wraps one external tool.
type Adapter interface {
	// Name is the adapter's identifier, e.g. "nmap".
	Name() string
	// Capability maps the arguments to a scope capability (which fixes the
	// tier). Unknown arguments must map to a higher capability, never a
	// lower one.
	Capability(args []string) (string, error)
	// Command returns the argv to execute. It is never passed to a shell.
	Command(t Target, args []string) ([]string, error)
	// Parse extracts proposed findings from captured output. It may return
	// nil when the adapter does not parse output.
	Parse(out []byte) []ProposedFinding
}

// registry holds the built-in adapters.
var registry = map[string]Adapter{}

func register(a Adapter) { registry[a.Name()] = a }

// Lookup returns a registered adapter by name.
func Lookup(name string) (Adapter, bool) {
	a, ok := registry[name]
	return a, ok
}

// Names returns the registered adapter names in a stable order.
func Names() []string {
	return []string{"nmap", "script"}
}

// MaxTier is the highest capability tier Lite will run. Tier 3 (safe
// validation) and above need the approval plane, which Lite has not ported.
const MaxTier = 2

// tierOf returns the numeric tier for a capability, or -1 when unknown.
func tierOf(capability string) int { return scope.Tier(capability) }

// EvidenceKind is the evidence kind recorded for adapter output. The report
// uses it to list recon artifacts captured through adapters.
const EvidenceKind = evidence.KindAdapterOutput
