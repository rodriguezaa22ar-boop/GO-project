package conformance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rodriguezaa22ar-boop/go-project/internal/adapter"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
)

func TestNmapParseProposedFindings(t *testing.T) {
	data, err := os.ReadFile("../testdata/golden/nmap/sample.xml")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := adapter.Lookup("nmap")
	pf := a.Parse(data)
	if len(pf) != 2 {
		t.Fatalf("expected 2 open-port findings, got %d: %+v", len(pf), pf)
	}
	if pf[0].Title != "Open tcp/22 (ssh OpenSSH)" {
		t.Errorf("finding 0 title = %q", pf[0].Title)
	}
}

func TestNmapCapabilityClassification(t *testing.T) {
	a, _ := adapter.Lookup("nmap")
	if c, _ := a.Capability([]string{"-sn"}); c != "passive-recon" {
		t.Errorf("-sn => %s, want passive-recon", c)
	}
	if c, _ := a.Capability([]string{"-sV"}); c != "active-recon" {
		t.Errorf("-sV => %s, want active-recon", c)
	}
	if c, _ := a.Capability([]string{"-sn", "-p", "80"}); c != "active-recon" {
		t.Errorf("-sn -p => %s, want active-recon (no downgrade)", c)
	}
}

func TestAdapterRunCapturesEvidenceAndEvents(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	operation.Start(l, operation.StartParams{Name: "ad-op", Target: "node", Profile: "htb-starting-point"})
	op := reload(t, l)
	res, err := adapter.Run(op, adapter.RunParams{
		AdapterName: "script", Target: "node",
		Args: []string{"--tier", "2", "--", "/bin/echo", "PORT 22 open"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Tier != 2 || res.Capability != "active-recon" {
		t.Errorf("tier=%d cap=%s", res.Tier, res.Capability)
	}
	// Evidence artifact stored and hashed.
	art := filepath.Join(op.Dir, "evidence", res.EvidenceID, "script-output.txt")
	if _, err := os.Stat(art); err != nil {
		t.Errorf("evidence artifact missing: %v", err)
	}
	// Ledger carries adapter.started and adapter.finished.
	events, _ := ledger.Read(op.Dir)
	var started, finished bool
	for _, e := range events {
		if e.Event == "adapter.started" {
			started = true
		}
		if e.Event == "adapter.finished" {
			finished = true
		}
	}
	if !started || !finished {
		t.Errorf("adapter events: started=%v finished=%v", started, finished)
	}
}

func TestAdapterRefusesAboveTierTwo(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	operation.Start(l, operation.StartParams{Name: "r-op", Target: "node", Profile: "htb-starting-point"})
	op := reload(t, l)
	if _, err := adapter.Run(op, adapter.RunParams{AdapterName: "script", Target: "node", Args: []string{"--", "/bin/echo", "hi"}}); err == nil {
		t.Error("expected undeclared-tier script to be refused")
	}
	if _, err := adapter.Run(op, adapter.RunParams{AdapterName: "metasploit", Target: "node"}); err == nil {
		t.Error("expected metasploit to be refused")
	}
}
