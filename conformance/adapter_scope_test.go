package conformance

import (
	"strings"
	"testing"

	"github.com/rodriguezaa22ar-boop/go-project/internal/adapter"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/report"
)

// Operator args must never widen the scan beyond the scoped target, change
// where output goes, or raise the work above tier 2.
func TestNmapRefusesOutOfAllowlistArgs(t *testing.T) {
	a, _ := adapter.Lookup("nmap")
	refused := [][]string{
		{"-sV", "10.0.0.0/8"},         // extra target
		{"scanme.example"},            // extra target, no flags
		{"-iL", "hosts.txt"},          // targets from file
		{"-iR", "100"},                // random internet hosts
		{"--resume", "old.xml"},       // resumes someone else's target list
		{"--script", "vuln"},          // above tier 2
		{"--script=safe,brute"},       // one bad category is enough
		{"--script", "smb-brute"},     // named scripts refused
		{"--script-args", "x=1"},      // not allowlisted
		{"-oX", "out.xml"},            // output managed by adapter
		{"-oXout.xml"},                // joined form
		{"-oS", "x"},                  // other output forms
		{"-D", "RND:10"},              // decoys
		{"-S", "1.2.3.4"},             // spoofed source
		{"--min-rate", "100000"},      // flood rate
		{"-p", "80;id"},               // malformed port spec
		{"--top-ports"},               // missing value
		{"--host-timeout", "forever"}, // bad duration
	}
	for _, args := range refused {
		if _, err := a.Capability(args); err == nil {
			t.Errorf("Capability(%q) accepted, want refusal", args)
		}
		if _, err := a.Command(adapter.Target{Name: "n", Address: "10.0.0.5"}, args); err == nil {
			t.Errorf("Command(%q) accepted, want refusal", args)
		}
	}
}

func TestNmapAllowlistClassification(t *testing.T) {
	a, _ := adapter.Lookup("nmap")
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"-sn"}, "passive-recon"},
		{[]string{"-sn", "-T4", "-n", "--max-retries", "1"}, "passive-recon"},
		{[]string{"-sn", "--script", "safe"}, "active-recon"},
		{[]string{"-sn", "-p22"}, "active-recon"},
		{[]string{"-sV", "--top-ports", "100"}, "active-recon"},
		{[]string{"-p", "22,80,1000-1024"}, "active-recon"},
		{[]string{"--script=default,safe", "-sV"}, "active-recon"},
		{[]string{"-A", "--host-timeout", "30s"}, "active-recon"},
		{nil, "active-recon"},
	}
	for _, c := range cases {
		got, err := a.Capability(c.args)
		if err != nil {
			t.Errorf("Capability(%q) refused: %v", c.args, err)
			continue
		}
		if got != c.want {
			t.Errorf("Capability(%q) = %s, want %s", c.args, got, c.want)
		}
	}
}

func TestNmapCommandUsesScopedAddressOnly(t *testing.T) {
	a, _ := adapter.Lookup("nmap")
	argv, err := a.Command(adapter.Target{Name: "astra", Address: "100.71.57.96"}, []string{"-sV", "--top-ports", "100"})
	if err != nil {
		t.Fatal(err)
	}
	want := "nmap -sV --top-ports 100 -oX - 100.71.57.96"
	if got := strings.Join(argv, " "); got != want {
		t.Errorf("argv = %q, want %q", got, want)
	}
	if _, err := a.Command(adapter.Target{Name: "x", Address: "-iR"}, nil); err == nil {
		t.Error("address beginning with '-' accepted")
	}
}

// A refused nmap invocation must fail before the scope preflight and before
// adapter.started, so nothing is executed and the ledger shows no run.
func TestNmapRefusalHappensBeforeExecution(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	operation.Start(l, operation.StartParams{Name: "n-op", Target: "node", Profile: "htb-starting-point"})
	op := reload(t, l)
	if _, err := adapter.Run(op, adapter.RunParams{AdapterName: "nmap", Target: "node", Args: []string{"-sV", "10.0.0.0/8"}}); err == nil {
		t.Fatal("expected refusal")
	}
	events, _ := ledger.Read(op.Dir)
	for _, e := range events {
		if e.Event == "adapter.started" || e.Event == "adapter.finished" {
			t.Errorf("unexpected %s event after refusal", e.Event)
		}
	}
}

func TestReportListsAdapterEvidence(t *testing.T) {
	freeze(t, "2026-10-02T07:40:00Z")
	l := setupLab(t)
	operation.Start(l, operation.StartParams{Name: "rep-op", Target: "node", Profile: "htb-starting-point"})
	op := reload(t, l)

	before, err := report.Render(op)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(before, "- No recon or action artifacts tracked yet.\n") {
		t.Error("report without adapter runs should keep the shell build's wording")
	}

	res, err := adapter.Run(op, adapter.RunParams{
		AdapterName: "script", Target: "node",
		Args: []string{"--tier", "1", "--", "/bin/echo", "PORT 22 open"},
	})
	if err != nil {
		t.Fatal(err)
	}
	after, err := report.Render(op)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(after, "No recon or action artifacts tracked yet") {
		t.Error("report still claims no recon artifacts after an adapter run")
	}
	if !strings.Contains(after, "- Recon artifact: "+res.EvidenceID+" ") || !strings.Contains(after, "sha256="+res.SHA256) {
		t.Errorf("report does not list adapter evidence %s:\n%s", res.EvidenceID, after)
	}
	if strings.Contains(after, "PORT 22 open") {
		t.Error("report leaked raw tool output; it must stay metadata-only")
	}
}
