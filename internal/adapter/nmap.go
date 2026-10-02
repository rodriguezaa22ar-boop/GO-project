package adapter

import (
	"encoding/xml"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func init() { register(nmapAdapter{}) }

type nmapAdapter struct{}

func (nmapAdapter) Name() string { return "nmap" }

// Capability classifies an nmap invocation. A host-discovery-only sweep
// (-sn) is passive recon (tier 1); any scan that probes ports or services is
// active recon (tier 2). Unknown flags do not lower the tier.
func (nmapAdapter) Capability(args []string) (string, error) {
	hasSn := false
	for _, a := range args {
		if a == "-sn" {
			hasSn = true
		}
	}
	// If -sn is present and no explicit port scan flag is, treat as passive.
	portScan := false
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "-p"), a == "-sS", a == "-sT", a == "-sU", a == "-sV", a == "-A", a == "-F":
			portScan = true
		}
	}
	if hasSn && !portScan {
		return scope.PassiveRecon, nil
	}
	return scope.ActiveRecon, nil
}

// Command builds `nmap <args> -oX - <address>` so output is XML on stdout.
// The operator's args come first; the runner forbids output-redirect flags.
func (nmapAdapter) Command(t Target, args []string) ([]string, error) {
	for _, a := range args {
		if a == "-oX" || a == "-oN" || a == "-oG" || a == "-oA" {
			return nil, state.Failf("nmap adapter manages output; remove %s", a)
		}
	}
	argv := []string{"nmap"}
	argv = append(argv, args...)
	argv = append(argv, "-oX", "-", t.Address)
	return argv, nil
}

// Parse reads nmap XML and proposes one finding per open port.
func (nmapAdapter) Parse(out []byte) []ProposedFinding {
	var run nmapRun
	if err := xml.Unmarshal(out, &run); err != nil {
		return nil
	}
	var findings []ProposedFinding
	for _, host := range run.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			svc := port.Service.Name
			if port.Service.Product != "" {
				svc = strings.TrimSpace(port.Service.Name + " " + port.Service.Product)
			}
			title := "Open " + port.Protocol + "/" + port.PortID
			if svc != "" {
				title += " (" + svc + ")"
			}
			findings = append(findings, ProposedFinding{
				Title:      title,
				Severity:   "info",
				Confidence: "high",
				Detail:     "nmap reported " + port.PortID + "/" + port.Protocol + " open",
			})
		}
	}
	return findings
}

// nmap XML subset.
type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Ports []nmapPort `xml:"ports>port"`
}

type nmapPort struct {
	Protocol string      `xml:"protocol,attr"`
	PortID   string      `xml:"portid,attr"`
	State    nmapState   `xml:"state"`
	Service  nmapService `xml:"service"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
}
