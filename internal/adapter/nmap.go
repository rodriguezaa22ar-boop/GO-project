package adapter

import (
	"encoding/xml"
	"strconv"
	"strings"
	"time"

	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func init() { register(nmapAdapter{}) }

type nmapAdapter struct{}

func (nmapAdapter) Name() string { return "nmap" }

// DefaultTimeout is longer than the runner's 120 s default: in the field
// test, -sV across 1,000 ports took over 3 minutes and was cut off.
func (nmapAdapter) DefaultTimeout() time.Duration { return 10 * time.Minute }

// The nmap adapter accepts an allowlist of flags only. Anything else is
// refused, including every positional argument: the target address is
// supplied by the adapter from the scope snapshot, so operator args can
// never add hosts (bare addresses, -iL, -iR), redirect output (-o*), pick
// arbitrary NSE scripts, or use evasion/spoofing options.

// nmapBareFlags take no value.
var nmapBareFlags = map[string]bool{
	"-sn": true, "-sS": true, "-sT": true, "-sU": true, "-sV": true,
	"-sC": true, "-A": true, "-O": true, "-F": true, "-r": true,
	"-Pn": true, "-n": true, "-6": true, "-v": true, "-vv": true,
	"--open": true, "--reason": true, "--traceroute": true,
	"--version-light": true, "--version-all": true,
	"-T0": true, "-T1": true, "-T2": true, "-T3": true, "-T4": true, "-T5": true,
}

// nmapValueFlags take exactly one value, either as the next argument or
// joined with "=". The validator checks the value.
var nmapValueFlags = map[string]func(string) bool{
	"--top-ports":         isPositiveInt,
	"--version-intensity": func(v string) bool { n, err := strconv.Atoi(v); return err == nil && n >= 0 && n <= 9 },
	"--max-retries":       isNonNegativeInt,
	"--max-rate":          isPositiveInt,
	"--host-timeout":      isDuration,
	"--exclude-ports":     isPortSpec,
	"--script":            isSafeScriptExpr,
	"-p":                  isPortSpec,
}

// nmapPassiveFlags may accompany -sn without raising it above passive recon.
var nmapPassiveFlags = map[string]bool{
	"-sn": true, "-n": true, "-6": true, "-v": true, "-vv": true, "--reason": true,
	"-T0": true, "-T1": true, "-T2": true, "-T3": true, "-T4": true, "-T5": true,
	"--max-retries": true, "--host-timeout": true, "--max-rate": true,
}

// parseNmapArgs validates operator args against the allowlist and returns
// the flag names that were used, in order.
func parseNmapArgs(args []string) ([]string, error) {
	var used []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if nmapBareFlags[a] {
			used = append(used, a)
			continue
		}
		name, val, joined := a, "", false
		if strings.HasPrefix(a, "--") {
			if k, v, ok := strings.Cut(a, "="); ok {
				name, val, joined = k, v, true
			}
		} else if strings.HasPrefix(a, "-p") && len(a) > 2 {
			name, val, joined = "-p", a[2:], true
		}
		check, ok := nmapValueFlags[name]
		if !ok {
			if !strings.HasPrefix(a, "-") {
				return nil, state.Failf("nmap adapter: positional argument %q refused; the target comes from the operation scope", a)
			}
			return nil, state.Failf("nmap adapter: flag %q is not on the Lite allowlist", a)
		}
		if !joined {
			if i+1 >= len(args) {
				return nil, state.Failf("nmap adapter: %s requires a value", name)
			}
			i++
			val = args[i]
		}
		if !check(val) {
			return nil, state.Failf("nmap adapter: invalid value for %s: %q", name, val)
		}
		used = append(used, name)
	}
	return used, nil
}

// Capability classifies an nmap invocation. A host-discovery-only sweep
// (-sn with only timing/verbosity options) is passive recon (tier 1);
// anything else on the allowlist is active recon (tier 2). Flags off the
// allowlist are refused rather than classified.
func (nmapAdapter) Capability(args []string) (string, error) {
	used, err := parseNmapArgs(args)
	if err != nil {
		return "", err
	}
	hasSn, passive := false, true
	for _, f := range used {
		if f == "-sn" {
			hasSn = true
		}
		if !nmapPassiveFlags[f] {
			passive = false
		}
	}
	if hasSn && passive {
		return scope.PassiveRecon, nil
	}
	return scope.ActiveRecon, nil
}

// Command builds `nmap <args> -oX - <address>` so output is XML on stdout.
func (nmapAdapter) Command(t Target, args []string) ([]string, error) {
	if _, err := parseNmapArgs(args); err != nil {
		return nil, err
	}
	if t.Address == "" || strings.HasPrefix(t.Address, "-") {
		return nil, state.Failf("nmap adapter: invalid target address %q", t.Address)
	}
	argv := []string{"nmap"}
	argv = append(argv, args...)
	argv = append(argv, "-oX", "-", t.Address)
	return argv, nil
}

func isPositiveInt(v string) bool    { n, err := strconv.Atoi(v); return err == nil && n > 0 }
func isNonNegativeInt(v string) bool { n, err := strconv.Atoi(v); return err == nil && n >= 0 }

// isDuration accepts nmap time specs: digits with an optional ms/s/m/h unit.
func isDuration(v string) bool {
	num := strings.TrimRight(v, "smh")
	if num == "" || len(v)-len(num) > 2 {
		return false
	}
	return isPositiveInt(num)
}

// isPortSpec accepts digits, commas, dashes and protocol prefixes (T:, U:).
func isPortSpec(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		switch {
		case r >= '0' && r <= '9', r == ',', r == '-', r == ':', r == 'T', r == 'U':
		default:
			return false
		}
	}
	return true
}

// isSafeScriptExpr accepts only the NSE "default" and "safe" categories.
// Named scripts and other categories (vuln, brute, exploit, intrusive, dos)
// can exceed tier 2, so they are refused.
func isSafeScriptExpr(v string) bool {
	if v == "" {
		return false
	}
	for _, part := range strings.Split(v, ",") {
		if part != "default" && part != "safe" {
			return false
		}
	}
	return true
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
