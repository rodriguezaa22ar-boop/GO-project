package packet

import (
	"os"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// VerifyResult is the outcome of verifying one packet.
type VerifyResult struct {
	Status   string // "verified" or "attention-required"
	Verified int
	Gaps     int
	Problems int
	Rows     []string // "LABEL STATUS PATH (detail)" lines
}

type anchorCheck struct {
	v *VerifyResult
}

func (c *anchorCheck) row(label, status, path, detail string) {
	if detail != "" {
		c.v.Rows = append(c.v.Rows, pad(label, 20)+" "+pad(status, 14)+" "+path+" ("+detail+")")
	} else {
		c.v.Rows = append(c.v.Rows, pad(label, 20)+" "+pad(status, 14)+" "+path)
	}
}

// hashAnchor verifies a "- <manifestLabel>: `path` ... sha256=X" line.
func (c *anchorCheck) hashAnchor(text, manifestLabel, display string) {
	line := anchorLine(text, manifestLabel)
	if line == "" {
		c.row(display, "unverifiable", "-", "anchor missing from manifest")
		c.v.Problems++
		return
	}
	path := anchorPath(line)
	if path == "" {
		c.row(display, "unverifiable", "-", "not recorded")
		c.v.Gaps++
		return
	}
	expected := anchorToken(line, "sha256")
	if expected == "" {
		if !state.FileExists(path) {
			c.row(display, "unverifiable", path, "not recorded")
			c.v.Gaps++
		} else {
			c.row(display, "unverifiable", path, "missing expected sha256")
			c.v.Problems++
		}
		return
	}
	if !state.FileExists(path) {
		c.row(display, "missing", path, "expected sha256="+expected)
		c.v.Problems++
		return
	}
	actual := shaForFile(path)
	if actual == expected {
		c.row(display, "verified", path, "")
		c.v.Verified++
	} else {
		c.row(display, "changed", path, "expected="+expected+" actual="+actual)
		c.v.Problems++
	}
}

// ledgerAnchor verifies the "- Operation ledger: `path` events=N sha256=X"
// line, allowing later audit/archive/review events after the anchored prefix.
func (c *anchorCheck) ledgerAnchor(text string, allowLater []string) {
	line := anchorLine(text, "Operation ledger")
	if line == "" {
		c.row("Operation Ledger", "unverifiable", "-", "anchor missing from manifest")
		c.v.Problems++
		return
	}
	path := anchorPath(line)
	expectedEvents := anchorToken(line, "events")
	expectedSHA := anchorToken(line, "sha256")
	if path == "" || expectedEvents == "" || expectedSHA == "" {
		c.row("Operation Ledger", "unverifiable", orDash(path), "missing events or sha256")
		c.v.Problems++
		return
	}
	if !state.FileExists(path) {
		c.row("Operation Ledger", "missing", path, "expected events="+expectedEvents+" sha256="+expectedSHA)
		c.v.Problems++
		return
	}
	actualEvents := ledgerEventCount(path)
	actualSHA := shaForFile(path)
	if itoa(actualEvents) == expectedEvents && actualSHA == expectedSHA {
		c.row("Operation Ledger", "verified", path, "events="+itoa(actualEvents))
		c.v.Verified++
		return
	}
	exp := atoi(expectedEvents)
	if exp >= 0 && actualEvents > exp {
		prefix, _ := ledger.PrefixSHA256(path, exp)
		if prefix == expectedSHA && !hasDisallowedLater(path, exp, allowLater) {
			c.row("Operation Ledger", "verified", path, "events="+itoa(actualEvents)+" anchored_events="+expectedEvents+" later_allowed_events="+itoa(actualEvents-exp))
			c.v.Verified++
			return
		}
	}
	c.row("Operation Ledger", "changed", path, "expected_events="+expectedEvents+" actual_events="+itoa(actualEvents)+" expected_sha="+expectedSHA+" actual_sha="+actualSHA)
	c.v.Problems++
}

func hasDisallowedLater(path string, prefix int, allow []string) bool {
	events, err := ledger.ReadPath(path)
	if err != nil {
		return true
	}
	allowed := map[string]bool{}
	for _, a := range allow {
		allowed[a] = true
	}
	for _, e := range events {
		if e.Line > prefix && !allowed[e.Event] {
			return true
		}
	}
	return false
}

var closeoutAllowLater = []string{"audit.packet.generated", "archive.packet.generated", "finding.review_packet.generated"}

// CloseoutVerify reproduces atlas_closeout_verify_markdown_manifest.
func CloseoutVerify(op *operation.Operation, manifestPath string) (*VerifyResult, error) {
	text, err := readPacket(manifestPath)
	if err != nil {
		return nil, err
	}
	id := field(text, "Operation ID")
	if id == "" {
		return nil, state.Failf("closeout manifest is missing Operation ID: %s", manifestPath)
	}
	if id != op.Slug {
		return nil, state.Failf("closeout manifest belongs to '%s', not '%s'", id, op.Slug)
	}
	v := &VerifyResult{}
	c := &anchorCheck{v: v}
	c.hashAnchor(text, "Latest report", "Latest Report")
	c.hashAnchor(text, "Evidence manifest", "Evidence Manifest")
	c.hashAnchor(text, "Latest handoff", "Latest Handoff")
	c.ledgerAnchor(text, closeoutAllowLater)
	c.hashAnchor(text, "Operation env", "Operation Env")
	c.hashAnchor(text, "Scope snapshot", "Scope Snapshot")
	c.hashAnchor(text, "Evidence index", "Evidence Index")
	c.hashAnchor(text, "Finding index", "Finding Index")
	c.hashAnchor(text, "Validation index", "Validation Index")
	finishStatus(v)
	return v, nil
}

func finishStatus(v *VerifyResult) {
	if v.Problems > 0 {
		v.Status = "attention-required"
	} else {
		v.Status = "verified"
	}
}

func readPacket(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", state.Failf("packet is not a file: %s", path)
		}
		return "", err
	}
	return string(data), nil
}

func pad(s string, n int) string {
	for len(s) < n {
		s += " "
	}
	return s
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func atoi(s string) int {
	if s == "" {
		return -1
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return -1
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
