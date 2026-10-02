// Package ledger owns ledger.ndjson. It is the only package that opens the
// file, and it opens it append-only under an advisory lock. Nothing here
// rewrites or reorders events.
package ledger

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ndjson"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// File returns the ledger path for an operation directory.
func File(opDir string) string {
	return filepath.Join(opDir, "ledger.ndjson")
}

// Event is one operation ledger entry in the shell build's field order.
type Event struct {
	TS         string
	Event      string
	Op         string
	Target     string
	Capability string
	Tool       string
	Status     string
	Detail     string
	Line       int // 1-based line number; set when read back
}

func (e Event) object() ndjson.Object {
	return ndjson.Object{
		{Key: "ts", Value: e.TS},
		{Key: "event", Value: e.Event},
		{Key: "op", Value: e.Op},
		{Key: "target", Value: e.Target},
		{Key: "capability", Value: e.Capability},
		{Key: "tool", Value: e.Tool},
		{Key: "status", Value: e.Status},
		{Key: "detail", Value: e.Detail},
	}
}

// Append records an event with the current timestamp.
func Append(opDir string, e Event) error {
	if e.TS == "" {
		e.TS = state.Timestamp()
	}
	if err := os.MkdirAll(opDir, 0o700); err != nil {
		return err
	}
	path := File(opDir)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err == nil {
		defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	}
	line := append(ndjson.Encode(e.object()), '\n')
	_, err = f.Write(line)
	return err
}

// Read returns every event with its line number. A missing or empty ledger
// returns nil.
func Read(opDir string) ([]Event, error) {
	recs, err := ndjson.ReadFile(File(opDir))
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(recs))
	for i, r := range recs {
		out = append(out, Event{
			TS:         r.String("ts"),
			Event:      r.String("event"),
			Op:         r.String("op"),
			Target:     r.String("target"),
			Capability: r.String("capability"),
			Tool:       r.String("tool"),
			Status:     r.String("status"),
			Detail:     r.String("detail"),
			Line:       i + 1,
		})
	}
	return out, nil
}

// Count returns the number of events, like `jq -s length`.
func Count(path string) (int, error) {
	recs, err := ndjson.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return len(recs), nil
}

// PrefixSHA256 hashes the first n lines of the ledger, like
// `head -n N | sha256sum`.
func PrefixSHA256(path string, n int) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for i := 0; i < n && sc.Scan(); i++ {
		h.Write(sc.Bytes())
		h.Write([]byte{'\n'})
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Latest returns the last event whose name matches one of names, or nil.
func Latest(events []Event, names ...string) *Event {
	for i := len(events) - 1; i >= 0; i-- {
		for _, n := range names {
			if events[i].Event == n {
				e := events[i]
				return &e
			}
		}
	}
	return nil
}

// LatestExcept returns the last event whose name is not in names.
func LatestExcept(events []Event, names ...string) *Event {
	for i := len(events) - 1; i >= 0; i-- {
		skip := false
		for _, n := range names {
			if events[i].Event == n {
				skip = true
				break
			}
		}
		if !skip {
			e := events[i]
			return &e
		}
	}
	return nil
}

var forbiddenValue = regexp.MustCompile(`(?i)password=|passwd=|api_key=|secret=|token=|authorization:|bearer[[:space:]]|set-cookie:|BEGIN RSA|BEGIN OPENSSH|session=|cookie=`)

var forbiddenKeys = map[string]bool{
	"raw_evidence": true, "evidence_body": true, "request_body": true,
	"response_body": true, "secret": true, "token": true, "private_key": true,
}

// VerifyResult is the shell build's atlas.ledger_verify.v1 for an
// operation ledger.
type VerifyResult struct {
	EventCount    int
	HeadEventHash string
}

// VerifyOperationLedger applies the same checks as the shell build's
// atlas_ledger_verify_operation_json: valid JSON per line, required string
// fields, no forbidden keys, no forbidden markers in any string value.
func VerifyOperationLedger(path string) (*VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, state.Failf("missing ledger: %s", path)
		}
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	lineNo := 0
	head := ""
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			return nil, state.Failf("operation ledger event %d is empty", lineNo)
		}
		var rec map[string]any
		if err := jsonUnmarshal([]byte(line), &rec); err != nil {
			return nil, state.Failf("operation ledger event %d invalid JSON", lineNo)
		}
		if !validOperationEvent(rec) {
			return nil, state.Failf("operation ledger event %d invalid fields", lineNo)
		}
		canon, err := canonicalJSON(rec)
		if err != nil {
			return nil, err
		}
		sum := sha256.Sum256(append(canon, '\n'))
		head = hex.EncodeToString(sum[:])
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if lineNo == 0 {
		return nil, state.Failf("ledger is empty: %s", path)
	}
	return &VerifyResult{EventCount: lineNo, HeadEventHash: head}, nil
}

func validOperationEvent(rec map[string]any) bool {
	nonempty := func(k string) bool {
		s, ok := rec[k].(string)
		return ok && s != ""
	}
	for _, k := range []string{"ts", "event", "op", "target", "capability", "tool", "status"} {
		if !nonempty(k) {
			return false
		}
	}
	if _, ok := rec["detail"].(string); !ok {
		return false
	}
	return !containsForbidden(rec)
}

func containsForbidden(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if forbiddenKeys[k] || containsForbidden(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if containsForbidden(child) {
				return true
			}
		}
	case string:
		return forbiddenValue.MatchString(x)
	}
	return false
}

// Summary groups events by name with counts, sorted by name, matching the
// audit packet's Event Counts block.
type Summary struct {
	Event string
	Count int
}

// CountByEvent tallies events in name order.
func CountByEvent(events []Event) []Summary {
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Event]++
	}
	names := make([]string, 0, len(counts))
	for n := range counts {
		names = append(names, n)
	}
	sortStrings(names)
	out := make([]Summary, 0, len(names))
	for _, n := range names {
		out = append(out, Summary{Event: n, Count: counts[n]})
	}
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// Describe formats the event as the shell build's timeline row does.
func (e Event) Describe() string {
	detail := strings.NewReplacer("\t", " ", "\n", " ").Replace(e.Detail)
	return fmt.Sprintf("%-20s %-28s %-12s %-16s %-10s %s", e.TS, e.Event, e.Status, e.Capability, e.Tool, detail)
}

func jsonUnmarshal(data []byte, v any) error { return ndjson.Decode(data, v) }

func canonicalJSON(v any) ([]byte, error) { return ndjson.Canonical(v), nil }
