// Package packet writes the metadata-only retention packets (handoff,
// closeout, audit, archive) in the shell build's Markdown format and order,
// and verifies them. Packets hold only paths, hashes and counts.
package packet

import (
	"path/filepath"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/readiness"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// shaForFile returns the file's sha256, or "" when the path is empty or
// missing, matching atlas_closeout_sha_for_file.
func shaForFile(path string) string {
	if path == "" || !state.FileExists(path) {
		return ""
	}
	sum, err := state.SHA256File(path)
	if err != nil {
		return ""
	}
	return sum
}

// ledgerEventCount returns the number of events, like jq -s length.
func ledgerEventCount(path string) int {
	n, err := ledger.Count(path)
	if err != nil {
		return 0
	}
	return n
}

// reportFields returns the latest report's generation time, path and sha,
// matching atlas_handoff_latest_report_fields.
func reportFields(st *readiness.State) (at, path, sha string) {
	if !st.Report.Present() {
		return "", "", ""
	}
	path = st.Report.Detail
	at = st.Report.At
	sha = shaForFile(path)
	return
}

// handoffFields returns the latest handoff's time, path and sha.
func handoffFields(st *readiness.State) (at, path, sha string) {
	if !st.Handoff.Present() {
		return "", "", ""
	}
	path = st.Handoff.Detail
	at = st.Handoff.At
	sha = shaForFile(path)
	return
}

func closeoutFields(st *readiness.State) (at, path, sha string) {
	if !st.Closeout.Present() {
		return "", "", ""
	}
	path = st.Closeout.Detail
	at = st.Closeout.At
	sha = shaForFile(path)
	return
}

// hashLine renders atlas_closeout_print_hash_line: a bullet with the path
// and its sha, or "- Label: none" when the file is absent.
func hashLine(label, path string) string {
	if path != "" && state.FileExists(path) {
		sha := shaForFile(path)
		line := "- " + label + ": `" + path + "`"
		if sha != "" {
			line += " sha256=" + sha
		}
		return line
	}
	return "- " + label + ": none"
}

func packetDir(op *operation.Operation, name string) string {
	return filepath.Join(op.Dir, name)
}

func writeMarkdown(path, body string) error {
	return state.WriteFileMode(path, []byte(body), 0o600)
}

// anchorLine finds the first "- <label>: " line in a Markdown packet.
func anchorLine(text, label string) string {
	prefix := "- " + label + ": "
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, prefix) {
			return l
		}
	}
	return ""
}

// anchorPath extracts the backtick-wrapped path from an anchor line.
func anchorPath(line string) string {
	i := strings.IndexByte(line, '`')
	if i < 0 {
		return ""
	}
	rest := line[i+1:]
	j := strings.IndexByte(rest, '`')
	if j < 0 {
		return ""
	}
	return rest[:j]
}

// anchorToken extracts key=value tokens that follow the path.
func anchorToken(line, key string) string {
	for _, tok := range strings.Fields(line) {
		if strings.HasPrefix(tok, key+"=") {
			return strings.TrimPrefix(tok, key+"=")
		}
	}
	return ""
}

// field reads a "Key: value" header line value.
func field(text, key string) string {
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, key+": ") {
			return strings.TrimPrefix(l, key+": ")
		}
	}
	return ""
}

// bulletValue reads a "- Key: value" bullet value.
func bulletValue(text, label string) string {
	prefix := "- " + label + ": "
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, prefix) {
			return strings.TrimPrefix(l, prefix)
		}
	}
	return ""
}

// LatestInLedger returns the path recorded by the latest ledger event of
// the kind that matches the packet subdir (handoff, closeout, audit,
// archive), or "" when none exists.
func LatestInLedger(op *operation.Operation, subdir string) (string, error) {
	eventName := map[string]string{
		"handoff":  "handoff.generated",
		"closeout": "closeout.manifest.generated",
		"audit":    "audit.packet.generated",
		"archive":  "archive.packet.generated",
	}[subdir]
	if eventName == "" {
		return "", state.Failf("unknown packet kind: %s", subdir)
	}
	events, err := ledger.Read(op.Dir)
	if err != nil {
		return "", err
	}
	if m := ledger.Latest(events, eventName); m != nil {
		return m.Detail, nil
	}
	return "", nil
}
