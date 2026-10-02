// Package receipt verifies, replays and creates atlas.receipt.v1 proof
// records. Hashes are computed over jq -cS canonical JSON plus a trailing
// newline, matching the shell build's receipt.sh.
package receipt

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ndjson"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

// canonicalHash hashes jq -cS output of v plus a trailing newline.
func canonicalHash(v any) string {
	sum := sha256.Sum256(append(ndjson.Canonical(v), '\n'))
	return hex.EncodeToString(sum[:])
}

func eventHash(m map[string]any) string {
	c := cloneWithout(m, "event_hash", "receipt_hash")
	return canonicalHash(c)
}

func receiptHash(m map[string]any) string {
	c := cloneWithout(m, "receipt_hash")
	return canonicalHash(c)
}

func cloneWithout(m map[string]any, drop ...string) map[string]any {
	skip := map[string]bool{}
	for _, d := range drop {
		skip[d] = true
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		if !skip[k] {
			out[k] = v
		}
	}
	return out
}

// VerifyResult is atlas.receipt_verify.v1.
type VerifyResult struct {
	ReceiptID    string
	Action       string
	EventHash    string
	PrevHash     string // "null" when absent
	ReceiptHash  string
	EvidenceRefs int
	ArtifactRefs int
	ApprovalRefs int
}

var receiptKeys = []string{
	"schema_version", "receipt_id", "timestamp", "metadata_only", "raw_artifacts_embedded",
	"action", "actor", "subject", "evidence_refs", "artifact_refs", "approval_refs",
	"prev_hash", "event_hash", "receipt_hash", "known_limitations", "verifier",
}

// Validate reproduces atlas_receipt_validate_json.
func Validate(data []byte) (*VerifyResult, error) {
	var m map[string]any
	if err := ndjson.Decode(data, &m); err != nil {
		return nil, state.Failf("invalid receipt JSON")
	}
	if fb := forbiddenPaths(m); len(fb) > 0 {
		return nil, state.Failf("receipt contains forbidden raw-content marker: %s", strings.Join(fb, ","))
	}
	if err := validateFields(m); err != nil {
		return nil, err
	}
	if s, _ := m["event_hash"].(string); s != eventHash(m) {
		return nil, state.Failf("receipt event_hash mismatch")
	}
	if s, _ := m["receipt_hash"].(string); s != receiptHash(m) {
		return nil, state.Failf("receipt hash mismatch")
	}
	res := &VerifyResult{
		ReceiptID:    str(m, "receipt_id"),
		Action:       str(m, "action"),
		EventHash:    str(m, "event_hash"),
		ReceiptHash:  str(m, "receipt_hash"),
		PrevHash:     "null",
		EvidenceRefs: arrLen(m, "evidence_refs"),
		ArtifactRefs: arrLen(m, "artifact_refs"),
		ApprovalRefs: arrLen(m, "approval_refs"),
	}
	if p, ok := m["prev_hash"].(string); ok {
		res.PrevHash = p
	}
	return res, nil
}

func validateFields(m map[string]any) error {
	fail := state.Failf("invalid receipt fields")
	if !exactKeys(m, receiptKeys) {
		return fail
	}
	if str(m, "schema_version") != "atlas.receipt.v1" {
		return fail
	}
	if !nonempty(m, "receipt_id") || !nonempty(m, "timestamp") || !nonempty(m, "action") || !nonempty(m, "actor") {
		return fail
	}
	if b, ok := m["metadata_only"].(bool); !ok || !b {
		return fail
	}
	if b, ok := m["raw_artifacts_embedded"].(bool); !ok || b {
		return fail
	}
	subj, ok := m["subject"].(map[string]any)
	if !ok || !exactKeys(subj, []string{"type", "ref"}) || !nonempty(subj, "type") || !nonempty(subj, "ref") {
		return fail
	}
	if !stringArray(m, "evidence_refs") || !stringArray(m, "approval_refs") {
		return fail
	}
	arts, ok := m["artifact_refs"].([]any)
	if !ok {
		return fail
	}
	for _, a := range arts {
		am, ok := a.(map[string]any)
		if !ok || !exactKeys(am, []string{"path", "sha256"}) || !nonempty(am, "path") || !hex64.MatchString(str(am, "sha256")) {
			return fail
		}
	}
	if _, has := m["prev_hash"]; !has {
		return fail
	}
	if m["prev_hash"] != nil {
		if p, ok := m["prev_hash"].(string); !ok || !hex64.MatchString(p) {
			return fail
		}
	}
	if !hex64.MatchString(str(m, "event_hash")) || !hex64.MatchString(str(m, "receipt_hash")) {
		return fail
	}
	lims, ok := m["known_limitations"].([]any)
	if !ok || len(lims) == 0 {
		return fail
	}
	for _, l := range lims {
		if s, ok := l.(string); !ok || s == "" {
			return fail
		}
	}
	ver, ok := m["verifier"].(map[string]any)
	if !ok || !exactKeys(ver, []string{"name", "schema"}) {
		return fail
	}
	if str(ver, "name") != "atlas receipt verify" || str(ver, "schema") != "schemas/atlas.receipt.v1.schema.json" {
		return fail
	}
	return nil
}

var (
	badKeyExact = regexp.MustCompile(`(?i)^(raw_artifact|raw_artifacts|raw_body|raw_request|raw_response|raw_prompt|raw_model_output|system_prompt|tool_output_body|tool_call_raw|raw_logs|raw_job_output|raw_workflow_output|artifact_body|artifact_content|raw_payload|payload|request_body|response_body|secret|token|password|passwd|api_key|authorization|cookie|session|private_key|credential|webhook_secret|workflow_secret|environment_secret|github_token)$`)
	badKeyPart  = regexp.MustCompile(`(?i)(^|[_-])(secret|token|password|passwd|api_key|authorization|cookie|session|private_key|credential)([_-]|$)`)
	badValue    = regexp.MustCompile(`(?i)password=|passwd=|api_key=|secret=|token=|github_token=|webhook_secret=|workflow_secret=|environment_secret=|authorization:|bearer[ \t]|set-cookie:|BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY|session=|cookie=|gh[pousr]_[A-Za-z0-9_]{20,}`)
)

// forbiddenPaths reproduces atlas_receipt_forbidden_content_paths: any key
// matching the bad-key patterns, or any string scalar matching bad-value.
func forbiddenPaths(v any) []string {
	set := map[string]bool{}
	var walk func(path []string, node any)
	walk = func(path []string, node any) {
		if len(path) > 0 {
			last := path[len(path)-1]
			if badKeyExact.MatchString(last) || badKeyPart.MatchString(last) {
				set[strings.Join(path, ".")] = true
			}
		}
		switch x := node.(type) {
		case map[string]any:
			keys := make([]string, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(append(append([]string{}, path...), k), x[k])
			}
		case []any:
			for i, e := range x {
				walk(append(append([]string{}, path...), itoa(i)), e)
			}
		case string:
			if badValue.MatchString(x) {
				set[strings.Join(path, ".")] = true
			}
		}
	}
	walk(nil, v)
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// VerifyFile validates a receipt file ("-" reads stdin).
func VerifyFile(path string) (*VerifyResult, []byte, error) {
	data, err := readInput(path)
	if err != nil {
		return nil, nil, err
	}
	res, err := Validate(data)
	return res, data, err
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return os.ReadFile("/dev/stdin")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, state.Failf("missing receipt: %s", path)
		}
		return nil, err
	}
	return data, nil
}

// ChainRow is one row of a replay result.
type ChainRow struct {
	Index         int
	Path          string
	ReceiptID     string
	Action        string
	PrevHash      string // "" for genesis
	EventHash     string
	ReceiptHash   string
	LinkageStatus string
}

// ReplayResult is atlas.receipt_replay.v1 (the fields Lite surfaces).
type ReplayResult struct {
	ReceiptCount         int
	FirstEventHash       string
	ChainHeadEventHash   string
	ChainHeadReceiptHash string
	Chain                []ChainRow
}

// Replay reproduces atlas_receipt_replay_json's linkage checks.
func Replay(paths []string) (*ReplayResult, error) {
	if len(paths) == 0 {
		return nil, state.Failf("receipt replay requires at least one receipt file")
	}
	res := &ReplayResult{}
	expectedPrev := ""
	for i, p := range paths {
		if p == "-" {
			return nil, state.Failf("receipt replay requires receipt files, not stdin")
		}
		data, err := readInput(p)
		if err != nil {
			return nil, err
		}
		v, err := Validate(data)
		if err != nil {
			return nil, err
		}
		linkage := "ok"
		if i == 0 {
			if v.PrevHash != "null" {
				return nil, state.Failf("receipt replay receipt 1 prev_hash must be null: %s", p)
			}
			linkage = "genesis"
			res.FirstEventHash = v.EventHash
		} else if v.PrevHash != expectedPrev {
			return nil, state.Failf("receipt replay receipt %d prev_hash mismatch: expected %s got %s", i+1, expectedPrev, v.PrevHash)
		}
		prev := v.PrevHash
		if prev == "null" {
			prev = ""
		}
		res.Chain = append(res.Chain, ChainRow{
			Index: i + 1, Path: p, ReceiptID: v.ReceiptID, Action: v.Action,
			PrevHash: prev, EventHash: v.EventHash, ReceiptHash: v.ReceiptHash, LinkageStatus: linkage,
		})
		expectedPrev = v.EventHash
		res.ChainHeadEventHash = v.EventHash
		res.ChainHeadReceiptHash = v.ReceiptHash
	}
	res.ReceiptCount = len(paths)
	return res, nil
}

// --- helpers ---

func str(m map[string]any, k string) string {
	s, _ := m[k].(string)
	return s
}

func nonempty(m map[string]any, k string) bool {
	s, ok := m[k].(string)
	return ok && s != ""
}

func arrLen(m map[string]any, k string) int {
	a, _ := m[k].([]any)
	return len(a)
}

func stringArray(m map[string]any, k string) bool {
	a, ok := m[k].([]any)
	if !ok {
		return false
	}
	for _, e := range a {
		if s, ok := e.(string); !ok || s == "" {
			return false
		}
	}
	return true
}

func exactKeys(m map[string]any, allowed []string) bool {
	set := map[string]bool{}
	for _, k := range allowed {
		set[k] = true
	}
	for k := range m {
		if !set[k] {
			return false
		}
	}
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}

// CreateParams holds the inputs to Create.
type CreateParams struct {
	ReceiptID    string
	Timestamp    string
	Action       string
	Actor        string
	SubjectType  string
	SubjectRef   string
	PrevHash     string
	EvidenceRefs []string
	ArtifactRefs []string
	ApprovalRefs []string
	Limitations  []string
}

var defaultLimitations = []string{
	"Metadata-only proof record; raw artifacts and sensitive contents are not embedded.",
	"Does not prove external artifact availability, human intent, legal compliance, or artifact correctness.",
}

// Create builds a receipt, computes its hashes and returns the canonical
// JSON (sorted keys) plus a trailing newline. The result validates under
// both this build and the shell build.
func Create(p CreateParams) ([]byte, error) {
	if p.Action == "" {
		return nil, state.Failf("receipt create requires --action")
	}
	if p.Actor == "" {
		return nil, state.Failf("receipt create requires --actor")
	}
	if p.SubjectType == "" {
		return nil, state.Failf("receipt create requires --subject-type")
	}
	if p.SubjectRef == "" {
		return nil, state.Failf("receipt create requires --subject")
	}
	var prev any
	if p.PrevHash != "" {
		if !hex64.MatchString(p.PrevHash) {
			return nil, state.Failf("receipt create requires --prev-hash as 64 lowercase hex characters")
		}
		prev = p.PrevHash
	}
	if p.ReceiptID == "" {
		p.ReceiptID = "receipt_" + state.Now().Format("20060102T150405Z") + "_" + state.Slugify(p.Action)
	}
	if p.Timestamp == "" {
		p.Timestamp = state.Timestamp()
	}
	limits := p.Limitations
	if len(limits) == 0 {
		limits = defaultLimitations
	}
	arts := make([]any, 0, len(p.ArtifactRefs))
	for _, a := range p.ArtifactRefs {
		eq := strings.LastIndexByte(a, '=')
		if eq < 0 {
			return nil, state.Failf("receipt create requires --artifact-ref values formatted as path=sha256")
		}
		path, sha := a[:eq], a[eq+1:]
		if path == "" || !hex64.MatchString(sha) {
			return nil, state.Failf("receipt create requires --artifact-ref values formatted as path=sha256")
		}
		arts = append(arts, map[string]any{"path": path, "sha256": sha})
	}
	m := map[string]any{
		"schema_version":         "atlas.receipt.v1",
		"receipt_id":             p.ReceiptID,
		"timestamp":              p.Timestamp,
		"metadata_only":          true,
		"raw_artifacts_embedded": false,
		"action":                 p.Action,
		"actor":                  p.Actor,
		"subject":                map[string]any{"type": p.SubjectType, "ref": p.SubjectRef},
		"evidence_refs":          toAnySlice(p.EvidenceRefs),
		"artifact_refs":          arts,
		"approval_refs":          toAnySlice(p.ApprovalRefs),
		"prev_hash":              prev,
		"known_limitations":      toAnySlice(limits),
		"verifier":               map[string]any{"name": "atlas receipt verify", "schema": "schemas/atlas.receipt.v1.schema.json"},
	}
	m["event_hash"] = eventHash(m)
	m["receipt_hash"] = receiptHash(m)
	if _, err := Validate(append(ndjson.Canonical(m), '\n')); err != nil {
		return nil, err
	}
	return append(ndjson.Canonical(m), '\n'), nil
}

func toAnySlice(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}
