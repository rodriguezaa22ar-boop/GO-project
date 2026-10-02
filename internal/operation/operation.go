// Package operation manages target records, operation session records and
// the active-operation pointer, in the shell build's layout.
package operation

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/envfile"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ledger"
	"github.com/rodriguezaa22ar-boop/go-project/internal/ndjson"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// Target is a target registry record.
type Target struct {
	Slug        string
	Name        string
	Address     string
	ScopeStatus string
	Criticality string
	Tags        string
	Owner       string
	Notes       string
	CreatedAt   string
	File        string
}

// ValidScopeStatus mirrors labctl's target_validate_scope_status.
func ValidScopeStatus(s string) bool {
	switch s {
	case "unknown", "review", "in-scope", "out-of-scope":
		return true
	}
	return false
}

// ValidCriticality mirrors labctl's target_validate_criticality.
func ValidCriticality(s string) bool {
	switch s {
	case "unknown", "low", "medium", "high", "critical":
		return true
	}
	return false
}

// TargetFile returns the env path for a target name or slug.
func TargetFile(l *state.Layout, name string) string {
	return filepath.Join(l.TargetsDir, state.Slugify(name)+".env")
}

// LoadTarget reads a target record. A missing record returns nil, nil.
func LoadTarget(l *state.Layout, name string) (*Target, error) {
	path := TargetFile(l, name)
	rec, err := envfile.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return targetFromRecord(path, rec), nil
}

func targetFromRecord(path string, rec *envfile.Record) *Target {
	return &Target{
		Slug:        strings.TrimSuffix(filepath.Base(path), ".env"),
		Name:        rec.Get("NAME"),
		Address:     rec.Get("ADDRESS"),
		ScopeStatus: rec.Get("SCOPE_STATUS"),
		Criticality: rec.Get("CRITICALITY"),
		Tags:        rec.Get("TAGS"),
		Owner:       rec.Get("OWNER"),
		Notes:       rec.Get("NOTES"),
		CreatedAt:   rec.Get("CREATED_AT"),
		File:        path,
	}
}

// ListTargets returns every target record in file-name order.
func ListTargets(l *state.Layout) ([]*Target, error) {
	matches, err := filepath.Glob(filepath.Join(l.TargetsDir, "*.env"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	var out []*Target
	for _, path := range matches {
		rec, err := envfile.Load(path)
		if err != nil {
			return nil, err
		}
		out = append(out, targetFromRecord(path, rec))
	}
	return out, nil
}

// AddTarget writes a new target record in labctl's key order.
func AddTarget(l *state.Layout, t Target) (string, error) {
	slug := state.Slugify(t.Name)
	if slug == "" {
		return "", state.Failf("target name produced an empty slug")
	}
	path := filepath.Join(l.TargetsDir, slug+".env")
	if _, err := os.Lstat(path); err == nil {
		return "", state.Failf("target already exists: %s", slug)
	}
	if err := os.MkdirAll(l.TargetsDir, 0o700); err != nil {
		return "", err
	}
	rec := envfile.New()
	rec.Upsert("NAME", t.Name)
	rec.Upsert("ADDRESS", t.Address)
	rec.Upsert("SCOPE_STATUS", t.ScopeStatus)
	rec.Upsert("CRITICALITY", t.Criticality)
	rec.Upsert("TAGS", t.Tags)
	rec.Upsert("OWNER", t.Owner)
	rec.Upsert("NOTES", t.Notes)
	rec.Upsert("CREATED_AT", state.Timestamp())
	return slug, envfile.Save(path, rec)
}

// ResolveTarget mirrors resolve_target_input: a registered target supplies
// its metadata, anything else is used verbatim with unknown status.
func ResolveTarget(l *state.Layout, input string) (scope.TargetInfo, error) {
	t, err := LoadTarget(l, input)
	if err != nil {
		return scope.TargetInfo{}, err
	}
	if t == nil {
		return scope.TargetInfo{Target: input, Address: input, Label: input,
			ScopeStatus: "unknown", Criticality: "unknown"}, nil
	}
	name := t.Name
	if name == "" {
		name = input
	}
	addr := t.Address
	if addr == "" {
		addr = name
	}
	return scope.TargetInfo{
		Target: name, Address: addr, Label: name,
		ScopeStatus: orUnknown(t.ScopeStatus), Criticality: orUnknown(t.Criticality),
		Tags: t.Tags, Owner: t.Owner,
	}, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// Operation is a loaded session.env for an atlas operation.
type Operation struct {
	Name          string
	Slug          string
	Target        string
	TargetAddress string
	TargetLabel   string
	ScopeStatus   string
	Criticality   string
	Tags          string
	Owner         string
	Status        string
	CreatedAt     string
	ClosedAt      string
	LastResumedAt string
	Notes         string
	Dir           string
	File          string
	Layout        *state.Layout
}

// TargetInfo returns the operation's target fields as snapshot fallbacks.
func (o *Operation) TargetInfo() scope.TargetInfo {
	return scope.TargetInfo{Target: o.Target, Address: o.TargetAddress, Label: o.TargetLabel,
		ScopeStatus: o.ScopeStatus, Criticality: o.Criticality, Tags: o.Tags, Owner: o.Owner}
}

// Snapshot loads the operation's scope snapshot.
func (o *Operation) Snapshot() (*scope.Snapshot, error) {
	return scope.LoadSnapshot(o.Dir, o.TargetInfo())
}

// LedgerFile returns the operation ledger path.
func (o *Operation) LedgerFile() string { return ledger.File(o.Dir) }

// Load reads an operation by name or slug, as load_atlas_operation does.
func Load(l *state.Layout, name string) (*Operation, error) {
	slug := state.Slugify(name)
	dir := l.OpDir(slug)
	path := filepath.Join(dir, "session.env")
	rec, err := envfile.Load(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, state.Failf("unknown operation: %s", slug)
		}
		return nil, err
	}
	if rec.Get("SOURCE_TOOL") != state.ToolName {
		return nil, state.Failf("not an atlas operation: %s", slug)
	}
	if rec.Get("MODE") != "operation" {
		return nil, state.Failf("invalid atlas operation record: %s", slug)
	}
	o := &Operation{
		Name:          rec.Get("NAME"),
		Slug:          rec.Get("SLUG"),
		Target:        rec.Get("TARGET"),
		TargetAddress: rec.Get("TARGET_ADDRESS"),
		TargetLabel:   rec.Get("TARGET_LABEL"),
		ScopeStatus:   orUnknown(rec.Get("TARGET_SCOPE_STATUS")),
		Criticality:   orUnknown(rec.Get("TARGET_CRITICALITY")),
		Tags:          rec.Get("TARGET_TAGS"),
		Owner:         rec.Get("TARGET_OWNER"),
		Status:        rec.Get("STATUS"),
		CreatedAt:     rec.Get("CREATED_AT"),
		ClosedAt:      rec.Get("CLOSED_AT"),
		LastResumedAt: rec.Get("LAST_RESUMED_AT"),
		Notes:         rec.Get("NOTES"),
		Dir:           dir,
		File:          path,
		Layout:        l,
	}
	if o.TargetAddress == "" {
		o.TargetAddress = o.Target
	}
	if o.TargetLabel == "" {
		o.TargetLabel = o.Target
	}
	return o, nil
}

// ActiveSlug returns the active operation slug, or "" when none is set or
// the recorded operation no longer exists.
func ActiveSlug(l *state.Layout) string {
	rec, err := envfile.Load(l.ActiveFile)
	if err != nil {
		return ""
	}
	slug := rec.Get("ACTIVE_OPERATION")
	if slug == "" {
		return ""
	}
	if !state.FileExists(filepath.Join(l.OpDir(slug), "session.env")) {
		return ""
	}
	return slug
}

// LoadActive loads the active operation or fails like the shell build.
func LoadActive(l *state.Layout) (*Operation, error) {
	slug := ActiveSlug(l)
	if slug == "" {
		return nil, state.Failf("no active operation; use 'atlas op start' or 'atlas op resume'")
	}
	return Load(l, slug)
}

// LoadNamedOrActive loads name when given, else the active operation.
func LoadNamedOrActive(l *state.Layout, name string) (*Operation, error) {
	if name != "" {
		return Load(l, name)
	}
	return LoadActive(l)
}

// SetActive records the active operation pointer.
func SetActive(l *state.Layout, slug string) error {
	if err := os.MkdirAll(l.AtlasState, 0o700); err != nil {
		return err
	}
	rec := envfile.New()
	rec.Upsert("ACTIVE_OPERATION", slug)
	rec.Upsert("SET_AT", state.Timestamp())
	return envfile.Save(l.ActiveFile, rec)
}

// ClearActive removes the pointer.
func ClearActive(l *state.Layout) error {
	err := os.Remove(l.ActiveFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// IsActive reports whether slug is the active operation.
func IsActive(l *state.Layout, slug string) bool {
	return ActiveSlug(l) == slug
}

// List returns every atlas operation in slug order.
func List(l *state.Layout) ([]*Operation, error) {
	matches, err := filepath.Glob(filepath.Join(l.SessionsDir, "*", "session.env"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	var out []*Operation
	for _, path := range matches {
		slug := filepath.Base(filepath.Dir(path))
		o, err := Load(l, slug)
		if err != nil {
			continue // not an atlas operation
		}
		out = append(out, o)
	}
	return out, nil
}

var opSubdirs = []string{"loot", "pcaps", "notes", "logs", "tmp", "recon-runs", "action-sessions", "evidence", "findings", "validation-plans"}

// StartParams holds the inputs to Start.
type StartParams struct {
	Name    string
	Target  string
	Profile string
	Notes   string
}

// Start mirrors cmd_op_start: resolve the target, refuse out-of-scope,
// load the profile, create the session directory, write session.env and the
// scope snapshot, append op.started, record history and set active.
func Start(l *state.Layout, p StartParams) (*Operation, *scope.Profile, error) {
	target, err := ResolveTarget(l, p.Target)
	if err != nil {
		return nil, nil, err
	}
	if target.ScopeStatus == "out-of-scope" {
		return nil, nil, state.Failf("target '%s' is marked out-of-scope in target registry", target.Target)
	}
	profile, err := scope.LoadProfile(l.ProfilesDir, p.Profile)
	if err != nil {
		return nil, nil, err
	}
	slug := state.Slugify(p.Name)
	if slug == "" {
		return nil, nil, state.Failf("operation name produced an empty slug")
	}
	dir := l.OpDir(slug)
	if _, err := os.Lstat(dir); err == nil {
		return nil, nil, state.Failf("operation already exists: %s", slug)
	}
	for _, sub := range opSubdirs {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, nil, err
		}
	}
	rec := envfile.New()
	rec.Upsert("NAME", p.Name)
	rec.Upsert("SLUG", slug)
	rec.Upsert("TARGET", target.Target)
	rec.Upsert("TARGET_ADDRESS", target.Address)
	rec.Upsert("TARGET_LABEL", target.Label)
	rec.Upsert("TARGET_SCOPE_STATUS", target.ScopeStatus)
	rec.Upsert("TARGET_CRITICALITY", target.Criticality)
	rec.Upsert("TARGET_TAGS", target.Tags)
	rec.Upsert("TARGET_OWNER", target.Owner)
	rec.Upsert("STATUS", "active")
	rec.Upsert("CREATED_AT", state.Timestamp())
	rec.Upsert("LAST_RESUMED_AT", state.Timestamp())
	rec.Upsert("NOTES", p.Notes)
	rec.Upsert("SOURCE_TOOL", state.ToolName)
	rec.Upsert("MODE", "operation")
	file := filepath.Join(dir, "session.env")
	if err := envfile.Save(file, rec); err != nil {
		return nil, nil, err
	}
	if err := scope.WriteSnapshot(dir, target, profile); err != nil {
		return nil, nil, err
	}
	if err := ledger.Append(dir, ledger.Event{Event: "op.started", Op: slug, Target: target.Target,
		Capability: scope.ReadOnly, Tool: state.ToolName, Status: "ok",
		Detail: "profile=" + profile.Name + " notes=" + p.Notes}); err != nil {
		return nil, nil, err
	}
	if err := state.RecordHistory(dir, "start", target.Target); err != nil {
		return nil, nil, err
	}
	if err := SetActive(l, slug); err != nil {
		return nil, nil, err
	}
	o, err := Load(l, slug)
	return o, profile, err
}

// Resume mirrors cmd_op_resume.
func Resume(l *state.Layout, name string) (*Operation, error) {
	o, err := Load(l, name)
	if err != nil {
		return nil, err
	}
	for _, kv := range [][2]string{{"STATUS", "active"}, {"LAST_RESUMED_AT", state.Timestamp()}, {"CLOSED_AT", ""}} {
		if err := envfile.UpsertFile(o.File, kv[0], kv[1]); err != nil {
			return nil, err
		}
	}
	if err := SetActive(l, o.Slug); err != nil {
		return nil, err
	}
	if err := o.AppendLedger("op.resumed", scope.ReadOnly, state.ToolName, "ok", o.Target); err != nil {
		return nil, err
	}
	if err := state.RecordHistory(o.Dir, "resume", o.Target); err != nil {
		return nil, err
	}
	return Load(l, o.Slug)
}

// AppendLedger mirrors atlas_ledger_append_current.
func (o *Operation) AppendLedger(event, capability, tool, status, detail string) error {
	return ledger.Append(o.Dir, ledger.Event{Event: event, Op: o.Slug, Target: o.Target,
		Capability: capability, Tool: tool, Status: status, Detail: detail})
}

// HasApproval mirrors atlas_approval_has_current against approvals.ndjson.
func (o *Operation) HasApproval(capability, target string) bool {
	recs, err := ndjson.ReadFile(filepath.Join(o.Dir, "approvals.ndjson"))
	if err != nil {
		return false
	}
	for _, r := range recs {
		if r.String("capability") == capability && r.String("target") == target && r.String("status") == "approved" {
			return true
		}
	}
	return false
}

// Preflight runs the scope check, records the decision in the ledger and
// returns the operator-facing error on refusal.
func (o *Operation) Preflight(capability, tool, target, reason string) error {
	snap, err := o.Snapshot()
	if err != nil {
		return err
	}
	d := snap.Preflight(capability, target, reason, func(c string) bool {
		return o.HasApproval(c, snap.Target)
	})
	status := "allowed"
	if !d.Allowed {
		status = "denied"
	}
	if err := o.AppendLedger("scope.preflight", capability, tool, status, d.Detail); err != nil {
		return err
	}
	return d.Err
}

// FormatTarget mirrors format_operation_target.
func (o *Operation) FormatTarget() string {
	rendered := o.Target
	if o.TargetLabel != o.Target {
		rendered = o.Target + " (" + o.TargetLabel + ")"
	}
	if o.TargetAddress != "" && o.TargetAddress != o.Target {
		return rendered + " -> " + o.TargetAddress
	}
	return rendered
}

// MatchesIdentifier mirrors operation_target_matches_identifier.
func (o *Operation) MatchesIdentifier(target string) bool {
	return target == o.Target || (o.TargetAddress != "" && target == o.TargetAddress) || (o.TargetLabel != "" && target == o.TargetLabel)
}

// Close mirrors the state mutation in cmd_op_close: set STATUS/CLOSED_AT,
// append readiness and closed events, record history, clear active.
func (o *Operation) Close(readinessStatus, detail string) error {
	if err := envfile.UpsertFile(o.File, "STATUS", "closed"); err != nil {
		return err
	}
	if err := envfile.UpsertFile(o.File, "CLOSED_AT", state.Timestamp()); err != nil {
		return err
	}
	if err := o.AppendLedger("op.close.readiness", scope.ReadOnly, state.ToolName, readinessStatus, detail); err != nil {
		return err
	}
	if err := o.AppendLedger("op.closed", scope.ReadOnly, state.ToolName, "ok", o.Target+" "+detail); err != nil {
		return err
	}
	if err := state.RecordHistory(o.Dir, "close", o.Target); err != nil {
		return err
	}
	o.Status = "closed"
	if IsActive(o.Layout, o.Slug) {
		return ClearActive(o.Layout)
	}
	return nil
}
