// Package scope owns profiles, capability tiers, the per-operation scope
// snapshot and the preflight check that every target-touching command runs
// before it does anything.
package scope

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/envfile"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// Capability names and tiers, as in the shell build's scope.sh.
const (
	ReadOnly            = "read-only"
	PassiveRecon        = "passive-recon"
	ActiveRecon         = "active-recon"
	SafeValidation      = "safe-validation"
	IntrusiveValidation = "intrusive-validation"
	Destructive         = "destructive"
)

// Tier returns the numeric tier for a capability, or -1 when unknown.
func Tier(capability string) int {
	switch capability {
	case ReadOnly:
		return 0
	case PassiveRecon:
		return 1
	case ActiveRecon:
		return 2
	case SafeValidation:
		return 3
	case IntrusiveValidation:
		return 4
	case Destructive:
		return 5
	}
	return -1
}

// TierString renders the tier as the shell build prints it ("?" for unknown).
func TierString(capability string) string {
	t := Tier(capability)
	if t < 0 {
		return "?"
	}
	return fmt.Sprint(t)
}

// RequiresApproval mirrors atlas_approval_requires_gate.
func RequiresApproval(capability string) bool {
	return capability == SafeValidation || capability == IntrusiveValidation
}

const (
	DefaultAllowed = "read-only passive-recon active-recon safe-validation"
	DefaultBlocked = "destructive persistence credential-spraying denial-of-service out-of-scope-network"
	DefaultSummary = "default bounded Atlas operation profile"
	DefaultText    = "Bounded authorized reconnaissance and defensive posture review for the named target."
)

var defaultAllowedActions = []string{
	"target-first recon against configured scope",
	"service validation and non-invasive fingerprint refresh",
	"HTTP/HTTPS probing of observed web surfaces",
	"HTTP posture review for headers, redirects, metadata routes, and common login/admin routes",
	"bounded API status and CORS preflight posture checks",
	"shared-intel summarization, story views, and report generation",
}

var defaultOutOfScope = []string{
	"exploitation, payload delivery, or persistence",
	"brute forcing, password guessing, credential stuffing, or session hijacking",
	"destructive testing, denial of service, fuzzing, or high-volume crawling",
	"access to third-party systems beyond the configured target",
	"data extraction beyond minimal service, route, header, API status, CORS header, and posture evidence",
}

// Profile is a loaded scope profile with defaults applied.
type Profile struct {
	Name                 string
	Summary              string
	ScopeText            string
	AllowedCapabilities  string
	BlockedCapabilities  string
	AllowedActions       string
	OutOfScopeActions    string
	RecommendedWorkflows string
	ValidationLanes      string
}

// LoadProfile mirrors atlas_scope_load_profile. "default" needs no file.
func LoadProfile(profilesDir, name string) (*Profile, error) {
	if name == "" {
		name = "default"
	}
	p := &Profile{Name: name}
	rec := envfile.New()
	if name != "default" {
		slug := state.Slugify(name)
		if slug == "" {
			return nil, state.Failf("profile name produced an empty slug")
		}
		path := filepath.Join(profilesDir, slug+".env")
		loaded, err := envfile.Load(path)
		if err != nil {
			if os.IsNotExist(err) {
				return nil, state.Failf("unknown Atlas profile: %s", name)
			}
			return nil, err
		}
		rec = loaded
	}
	pick := func(key, fallback string) string {
		if v := rec.Get(key); v != "" {
			return v
		}
		return fallback
	}
	p.Name = pick("PROFILE_NAME", name)
	p.Summary = pick("PROFILE_SUMMARY", DefaultSummary)
	p.ScopeText = pick("SCOPE_TEXT", DefaultText)
	p.AllowedCapabilities = pick("ALLOWED_CAPABILITIES", DefaultAllowed)
	p.BlockedCapabilities = pick("BLOCKED_CAPABILITIES", DefaultBlocked)
	p.AllowedActions = rec.Get("ALLOWED_ACTIONS")
	p.OutOfScopeActions = rec.Get("OUT_OF_SCOPE_ACTIONS")
	p.RecommendedWorkflows = rec.Get("RECOMMENDED_WORKFLOWS")
	p.ValidationLanes = rec.Get("VALIDATION_LANES")
	return p, nil
}

// ListProfileFiles returns the profile env files in name order.
func ListProfileFiles(profilesDir string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(profilesDir, "*.env"))
	if err != nil {
		return nil, err
	}
	return matches, nil
}

// PipeLines splits a |-separated list, dropping empty items.
func PipeLines(value string) []string {
	if value == "" {
		return nil
	}
	var out []string
	for _, item := range strings.Split(value, "|") {
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// Words splits a whitespace-separated capability list.
func Words(list string) []string {
	return strings.Fields(list)
}

// Contains mirrors atlas_scope_word_contains.
func Contains(list, wanted string) bool {
	for _, w := range Words(list) {
		if w == wanted {
			return true
		}
	}
	return false
}

// TargetInfo is the resolved target metadata written into a snapshot.
type TargetInfo struct {
	Target      string
	Address     string
	Label       string
	ScopeStatus string
	Criticality string
	Tags        string
	Owner       string
}

// SnapshotFile returns the snapshot path for an operation directory.
func SnapshotFile(opDir string) string {
	return filepath.Join(opDir, "scope.snapshot.env")
}

// WriteSnapshot mirrors atlas_scope_write_snapshot, including key order.
func WriteSnapshot(opDir string, t TargetInfo, p *Profile) error {
	rec := envfile.New()
	rec.Upsert("SCOPE_PROFILE", p.Name)
	rec.Upsert("SCOPE_PROFILE_SUMMARY", p.Summary)
	rec.Upsert("SCOPE_TARGET", t.Target)
	rec.Upsert("SCOPE_TARGET_ADDRESS", t.Address)
	rec.Upsert("SCOPE_TARGET_LABEL", t.Label)
	rec.Upsert("TARGET_SCOPE_STATUS", t.ScopeStatus)
	rec.Upsert("TARGET_CRITICALITY", t.Criticality)
	rec.Upsert("TARGET_TAGS", t.Tags)
	rec.Upsert("TARGET_OWNER", t.Owner)
	rec.Upsert("SCOPE_TEXT", p.ScopeText)
	rec.Upsert("ALLOWED_CAPABILITIES", p.AllowedCapabilities)
	rec.Upsert("BLOCKED_CAPABILITIES", p.BlockedCapabilities)
	rec.Upsert("ALLOWED_ACTIONS", p.AllowedActions)
	rec.Upsert("OUT_OF_SCOPE_ACTIONS", p.OutOfScopeActions)
	rec.Upsert("RECOMMENDED_WORKFLOWS", p.RecommendedWorkflows)
	rec.Upsert("VALIDATION_LANES", p.ValidationLanes)
	rec.Upsert("SNAPSHOT_AT", state.Timestamp())
	return envfile.Save(SnapshotFile(opDir), rec)
}

// Snapshot is a loaded scope snapshot with the shell build's fallbacks.
type Snapshot struct {
	Profile              string
	ProfileSummary       string
	Target               string
	TargetAddress        string
	TargetLabel          string
	TargetScopeStatus    string
	TargetCriticality    string
	TargetTags           string
	TargetOwner          string
	Text                 string
	Allowed              string
	Blocked              string
	AllowedActions       string
	OutOfScopeActions    string
	RecommendedWorkflows string
	ValidationLanes      string
}

// LoadSnapshot mirrors atlas_scope_load_snapshot. fallback supplies the
// operation's own target fields for a snapshot-less operation.
func LoadSnapshot(opDir string, fallback TargetInfo) (*Snapshot, error) {
	rec := envfile.New()
	if loaded, err := envfile.Load(SnapshotFile(opDir)); err == nil {
		rec = loaded
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	pick := func(key, fb string) string {
		if v := rec.Get(key); v != "" {
			return v
		}
		return fb
	}
	s := &Snapshot{
		Profile:              pick("SCOPE_PROFILE", "default"),
		ProfileSummary:       pick("SCOPE_PROFILE_SUMMARY", DefaultSummary),
		Target:               pick("SCOPE_TARGET", fallback.Target),
		TargetAddress:        pick("SCOPE_TARGET_ADDRESS", fallback.Address),
		TargetLabel:          pick("SCOPE_TARGET_LABEL", fallback.Label),
		TargetScopeStatus:    pick("TARGET_SCOPE_STATUS", orUnknown(fallback.ScopeStatus)),
		TargetCriticality:    pick("TARGET_CRITICALITY", orUnknown(fallback.Criticality)),
		TargetTags:           pick("TARGET_TAGS", fallback.Tags),
		TargetOwner:          pick("TARGET_OWNER", fallback.Owner),
		Text:                 pick("SCOPE_TEXT", DefaultText),
		Allowed:              pick("ALLOWED_CAPABILITIES", DefaultAllowed),
		Blocked:              pick("BLOCKED_CAPABILITIES", DefaultBlocked),
		AllowedActions:       rec.Get("ALLOWED_ACTIONS"),
		OutOfScopeActions:    rec.Get("OUT_OF_SCOPE_ACTIONS"),
		RecommendedWorkflows: rec.Get("RECOMMENDED_WORKFLOWS"),
		ValidationLanes:      rec.Get("VALIDATION_LANES"),
	}
	return s, nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// TargetMatches mirrors atlas_scope_target_matches.
func (s *Snapshot) TargetMatches(target string) bool {
	if target == s.Target {
		return true
	}
	if s.TargetAddress != "" && target == s.TargetAddress {
		return true
	}
	if s.TargetLabel != "" && target == s.TargetLabel {
		return true
	}
	return false
}

// AllowedActionLines returns the profile's allowed actions or the defaults.
func (s *Snapshot) AllowedActionLines() []string {
	if lines := PipeLines(s.AllowedActions); len(lines) > 0 {
		return lines
	}
	return append([]string(nil), defaultAllowedActions...)
}

// OutOfScopeLines returns the profile's out-of-scope list or the defaults.
func (s *Snapshot) OutOfScopeLines() []string {
	if lines := PipeLines(s.OutOfScopeActions); len(lines) > 0 {
		return lines
	}
	return append([]string(nil), defaultOutOfScope...)
}

// Decision is the result of a preflight: the ledger status and, when
// denied, the detail suffix and the operator-facing error.
type Decision struct {
	Allowed bool
	Detail  string
	Err     error
}

// Preflight evaluates capability against the snapshot for target. It does
// not touch the ledger; the caller records the decision so that the ledger
// package stays the only writer. hasApproval reports whether a current
// approval exists for gated capabilities.
func (s *Snapshot) Preflight(capability, target, reason string, hasApproval func(capability string) bool) Decision {
	detail := "reason=" + reason
	if !s.TargetMatches(target) {
		return Decision{Detail: detail + " target=" + target,
			Err: state.Failf("scope refused: target '%s' is outside active operation scope '%s'", target, s.Target)}
	}
	if Contains(s.Blocked, capability) {
		return Decision{Detail: detail + " blocked-capability=" + capability,
			Err: state.Failf("scope refused: capability '%s' is blocked", capability)}
	}
	if !Contains(s.Allowed, capability) {
		return Decision{Detail: detail + " unsupported-capability=" + capability,
			Err: state.Failf("scope refused: capability '%s' is not allowed for this operation", capability)}
	}
	if RequiresApproval(capability) && (hasApproval == nil || !hasApproval(capability)) {
		return Decision{Detail: detail + " approval-required=" + capability,
			Err: state.Failf("approval required: capability '%s' needs an approval grant, which Lite does not support (Lite runs tier 2 and below)", capability)}
	}
	return Decision{Allowed: true, Detail: detail + " target=" + target}
}
