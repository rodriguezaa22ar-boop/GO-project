// Package state knows where the Atlas shell build keeps its files and
// provides the small helpers (timestamps, slugs, IDs, history) that every
// command shares. It is the only package that resolves LAB_* paths.
package state

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/rodriguezaa22ar-boop/go-project/internal/envfile"
)

// ToolName is the value the shell build writes into SOURCE_TOOL. Lite keeps
// it so that the two implementations recognise each other's operations.
const ToolName = "atlas"

// Layout is the resolved directory layout for one lab root.
type Layout struct {
	Root        string
	StateDir    string
	TargetsDir  string
	SessionsDir string
	ReportsDir  string
	ProfilesDir string
	AtlasState  string
	ActiveFile  string
}

// Resolve builds the layout from the environment, mirroring lib/common.sh:
// LAB_ROOT defaults to the current directory, etc/lab.env is sourced if
// present, and each LAB_* variable can override one directory.
func Resolve() (*Layout, error) {
	root := os.Getenv("LAB_ROOT")
	if root == "" {
		root = os.Getenv("LCOAT_ROOT")
	}
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		root = wd
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}

	config := map[string]string{}
	configPath := os.Getenv("LAB_CONFIG")
	if configPath == "" {
		configPath = filepath.Join(root, "etc", "lab.env")
	}
	if rec, err := envfile.Load(configPath); err == nil {
		for _, k := range rec.Keys() {
			config[k] = rec.Get(k)
		}
	}
	get := func(key, fallback string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		if v, ok := config[key]; ok && v != "" {
			return v
		}
		return fallback
	}

	l := &Layout{Root: root}
	l.StateDir = get("LAB_STATE_DIR", filepath.Join(root, "state"))
	l.TargetsDir = get("LAB_TARGETS_DIR", filepath.Join(root, "targets"))
	l.SessionsDir = get("LAB_SESSIONS_DIR", filepath.Join(root, "sessions"))
	l.ReportsDir = get("LAB_REPORTS_DIR", filepath.Join(root, "reports"))
	l.ProfilesDir = get("ATLAS_SCOPE_PROFILES_DIR", "")
	if l.ProfilesDir == "" {
		candidates := []string{
			filepath.Join(root, "tools", "atlas", "profiles"),
			filepath.Join(root, "profiles"),
		}
		l.ProfilesDir = candidates[0]
		for _, c := range candidates {
			if st, err := os.Stat(c); err == nil && st.IsDir() {
				l.ProfilesDir = c
				break
			}
		}
	}
	l.AtlasState = filepath.Join(l.StateDir, "atlas")
	l.ActiveFile = filepath.Join(l.AtlasState, "active.env")
	return l, nil
}

// EnsureLayout creates the directories a mutating command expects.
func (l *Layout) EnsureLayout() error {
	for _, d := range []string{l.StateDir, l.TargetsDir, l.SessionsDir, l.ReportsDir, l.AtlasState} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	return nil
}

// OpDir returns the session directory for an operation slug.
func (l *Layout) OpDir(slug string) string {
	return filepath.Join(l.SessionsDir, slug)
}

// Now is the clock used for every timestamp. Tests may replace it. The
// LCOAT_NOW environment variable (RFC3339 UTC) pins it, which conformance
// runs use to align with a frozen shell-build clock.
var Now = func() time.Time {
	if v := os.Getenv("LCOAT_NOW"); v != "" {
		if t, err := time.Parse("2006-01-02T15:04:05Z", v); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

// Timestamp returns the shell build's `date -u +%Y-%m-%dT%H:%M:%SZ`.
func Timestamp() string {
	return Now().Format("2006-01-02T15:04:05Z")
}

// Today returns the shell build's `date -u +%F`, honouring ATLAS_TODAY.
func Today() string {
	if v := os.Getenv("ATLAS_TODAY"); v != "" {
		return v
	}
	return Now().Format("2006-01-02")
}

var (
	slugBad   = regexp.MustCompile(`[^a-z0-9._-]+`)
	slugMulti = regexp.MustCompile(`-{2,}`)
)

// Slugify mirrors lib/common.sh slugify.
func Slugify(s string) string {
	s = strings.ToLower(s)
	s = slugBad.ReplaceAllString(s, "-")
	s = strings.TrimLeft(s, "-")
	s = strings.TrimRight(s, "-")
	s = slugMulti.ReplaceAllString(s, "-")
	return s
}

// NextID reproduces the shell build's timestamp IDs: prefix_YYYYMMDDTHHMMSSZ,
// with a _02, _03 suffix when a directory for that ID already exists under
// dir. The caller creates the directory immediately to claim the ID.
func NextID(dir, prefix string) string {
	base := prefix + "_" + Now().Format("20060102T150405Z")
	candidate := base
	for index := 2; ; index++ {
		if _, err := os.Lstat(filepath.Join(dir, candidate)); os.IsNotExist(err) {
			return candidate
		}
		candidate = fmt.Sprintf("%s_%02d", base, index)
	}
}

// SHA256File returns the lowercase hex digest of a file, like sha256sum.
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Bytes hashes an in-memory buffer.
func SHA256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FileExists reports whether path is an existing regular file.
func FileExists(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// RecordHistory appends to notes/history.log as the shell build does.
func RecordHistory(opDir, event, detail string) error {
	if err := os.MkdirAll(filepath.Join(opDir, "notes"), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(opDir, "notes", "history.log"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\t%s\t%s\n", Timestamp(), event, detail)
	return err
}

// UserError marks an error whose message is meant for the operator; the CLI
// prints it as `error: ...` and exits 1, matching the shell build's fail().
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

// Failf builds a UserError.
func Failf(format string, args ...any) error {
	return &UserError{Msg: fmt.Sprintf(format, args...)}
}
