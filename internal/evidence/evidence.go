// Package evidence copies artifacts into the operation, hashes them and
// records them in evidence.ndjson. It never reads artifact bodies back for
// anything except hashing.
package evidence

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/rodriguezaa22ar-boop/go-project/internal/ndjson"
	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/scope"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

// IndexFile returns evidence.ndjson for an operation directory.
func IndexFile(opDir string) string { return filepath.Join(opDir, "evidence.ndjson") }

// Dir returns the evidence directory for an operation directory.
func Dir(opDir string) string { return filepath.Join(opDir, "evidence") }

// Record is one evidence index entry.
type Record struct {
	ID             string
	Operation      string
	Target         string
	Kind           string
	SourceTool     string
	SourcePath     string
	Path           string
	SHA256         string
	CreatedAt      string
	Classification string
	Redacted       bool
}

// AddParams holds the inputs to Add.
type AddParams struct {
	SourcePath     string
	Kind           string
	Target         string
	Classification string
	Redacted       bool
	Tool           string // ledger tool name; defaults to atlas
}

// Add mirrors cmd_evidence_add: preflight, allocate the ID, copy, hash,
// verify the copy, append the index record and the ledger event.
func Add(op *operation.Operation, p AddParams) (*Record, error) {
	if !state.FileExists(p.SourcePath) {
		return nil, state.Failf("evidence path is not a file: %s", p.SourcePath)
	}
	if p.Kind == "" {
		p.Kind = "artifact"
	}
	if p.Classification == "" {
		p.Classification = "internal"
	}
	if p.Target == "" {
		p.Target = op.Target
	}
	if p.Tool == "" {
		p.Tool = state.ToolName
	}
	if err := op.Preflight(scope.ReadOnly, p.Tool, p.Target, "add evidence artifact"); err != nil {
		return nil, err
	}
	root := Dir(op.Dir)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	id := state.NextID(root, "ev")
	dir := filepath.Join(root, id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, err
	}
	name := state.Slugify(filepath.Base(p.SourcePath))
	if name == "" {
		name = "artifact"
	}
	relative := filepath.Join("evidence", id, name)
	destination := filepath.Join(op.Dir, relative)

	sum, err := state.SHA256File(p.SourcePath)
	if err != nil {
		return nil, err
	}
	if err := copyFile(p.SourcePath, destination); err != nil {
		return nil, err
	}
	copied, err := state.SHA256File(destination)
	if err != nil {
		return nil, err
	}
	if copied != sum {
		return nil, state.Failf("evidence copy integrity check failed")
	}
	rec := &Record{ID: id, Operation: op.Slug, Target: p.Target, Kind: p.Kind, SourceTool: state.ToolName,
		SourcePath: p.SourcePath, Path: relative, SHA256: sum, CreatedAt: state.Timestamp(),
		Classification: p.Classification, Redacted: p.Redacted}
	if err := ndjson.Append(IndexFile(op.Dir), rec.object()); err != nil {
		return nil, err
	}
	detail := fmt.Sprintf("evidence=%s kind=%s sha256=%s path=%s", id, p.Kind, sum, relative)
	if err := op.AppendLedger("artifact.created", scope.ReadOnly, p.Tool, "ok", detail); err != nil {
		return nil, err
	}
	return rec, nil
}

func (r *Record) object() ndjson.Object {
	return ndjson.Object{
		{Key: "id", Value: r.ID},
		{Key: "operation", Value: r.Operation},
		{Key: "target", Value: r.Target},
		{Key: "kind", Value: r.Kind},
		{Key: "source_tool", Value: r.SourceTool},
		{Key: "source_path", Value: r.SourcePath},
		{Key: "path", Value: r.Path},
		{Key: "sha256", Value: r.SHA256},
		{Key: "created_at", Value: r.CreatedAt},
		{Key: "classification", Value: r.Classification},
		{Key: "redacted", Value: r.Redacted},
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// Latest returns the newest record per ID for an operation, filtered to a
// target when target is non-empty, as the jq reduce/select does.
func Latest(opDir, target string) ([]Record, error) {
	recs, err := ndjson.ReadFile(IndexFile(opDir))
	if err != nil {
		return nil, err
	}
	byID, order := ndjson.Latest(recs)
	var out []Record
	for _, id := range order {
		r := byID[id]
		if target != "" && r.String("target") != target {
			continue
		}
		out = append(out, Record{
			ID: r.String("id"), Operation: r.String("operation"), Target: r.String("target"),
			Kind: r.String("kind"), SourceTool: r.String("source_tool"), SourcePath: r.String("source_path"),
			Path: r.String("path"), SHA256: r.String("sha256"), CreatedAt: r.String("created_at"),
			Classification: r.String("classification"), Redacted: r.Bool("redacted"),
		})
	}
	return out, nil
}

// Count mirrors atlas_evidence_count_for_target.
func Count(opDir, target string) (int, error) {
	recs, err := Latest(opDir, target)
	return len(recs), err
}

// Exists reports whether an evidence ID is recorded for the operation.
func Exists(opDir, id string) (bool, error) {
	recs, err := ndjson.ReadFile(IndexFile(opDir))
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if r.String("id") == id {
			return true, nil
		}
	}
	return false, nil
}

// Rows mirrors atlas_evidence_rows_for_target: newest first by created_at
// then id, limited.
func Rows(opDir, target string, limit int) ([]Record, error) {
	recs, err := Latest(opDir, target)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].CreatedAt != recs[j].CreatedAt {
			return recs[i].CreatedAt > recs[j].CreatedAt
		}
		return recs[i].ID > recs[j].ID
	})
	if limit > 0 && len(recs) > limit {
		recs = recs[:limit]
	}
	return recs, nil
}
