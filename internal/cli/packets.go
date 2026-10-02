package cli

import (
	"path/filepath"
	"strings"

	"github.com/rodriguezaa22ar-boop/go-project/internal/operation"
	"github.com/rodriguezaa22ar-boop/go-project/internal/packet"
	"github.com/rodriguezaa22ar-boop/go-project/internal/state"
)

func opHandoff(ctx *Context, args []string) error {
	name, packetName := twoNames(args)
	op, err := operation.LoadNamedOrActive(ctx.Layout, name)
	if err != nil {
		return err
	}
	path, err := packet.Handoff(op, packetName)
	if err != nil {
		return err
	}
	ok(ctx, "handoff packet written")
	kv(ctx, "handoff", path)
	return nil
}

func opCloseout(ctx *Context, args []string) error {
	name, manifestName := twoNames(args)
	op, err := operation.LoadNamedOrActive(ctx.Layout, name)
	if err != nil {
		return err
	}
	path, err := packet.Closeout(op, manifestName)
	if err != nil {
		return err
	}
	ok(ctx, "closeout manifest written")
	kv(ctx, "closeout", path)
	return nil
}

func opAuditPacket(ctx *Context, args []string) error {
	name, packetName := twoNames(args)
	op, err := operation.LoadNamedOrActive(ctx.Layout, name)
	if err != nil {
		return err
	}
	path, err := packet.Audit(op, packetName)
	if err != nil {
		return err
	}
	ok(ctx, "audit packet written")
	kv(ctx, "audit_packet", path)
	return nil
}

func opArchivePacket(ctx *Context, args []string) error {
	name, packetName := twoNames(args)
	op, err := operation.LoadNamedOrActive(ctx.Layout, name)
	if err != nil {
		return err
	}
	path, err := packet.Archive(op, packetName)
	if err != nil {
		return err
	}
	ok(ctx, "archive packet written")
	kv(ctx, "archive_packet", path)
	return nil
}

// resolvePacketArg resolves [name] [packet] positionals shared by the
// verify commands: the first token may be an operation name or a packet.
func resolveVerifyArgs(ctx *Context, args []string, subdir string) (*operation.Operation, string, error) {
	var names []string
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			names = append(names, a)
		}
	}
	var op *operation.Operation
	var packetArg string
	var err error
	switch len(names) {
	case 0:
		op, err = operation.LoadActive(ctx.Layout)
	case 1:
		slug := state.Slugify(names[0])
		if fileExists(filepath.Join(ctx.Layout.OpDir(slug), "session.env")) {
			op, err = operation.Load(ctx.Layout, names[0])
		} else {
			op, err = operation.LoadActive(ctx.Layout)
			packetArg = names[0]
		}
	default:
		op, err = operation.Load(ctx.Layout, names[0])
		packetArg = names[1]
	}
	if err != nil {
		return nil, "", err
	}
	path, err := resolvePacketPath(op, subdir, packetArg)
	return op, path, err
}

// resolvePacketPath finds the packet file: explicit path, subdir/name, or
// the latest recorded one.
func resolvePacketPath(op *operation.Operation, subdir, arg string) (string, error) {
	dir := filepath.Join(op.Dir, subdir)
	if arg == "" {
		latest, err := packet.LatestInLedger(op, subdir)
		if err != nil {
			return "", err
		}
		if latest == "" {
			return "", state.Failf("no %s packet recorded for operation '%s'", subdir, op.Slug)
		}
		if !fileExists(latest) {
			return "", state.Failf("recorded %s packet is missing: %s", subdir, latest)
		}
		return latest, nil
	}
	if fileExists(arg) {
		return arg, nil
	}
	if c := filepath.Join(dir, arg); fileExists(c) {
		return c, nil
	}
	base := strings.TrimSuffix(strings.TrimSuffix(arg, ".md"), ".json")
	if c := filepath.Join(dir, state.Slugify(base)+".md"); fileExists(c) {
		return c, nil
	}
	return "", state.Failf("unknown %s packet for operation '%s': %s", subdir, op.Slug, arg)
}

func opVerify(ctx *Context, args []string) error {
	op, path, err := resolveVerifyArgs(ctx, args, "closeout")
	if err != nil {
		return err
	}
	res, err := packet.CloseoutVerify(op, path)
	if err != nil {
		return err
	}
	return printVerify(ctx, op, "Closeout Verification", path, res)
}

func opAuditVerify(ctx *Context, args []string) error {
	op, path, err := resolveVerifyArgs(ctx, args, "audit")
	if err != nil {
		return err
	}
	res, err := packet.AuditVerify(op, path)
	if err != nil {
		return err
	}
	return printVerify(ctx, op, "Audit Packet Verification", path, res)
}

func opArchiveVerify(ctx *Context, args []string) error {
	op, path, err := resolveVerifyArgs(ctx, args, "archive")
	if err != nil {
		return err
	}
	res, err := packet.ArchiveVerify(op, path)
	if err != nil {
		return err
	}
	return printVerify(ctx, op, "Archive Packet Verification", path, res)
}

func printVerify(ctx *Context, op *operation.Operation, title, path string, res *packet.VerifyResult) error {
	heading(ctx, title)
	rule(ctx)
	kv(ctx, "Operation", op.Name)
	kv(ctx, "Packet", path)
	rule(ctx)
	for _, r := range res.Rows {
		line(ctx, "%s", r)
	}
	rule(ctx)
	kv(ctx, "Verification Status", res.Status)
	kv(ctx, "Verified Anchors", itoaCLI(res.Verified))
	kv(ctx, "Verification Gaps", itoaCLI(res.Gaps))
	kv(ctx, "Verification Problems", itoaCLI(res.Problems))
	if res.Problems > 0 {
		return &ExitError{Code: 1}
	}
	return nil
}

func itoaCLI(n int) string { return itoa(n) }
