# Lab Coat Lite (Go) Blueprint

Lab Coat Lite (binary: `lcoat`) is a two-week Go build of the control-plane core first prototyped as Atlas, tested against the existing shell implementation as an oracle, then released as Lite while the Rust build takes over.

## Goals and non-goals

Lite must prove that the Atlas trust lifecycle survives a rewrite: a Go binary reads and writes the same on-disk state as the shell build and produces packets that the shell verifiers accept.

**Goals**

- Run the full lifecycle: scope, evidence, findings, report, handoff, close, closeout, audit packet, archive packet, trust-chain.
- Stay byte-compatible with the shell build's state layout, so either implementation can continue the other's operation.
- Wrap external tools (nmap first, then a generic script runner) behind scope checks, with output captured as hashed evidence.
- Produce a spec and fixture set that the Rust build inherits.

**Non-goals**

- Rewriting wiremap, vector or intelctl. They stay as sample adapters.
- Signing, SLSA provenance, production-readiness gates. Those remain shell-side until Rust.
- Compile-time metadata-only guarantees. Go cannot give them; see "Metadata-only enforcement in Go".
- Anything beyond Tier 2 execution. Lite does not run safe-validation or intrusive lanes.

Per the project's own language rules, Lite is described as ready-to-refine and metadata-only, not production-ready.

## Architecture

```text
Operator (lcoat CLI) --> Lab Coat Lite core (Go) ------------> Your existing tools
                         - Scope check (tier + profile)      - nmap
                         - Adapter runner                    - any CLI script
                         - Evidence and findings             - Burp, ZAP: later
                         - Packets (report to archive)       (exploit modules: refused)
                         - Verifiers and trust-chain
                                  ^
                                  |
                                  v
Shell build (the oracle) <--> Session files on disk
                              ledger.ndjson, evidence.ndjson, findings.ndjson, Markdown packets
```

The CLI sends every tool run through the scope check first. The adapter runner executes the tool, and the core records only hashes and results in plain files. Lite and the shell build read and write those same files, which is what makes the shell build usable as an oracle.

## State contract

Lite reads and writes the layout below, taken from an operation run in the shell build (`learning-op-001`). Everything is plain files under `sessions/<op>/`.

| Path | Format | Lite behavior |
| --- | --- | --- |
| `session.env` | shell-quoted `KEY=value` lines | Read and write. Needs a parser for `printf %q` quoting (`prototype\ learning`, `''`). |
| `scope.snapshot.env` | same env format | Copied from the profile at `op start`; read-only afterward. |
| `ledger.ndjson` | one JSON object per line: `ts, event, op, target, capability, tool, status, detail` | Append-only. Never rewritten. |
| `evidence.ndjson` | JSON lines: `id, sha256, path, kind, classification, redacted, source_path` | Append; hash computed on add. |
| `evidence/<id>/<file>` | copied artifact | Written once on `evidence add`. |
| `findings.ndjson` | JSON lines: `level, severity, confidence, status, evidence[]` | Append now; status updates later. |
| `handoff/`, `closeout/`, `audit/`, `archive/` | Markdown packets | Generated, each recording SHA256 of its inputs. |
| `reports/<name>.md` | Markdown, outside the session dir | Generated. |
| `validation.ndjson` | JSON lines | Read-only in Lite; validation planning is out of MVP. |

Three quirks the Go build has to respect:

- **No per-event hash link in the ledger.** Integrity comes from the whole-file SHA256 and event count recorded in the closeout, audit and archive packets. Only receipts carry `prev_hash`.
- **Second-resolution IDs.** `finding_20261002T054006Z` is a UTC timestamp, so two writes in one second collide. Lite must detect that and wait or suffix, not overwrite.
- **Packets embed hashes of other packets.** Generation order matters: report, handoff, closeout, audit, archive. Lite must follow it exactly or the shell verifiers will reject the result.

## Command surface

Lite keeps the shell build's grammar (`lcoat <domain> <verb>`, formerly `atlas <domain> <verb>`) so the same walkthroughs work on both. The MVP covers the lifecycle; everything else stays shell-side for now.

| Command | Stage | Mutates state | Lite |
| --- | --- | --- | --- |
| `target add / show / list` | Scope | yes | MVP |
| `op start / resume / close` | Scope | yes | MVP |
| `scope status / check` | Scope | ledger preflight event only | MVP |
| `evidence add` | Evidence | yes | MVP |
| `finding add / list` | Findings | yes | MVP |
| `op report` | Report | yes | MVP |
| `op handoff / closeout / audit-packet / archive-packet` | Retention | yes | MVP |
| `op verify / audit-verify / archive-verify` | Verification | no | MVP |
| `op trust-chain [--strict]` | Verification | no | MVP |
| `receipt verify / replay` | Receipts | no | MVP, port first |
| `receipt create` | Receipts | writes one file | MVP |
| `adapter run <adapter> <target>` | Adapters | evidence + ledger | MVP (new) |
| `finding update / accept / resolve` | Findings | yes | Later |
| `validation plan / approve / run` | Validation | yes | Later; needs the intel graph |
| `v1 status`, `production status` | Readiness | no | Later |
| `release packet / verify / replay / manifest` | Release | yes | Later; stays shell |
| `web`, `flow`, `advisor` | Extensions | yes | Not in Lite |

`adapter run` is the one new command. It follows the `<domain> <verb>` rule rather than adding a vague top-level `run`, which the Atlas `AGENTS.md` discourages (it names `atlas do` and `atlas runthis` as bad examples).

Read-only commands must stay read-only in Go too. Each gets a test that snapshots the session directory before and after and asserts no byte changed.

## Go package layout

One module, one binary, standard library only. `encoding/json`, `crypto/sha256`, `os/exec` and `flag` cover everything Lite needs, which keeps the supply chain as small as the shell build's.

```text
lcoat/
  go.mod
  cmd/lcoat/main.go        CLI entry and subcommand dispatch
  internal/
    envfile/               parse and write shell-quoted env records
    state/                 session layout, ID generation, file locking
    ledger/                append-only NDJSON, event count, file SHA256
    scope/                 profiles, capability tiers, preflight checks
    evidence/              add, hash, classify
    findings/              add, list, lifecycle
    packet/                report, handoff, closeout, audit, archive
    verify/                *-verify commands and trust-chain
    receipt/               create, verify, replay, forbidden-content scan
    adapter/               Adapter interface and runner
      nmap/
      script/
  testdata/
    golden/                sessions captured from the shell build
    profiles/              scope profiles copied from the shell build
  conformance/             runs shell and Go on one script, diffs the state
```

Two rules keep the packages honest. `ledger` is the only package that opens `ledger.ndjson`, and it opens it append-only under a file lock. `packet` never reads artifact bodies, only hashes and paths from `evidence` and `findings`, so a packet cannot leak content by construction.

## Adapter contract

An adapter wraps an external tool as a subprocess. The tool never needs to know about Atlas; Lite supplies the scope check, the ledger entries and the evidence hashing around it.

`lcoat adapter run <adapter> <target> [args]` does this, in order:

1. **Classify.** The adapter maps its arguments to a capability tier. Unknown arguments classify higher, per the project rule "when unsure, classify higher, not lower".
2. **Preflight.** `scope` checks the tier against the operation's `ALLOWED_CAPABILITIES` and `BLOCKED_CAPABILITIES`. A blocked or out-of-scope target stops here, with a ledger event.
3. **Record intent.** Append `adapter.started` to the ledger before anything touches the target.
4. **Execute.** Run the argv array directly. No `sh -c`, a scrubbed environment, a hard timeout.
5. **Capture.** Write stdout and stderr to a temp file and add it as evidence (`kind=scan-output`), which hashes it.
6. **Record result.** Append `adapter.finished` with exit code, duration, evidence ID and SHA256. Never the output itself.
7. **Propose findings.** If the adapter can parse its output, it returns proposed findings for the operator to confirm. Nothing is recorded as a finding automatically.

```go
type Adapter interface {
    Name() string
    Capability(args []string) scope.Tier      // unknown => higher tier
    Command(t Target, args []string) []string // argv, never a shell string
    Parse(out []byte) []ProposedFinding       // optional
}
```

| Adapter | Tier | Lite status |
| --- | --- | --- |
| `nmap` | 1 for `-sn`, 2 for port and service scans | MVP; parses XML output into proposed findings |
| `script` | operator must declare Tier 1 or 2; undeclared counts as Tier 3 and is refused | MVP; no parsing, evidence capture only |
| `burp`, `zap`, `nuclei` | 2 or 3 depending on mode | After MVP |
| `metasploit` | exploit modules are Tier 4 or above | Not in Lite; refused |

Lite refuses anything above Tier 2. Tier 3 approvals stay in the shell build until the approval plane is ported, and Tier 4 and 5 are refused outright.

## Metadata-only enforcement in Go

Go cannot make a forbidden field unrepresentable the way a Rust type can, so Lite enforces the rule with three layers that are weaker than Rust's but testable.

1. **Narrow packet types.** `packet` builds documents from structs whose fields are hashes, paths, counts, IDs and timestamps. There is no `Body` or `Content` field to fill. This stops accidents, not a developer who adds a string field.
2. **A scanner on every write path.** Port the forbidden-content patterns from the shell build's `receipt.sh` (secrets, tokens, private keys, authorization headers, raw prompts and outputs, cookies, exploit payloads) into `receipt.ForbiddenPaths`. Every packet and receipt passes through it before it reaches disk, and a hit aborts the write.
3. **Tests as the gate.** A table-driven test per pattern, plus a Go fuzz target that feeds random strings into finding titles and notes and asserts the scanner and writer agree.

The gap is real. In Go, a new code path that skips the scanner compiles fine and only a test catches it. In Rust, a `MetadataOnly` wrapper type that only the scanner can construct makes that path a compile error. That difference is the main thing the Rust build buys, and Lite should record every place where it was felt.

Two rules limit the damage in the meantime: only `packet` and `receipt` may write packet files, and CI fails if any other package imports `os.WriteFile` against a `sessions/` path.

## Conformance testing

The shell build is the spec. Lite is done when the two implementations can finish each other's operations and the shell verifiers accept everything Go writes.

1. **Pin the oracle.** Fix the shell build at one commit (a release packet generated during the walkthrough recorded `23ba2d2`) and never test against a moving target.
2. **Scenario scripts.** A scenario is a list of commands: add target, start op, add evidence, add findings, report, handoff, close, closeout, audit, archive. Run it once through the shell build and once through Go, each in its own temp root.
3. **Normalized diff.** Strip timestamps, timestamp-based ID suffixes and absolute paths, then compare the file list, the field sets of every NDJSON line, and the Markdown packets line by line.
4. **Cross-verification.** Run the shell's `op verify`, `op audit-verify`, `op archive-verify` and `op trust-chain` against the Go-written session, and Go's verifiers against the shell-written one. This uses the real hashes, so it catches what the normalized diff hides.
5. **First fixture.** The `learning-op-001` session from the walkthrough becomes golden fixture one: a real, closed operation with an `attention-required` readiness and a forced close.

The project's own rule applies: a trust gate is only real if it can fail correctly. Each verifier gets tamper fixtures, and the shell build is run first to record what it actually returns before Go is asked to match it.

| Tamper | Verifier that must object |
| --- | --- |
| Edit an evidence file after `evidence add` | evidence hash check |
| Append an event to the ledger after closeout | ledger replay in `op verify` and the release replay |
| Edit the report after the handoff was generated | freshness check (stale handoff) |
| Delete the closeout manifest | `op audit-verify` (missing packet) |
| Hand-edit a receipt's `prev_hash` | `receipt replay` chain check |

The Bats suite in the shell build's `tests/atlas.bats` is the second source of truth. Port it by lifecycle stage, in the same order as the plan below.

## Two-week plan

Each block ended with a check that can fail, so progress was measured by oracle agreement, not by lines written. All blocks are complete; the status column records how each exit check was met.

| Days | Deliverable | Exit check | Status |
| --- | --- | --- | --- |
| 1-2 | `envfile`, `state`, `ledger` | Go reads the `learning-op-001` session and computes a ledger SHA256 of `ba36a564...758f0c6f` over 18 events, matching the archive packet | Done; also matches the head event hash and closeout prefix hash |
| 3-4 | Targets, operations, scope profiles and preflight | `scope check` agrees with the shell build for every tier on `htb-starting-point`; `op start` output diffs clean | Done; `session.env`, scope snapshot and target record are byte-identical |
| 5-6 | `evidence add`, `finding add` | Evidence hash for the sample file is `fa0def3c...c1267ad`; the same-second ID collision test passes | Done |
| 7-8 | Report, handoff, closeout, audit and archive packets | The shell's `closeout`, `audit-verify` and `archive-verify` accept the Go-written packets | Done; all four packets are structurally byte-identical and verify both directions |
| 9-10 | `op verify`, `op trust-chain`, `receipt verify` and `replay` | Every tamper fixture fails the same way as in the shell; the three-receipt demo-site chain replays | Done; `receipt verify --json` is byte-identical. `op trust-chain` certifies the metadata chain only (v1 deferred, below) |
| 11-12 | `adapter run` with `nmap` and `script` | A scan of a local lab target is hashed into evidence with `adapter.started` and `adapter.finished` in the ledger; a Tier 3 request is refused | Done; nmap parses XML into proposed findings, metasploit refused |
| 13-14 | Full conformance run and the decision gate | Scenario diff is clean in both directions; a one-page go or no-go memo for the Rust build | Done; `conformance/cross_check.sh` passes, memo in `docs/DECISION.md` (verdict: go) |

Days 7-8 were the schedule risk, because the packets embed each other's hashes and must match the shell's format exactly; they landed without cutting scope.

One deviation from the plan: `op trust-chain` does not evaluate v1 readiness. The shell build's v1 pillars check for the `atlas`/`wiremap`/`vector`/`intelctl` toolchain that Lite does not ship, so Lite certifies only the metadata chain (archive status plus the closeout, audit and archive verifications). `v1 status` stays deferred to the Rust build.

## Open decisions

Settle these before day 1. Each has a default so the build is not blocked if you would rather not choose yet.

- [ ] **Repo location.** The Atlas public repo's `AGENTS.md` says Atlas is shell-native and tells contributors not to restructure it. Default: a separate repo (this one), so those rules stay true and Lite can state its own.
- [ ] **Public or private.** The existing split puts trust and verification in the public repo and operator runtime in the private toolkit. Default: verifiers, packets and receipts public; the `adapter` package private.
- [ ] **Byte-compatibility.** Default: Lite matches the shell build's formats exactly. A clean break would be faster to write but loses the oracle.
- [x] **Byte-compatibility (resolved in build).** Lite matches the shell build's formats exactly; the conformance cross-check holds the oracle.
- [x] **Ledger hash chain.** Lite does not add one; it stays byte-compatible. Recorded as the strongest single Rust-build candidate (see `docs/DECISION.md`).
- [ ] **Dev environment.** Default: add Go to the existing `shell.nix` so the toolchain stays reproducible the same way. (Lite currently builds with a stock Go toolchain and the standard library only.)
- [x] **Name.** Lab Coat, with the binary and crate name `lcoat`. The `atlas.*` schema IDs stay unchanged through Lite so the shell build remains a usable oracle; renaming them is a deliberate break for the Rust build.
- [ ] **License.** The owner's call; set it before the first public commit. Still open.
