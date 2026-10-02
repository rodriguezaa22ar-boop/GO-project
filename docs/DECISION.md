# Lab Coat Lite: go / no-go memo

As-of: 2026-10-02. Prototype built by driving the blueprint end to end and
cross-checking every stage against the Atlas shell build pinned at commit
`23ba2d2`.

## Verdict

Go. The Atlas trust lifecycle survives a rewrite. A Go binary reads and
writes the same on-disk state as the shell build and produces packets the
shell verifiers accept, so the shell build is a usable oracle for the Rust
build. Proceed to the Rust build with the formats and verifier semantics
settled here.

## What was proven

- **Byte compatibility.** A full lifecycle (scope, evidence, finding,
  report, handoff, close, closeout, audit, archive) driven through the Go
  build and the shell build under a frozen clock produces byte-identical
  `session.env`, `scope.snapshot.env`, `ledger.ndjson`, `evidence.ndjson`,
  `findings.ndjson`, the target record, the operation report and all four
  retention packets. Only the absolute lab-root prefix and the sha hex it
  changes differ, because the two runs live at different roots.
- **Verifier agreement, both directions.** The shell build's `op verify`,
  `op audit-verify` and `op archive-verify` accept every Go-written packet
  with zero problems, and the Go verifiers accept every shell-written
  packet. `conformance/cross_check.sh` runs all of this against a given
  Atlas checkout.
- **Hash reproduction.** The Go build reproduces the shell build's ledger
  file sha, event count, head event hash and closeout prefix hash on the
  golden `learning-op-001` session, and the evidence artifact hash.
- **Receipts.** `receipt verify --json` is byte-identical to the shell
  build on the demo-site receipts, the three-receipt chain replays to the
  same head hashes, a Go-created receipt verifies under the shell build,
  and tampered chains and forbidden content are rejected the same way.
- **Adapters.** `adapter run` wraps a tool behind a scope check, captures
  output as hashed evidence, records `adapter.started`/`adapter.finished`,
  and refuses anything above Tier 2 (undeclared script tier, metasploit).

## Confirmed design facts (carry into Rust)

- The ledger has no per-event hash chain; integrity rests on the whole-file
  sha and event count recorded in the closeout, audit and archive packets.
  Only receipts carry `prev_hash`. A chained ledger remains the strongest
  single upgrade for the Rust build: it would let a verifier detect a
  rewritten middle event, not just a changed file.
- IDs are second-resolution timestamps; same-second writes must suffix
  `_02`, `_03`. The Go build does this and it is tested.
- Packets embed each other's hashes, so generation order is load-bearing:
  report, handoff, then close, then closeout, audit, archive. The closeout,
  audit and archive packets each append their ledger event before
  rendering, so their ledger anchor includes it; handoff appends after.
- Hashing is sha256 over `jq -cS` canonical JSON plus a trailing newline.
  Reproducing jq's compact sorted-key encoding and number formatting is the
  subtle part; the Rust build should port `internal/ndjson` carefully and
  reuse these fixtures.

## What Lite does not cover, and why

- **v1 / production readiness.** The shell build's v1 pillars check for the
  presence of the `atlas`/`wiremap`/`vector`/`intelctl` toolchain, which
  Lite does not ship, so a faithful port does not fit Lite. `op trust-chain`
  therefore certifies only the metadata chain (archive status plus the
  three packet verifications) and labels v1 as not evaluated. The Rust build
  should decide whether v1 means "the toolchain is installed" or "this
  operation's trust artifacts are sound" and split the two.
- **Validation planning** needs the shared intel graph (wiremap), which is
  out of scope for a control-plane prototype.
- Evidence bundles and redaction, changing a finding's status after `add`, release
  packets, and the `web`/`flow`/`advisor` extensions were out of the MVP.

## Metadata-only enforcement: the gap to close in Rust

Lite enforces the metadata-only boundary with narrow packet structs (no
`Body`/`Content` field to fill), a forbidden-content scanner ported from
`receipt.sh`, and tests. A new code path that skips the scanner still
compiles; only a test catches it. This is the main thing the Rust build
buys: a `MetadataOnly` wrapper type that only the scanner can construct
makes that path a compile error. Every packet writer in Lite is a place
where that gap was felt.

## Field test (0.1.1 → 0.1.3)

A full operation run against a live container (local recon via the script
adapter, guardrail probes, closeout chain, receipt, tamper tests) found:

- **Edited evidence went undetected.** The packets anchor the evidence
  index, not the artifact bytes. Fixed: `evidence verify` re-hashes every
  stored artifact, and `op trust-chain` fails on any change. The Rust build
  should anchor artifact hashes inside the packets themselves.
- **A missing tool reported success.** `adapter run` printed "ok" and stored
  an empty capture. Fixed: tools resolve through the scrubbed PATH before
  `adapter.started`; a non-zero exit warns and exits 1.
- **Two adapter tests passed for the wrong reason** (the script adapter
  executed `--` as the tool). Fixed, and tests now require exit 0.
- **Runbook error:** packet commands after `op close` need the operation
  name. Fixed.
- **List commands ignored the operation name** (0.1.3). `finding list`,
  `evidence list` and `scope status` always read the active operation, so
  after `op close` they failed, and with another operation active they
  silently showed the wrong one's records. They now take an optional
  operation name and reject unknown names or stray arguments.
- Correction: Lite can end a chain clean. `finding add --status resolved`
  yields `current`; `open` yields `attention-required`; `accepted` yields
  `incomplete` (needs the review packet Lite lacks). What Lite lacks is
  changing a status after the finding is added.
- Still open: `receipt verify` does not re-hash referenced artifacts (by
  design, matches the shell build); `op brief` suggests validation
  planning, which Lite lacks.
