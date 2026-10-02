# Lab Coat Lite (Go)

Lab Coat Lite (binary: `lcoat`) is a small, single-binary Go implementation of the control plane first prototyped as Atlas. It keeps the same on-disk format as the Atlas shell build and wraps tools you already use, such as nmap, in scope checks and hashed evidence.

An operator starts an operation against an in-scope target and runs tools through it. Each run is checked against a scope profile and recorded in an append-only ledger. Its output is saved as hashed evidence, and findings link back to that evidence. At the end, Lite produces metadata-only packets (report, handoff, closeout, audit, archive) and verifiers that replay the chain. Packets hold hashes, paths, counts and IDs, never raw artifacts or secrets.

## What it is

- A control plane for authorized assessment workflows: scope, evidence, findings, packets, verification.
- Tool-agnostic. Adapters wrap external tools as subprocesses; the tools never need to know about Atlas.
- File-backed and inspectable: NDJSON, env records and Markdown packets.
- A conformance prototype. The Atlas shell build is the oracle, and Lite is done when the two can finish each other's operations.

## What it is not

- Not a scanner, an exploit framework or an autonomous tester.
- Not able to run anything above Tier 2. Higher tiers are refused.
- Not production-ready, externally audited or tamper-proof. Status: ready-to-refine, internal readiness.
- Not a replacement for the Rust build, which is planned to follow once the formats and verifier behavior are settled here.

## Status

Prototype, ready-to-refine. The two-week MVP in [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md) is built and passes conformance against the Atlas shell build.

Implemented: `target`, `op start/resume/list/status/show/readiness/close/report/handoff/closeout/audit-packet/archive-packet/verify/audit-verify/archive-verify/trust-chain`, `scope status/check`, `evidence add/list/verify`, `finding add/list`, `ledger verify/checkpoint`, `receipt verify/replay/create`, and `adapter run` with the `nmap` adapter (flag allowlist; the target always comes from scope) and the `script` adapter (operator-declared tier, recorded rather than enforced).

Deferred to the Rust build (see the blueprint): `v1 status`/`production status` (the pillars check for a toolchain Lite does not ship, so `op trust-chain` certifies only the metadata chain), validation planning, evidence bundles and redaction, finding lifecycle beyond `add`, release packets, and the `web`/`flow`/`advisor` extensions.

### Build and test

```sh
go build ./cmd/lcoat
go test ./...
# Cross-check against an Atlas shell-build checkout:
ATLAS_REPO=/path/to/atlas-trust-infrastructure conformance/cross_check.sh
```

Conformance: a full lifecycle driven through both builds produces byte-identical state once the absolute lab-root path and sha hex are normalized, and each build's verifiers accept the other's packets. See [`docs/DECISION.md`](docs/DECISION.md) for the go/no-go memo.

## License

Not yet chosen. Set a license before accepting contributions.
