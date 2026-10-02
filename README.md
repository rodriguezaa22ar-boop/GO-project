# Atlas Lite (Go)

Atlas Lite is a small, single-binary Go implementation of the Atlas control plane. It keeps the same on-disk format as the Atlas shell build and wraps tools you already use, such as nmap, in scope checks and hashed evidence.

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

Planning. The blueprint is in [`docs/BLUEPRINT.md`](docs/BLUEPRINT.md). No code has been written yet.

## License

Not yet chosen. Set a license before accepting contributions.
