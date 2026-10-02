# Lab Coat Lite — runbook for your Fedora lab

`lcoat` is a single static binary, no dependencies. You are the operator: it
only does what you run, under the scope you set, logged under your account.
Use it only against hosts you own or are authorized to assess — your Fedora
lab qualifies.

## 0. Install

Fedora 44 is almost certainly x86_64. Check with `uname -m`
(`x86_64` → amd64, `aarch64` → arm64), then:

```sh
# verify the download first
sha256sum -c SHA256SUMS --ignore-missing
install -m 0755 lcoat-linux-amd64 ~/.local/bin/lcoat   # or arm64
lcoat version          # -> lcoat 0.1.0
```

Pick a lab root (all state lives here; nothing is written elsewhere):

```sh
export LCOAT_ROOT="$HOME/lcoat-lab"
mkdir -p "$LCOAT_ROOT"
```

The default profile allows read-only, passive-recon, active-recon and
(approval-gated) safe-validation, and blocks destructive/persistence/DoS.
That is enough for recon; you need no profile file.

## Mode A — run it ON the lab box (capture local recon as evidence)

```sh
lcoat target add fedora-lab 127.0.0.1 --scope-status in-scope --criticality low --tag homelab
lcoat op start fedora-lab-review fedora-lab authorized self-review of my study server

# Capture real local recon through the script adapter (tier 2 = active-recon).
# Each run is scope-checked and its output is hashed into evidence.
lcoat adapter run script fedora-lab --tier 1 -- ss -tlnp
lcoat adapter run script fedora-lab --tier 1 -- systemctl list-units --type=service --state=running
lcoat adapter run script fedora-lab --tier 1 -- rpm -qa --last
```

## Mode B — run it FROM your workstation against the lab (nmap over the tailnet)

Install nmap first (`sudo dnf install nmap`). Then:

```sh
lcoat target add astra 100.71.57.96 --scope-status in-scope --criticality low --tag homelab
lcoat op start astra-recon astra authorized recon of my study server

# -sn is classified passive-recon (tier 1); a service scan is active-recon (tier 2).
lcoat adapter run nmap astra -- -sn
lcoat adapter run nmap astra -- -sV --top-ports 100
# nmap output is parsed into PROPOSED findings; you confirm the ones you want.
```

## Turn proposed findings into recorded findings

```sh
lcoat evidence list                       # note the evidence id (ev_...)
lcoat finding add "OpenSSH 22/tcp exposed" \
  --level observed --severity info --confidence high \
  --evidence ev_XXXX \
  --recommendation "Confirm SSH exposure is intended; restrict source if not"
lcoat op brief
```

## Close out with a verifiable trust chain

```sh
lcoat op report
lcoat op handoff
lcoat op close --force            # --force only while findings are still open
lcoat op closeout
lcoat op audit-packet
lcoat op archive-packet

# Independently re-hash the chain. All three should say "verified".
lcoat op verify
lcoat op audit-verify
lcoat op archive-verify
lcoat op trust-chain
```

## Mint a portable proof (optional)

```sh
A="$LCOAT_ROOT/sessions/astra-recon/archive/astra-recon-archive.md"
lcoat receipt create --action astra.recon.archived --actor "$USER" \
  --subject-type atlas-operation --subject operation://astra-recon \
  --artifact-ref "$A=$(sha256sum "$A" | awk '{print $1}')" \
  --out astra-recon.receipt.json
lcoat receipt verify astra-recon.receipt.json
```

## Notes

- Everything is metadata-only: packets and receipts store paths, hashes,
  counts and IDs — never raw output, secrets or credentials. Raw tool output
  lives only in the evidence files under your lab root.
- The ledger (`sessions/<op>/ledger.ndjson`) is append-only; the packet
  verifiers anchor its whole-file hash, so an edited ledger line is caught by
  `op audit-verify`.
- Keep real findings and any client/engagement data out of public repos.
  This lab root is yours; it is not published anywhere.
- `lcoat help` lists every command.
```
