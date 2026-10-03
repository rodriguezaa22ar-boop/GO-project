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
lcoat version          # -> lcoat 0.1.4
```

Pick a lab root (all state lives here; nothing is written elsewhere):

```sh
echo 'export LCOAT_ROOT="$HOME/lcoat-lab"' >> ~/.bashrc && source ~/.bashrc
mkdir -p "$LCOAT_ROOT"
```

The default profile allows read-only, passive-recon, active-recon and
(approval-gated) safe-validation, and blocks destructive/persistence/DoS.
That is enough for recon; you need no profile file.

## Mode A — run it ON the lab box (capture local recon as evidence)

```sh
lcoat target add fedora-lab 127.0.0.1 --scope-status in-scope --criticality low --tag homelab
lcoat op start fedora-lab-review fedora-lab authorized self-review of my study server

# Capture real local recon through the script adapter. You declare the tier
# (--tier 1 passive, --tier 2 active); Lite records your declaration but
# cannot inspect an arbitrary command, so the ledger reflects your word, not
# enforcement. Each run's output is hashed into evidence.
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

The nmap adapter only accepts allowlisted flags, and the target address
always comes from the operation's scope, never from your arguments. Refused:
extra hosts (bare addresses, `-iL`, `-iR`, `--resume`), output flags (`-o*`,
the adapter manages output), NSE scripts other than `--script default|safe`,
`--script-args`, decoys/spoofing/evasion options and `--min-rate`. Allowed:
`-sn -sS -sT -sU -sV -sC -A -O -F -r -Pn -n -6 -v -vv -T0..-T5 --open
--reason --traceroute --version-light --version-all`, plus `-p`, `--top-ports`,
`--exclude-ports`, `--version-intensity`, `--max-retries`, `--max-rate`,
`--host-timeout`.

nmap runs default to a 10-minute timeout (other adapters: 2 minutes). Pass
`--timeout <seconds>` before the `--` to change it. If a run hits the limit,
its partial output is still kept as evidence and the run is logged as an
error.

```sh
lcoat adapter run nmap astra -- -sV 10.0.0.0/8   # refused: extra target
```

## Turn proposed findings into recorded findings

```sh
lcoat evidence list                       # note the evidence id (ev_...)
lcoat finding add "Cockpit 9090/tcp listens on all interfaces" \
  --level observed --severity low --confidence high --status open \
  --evidence ev_XXXX \
  --recommendation "Restrict to the tailnet with firewalld, or disable it if unused"
lcoat finding list
lcoat op brief
```

A finding's status is set when you add it and cannot be changed later, and
it decides how the operation ends:

| Status | Use it when | Trust chain ends |
| --- | --- | --- |
| `open` | Needs fixing, not fixed yet | `attention-required` |
| `resolved` | Fixed during the run; cite the re-scan evidence | `current` |
| `accepted` | Intended exposure, risk accepted | `incomplete` (needs a review packet Lite cannot make) |

Expected exposure such as SSH on the tailnet does not need a finding; the
evidence already records it.

## Close out with a verifiable trust chain

```sh
OP=astra-recon                    # your operation name
lcoat op report
lcoat op handoff
lcoat op close                    # add --force only if a finding is still open

# After close there is no active operation, so name it from here on.
lcoat op closeout       $OP
lcoat op audit-packet   $OP
lcoat op archive-packet $OP

# Independently re-hash the chain.
lcoat op verify         $OP
lcoat op audit-verify   $OP
lcoat op archive-verify $OP
lcoat evidence verify   $OP       # re-hashes every captured evidence file
lcoat op trust-chain    $OP
```

`Trust Chain Status` is `current` with no findings or only `resolved` ones,
`attention-required` with any `open` finding, and `incomplete` with any
`accepted` one. Either way, the Verification section's Closeout, Audit
Packet, Archive Packet and Evidence Artifacts lines should all say
`verified`.

List commands take the operation name too, so they work after close:
`lcoat finding list $OP`, `lcoat evidence list $OP`, `lcoat scope status $OP`.

`op brief` may suggest "Create a validation plan"; validation planning is
not in Lite, so skip that step.

## Mint a portable proof (optional)

```sh
A="$LCOAT_ROOT/sessions/$OP/archive/$OP-archive.md"
lcoat receipt create --action astra.recon.archived --actor "$USER" \
  --subject-type atlas-operation --subject operation://$OP \
  --artifact-ref "$A=$(sha256sum "$A" | awk '{print $1}')" \
  --out $OP.receipt.json
lcoat receipt verify $OP.receipt.json
```

## Notes

- Everything is metadata-only: packets and receipts store paths, hashes,
  counts and IDs — never raw output, secrets or credentials. Raw tool output
  lives only in the evidence files under your lab root.
- The ledger (`sessions/<op>/ledger.ndjson`) is append-only; the packet
  verifiers anchor its whole-file hash, so an edited ledger line is caught by
  `op audit-verify`. Edited or deleted evidence files are caught by
  `evidence verify` and `op trust-chain`.
- `receipt verify` checks the receipt itself, not the files it references.
  To confirm the archive is unchanged, re-run `sha256sum` on it and compare
  with the receipt's artifact ref.
- If a tool is not installed, `adapter run` refuses before anything is
  logged. If the tool runs but exits non-zero, its output is still captured
  as evidence, the run is logged as an error, and `lcoat` exits 1.
- Keep real findings and any client/engagement data out of public repos.
  This lab root is yours; it is not published anywhere.
- `lcoat help` lists every command.
```
