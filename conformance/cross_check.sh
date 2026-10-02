#!/usr/bin/env bash
# Cross-check the Lab Coat Lite (Go) build against the Atlas shell build.
#
# Drives one scenario through both builds in separate roots under a frozen
# clock, then:
#   1. diffs every state file (root + sha normalized),
#   2. runs the shell verifiers against the Go-written packets,
#   3. runs the Go verifiers against the shell-written packets.
#
# Usage: ATLAS_REPO=/path/to/atlas-trust-infrastructure conformance/cross_check.sh
# The Atlas repo must contain lib/, tools/ and bin/ for the shell build.
set -euo pipefail

ATLAS_REPO="${ATLAS_REPO:?set ATLAS_REPO to the atlas-trust-infrastructure checkout}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export LCOAT_NOW="${LCOAT_NOW:-2026-10-02T07:40:00Z}"

# Frozen date shim so the shell build and Go build agree on timestamps/IDs.
shim="$(mktemp -d)"
cat >"$shim/date" <<'SHIM'
#!/usr/bin/env bash
now="${LCOAT_NOW:-2026-10-02T07:40:00Z}"
y=${now:0:4}; mo=${now:5:2}; d=${now:8:2}; h=${now:11:2}; mi=${now:14:2}; s=${now:17:2}
for a in "$@"; do
  case "$a" in
    +%Y-%m-%dT%H:%M:%SZ) printf '%s-%s-%sT%s:%s:%sZ\n' "$y" "$mo" "$d" "$h" "$mi" "$s"; exit 0 ;;
    +%Y%m%dT%H%M%SZ)     printf '%s%s%sT%s%s%sZ\n' "$y" "$mo" "$d" "$h" "$mi" "$s"; exit 0 ;;
    +%F)                 printf '%s-%s-%s\n' "$y" "$mo" "$d"; exit 0 ;;
  esac
done
exec /usr/bin/date "$@"
SHIM
chmod +x "$shim/date"
export PATH="$shim:$PATH"

lcoat="$(mktemp -d)/lcoat"
( cd "$HERE" && go build -o "$lcoat" ./cmd/lcoat )

SH="$(mktemp -d)"; GO="$(mktemp -d)"
for r in "$SH" "$GO"; do
  cp -r "$ATLAS_REPO/lib" "$r/lib"
  cp -r "$ATLAS_REPO/tools" "$r/tools"
  cp -r "$ATLAS_REPO/bin" "$r/bin"
done
printf 'nmap scan output\nPORT 22 open ssh\n' >"$SH/recon.txt"
cp "$SH/recon.txt" "$GO/recon.txt"

scenario() { # ROOTVAR bin root
  local V="$1" bin="$2" root="$3" eid
  env "$V=$root" "$bin" target add demo-node 10.10.10.5 --scope-status in-scope --criticality medium --tag prototype >/dev/null
  env "$V=$root" "$bin" op start --profile htb-starting-point full-op demo-node authorized full lifecycle >/dev/null
  eid=$(env "$V=$root" "$bin" evidence add "$root/recon.txt" --kind scan-output --classification public | awk -F': ' '$1=="id"{print $2}')
  env "$V=$root" "$bin" finding add "SSH exposed" --level observed --severity low --confidence high --evidence "$eid" >/dev/null
  env "$V=$root" "$bin" op report full-op >/dev/null
  env "$V=$root" "$bin" op handoff full-op >/dev/null
  env "$V=$root" "$bin" op close full-op --force >/dev/null
  env "$V=$root" "$bin" op closeout full-op >/dev/null
  env "$V=$root" "$bin" op audit-packet full-op >/dev/null
  env "$V=$root" "$bin" op archive-packet full-op >/dev/null
}
( cd "$SH" && scenario LAB_ROOT "$SH/tools/atlas/bin/atlas" "$SH" )
( cd "$GO" && scenario LCOAT_ROOT "$lcoat" "$GO" )

fail=0
norm() { sed -e "s#$1#ROOT#g" -e 's/[0-9a-f]\{64\}/HASH/g' "$2"; }

echo "== state file structural diff (root + sha normalized) =="
while IFS= read -r rel; do
  sf="$SH/$rel"; gf="$GO/$rel"
  if [ ! -f "$gf" ]; then echo "  MISSING in go: $rel"; fail=1; continue; fi
  if diff <(norm "$SH" "$sf") <(norm "$GO" "$gf") >/dev/null 2>&1; then
    echo "  ok   $rel"
  else
    echo "  DIFF $rel"; fail=1
  fi
done < <(cd "$SH" && find sessions targets reports -type f | sort)

echo "== shell verifiers on Go packets =="
for v in verify audit-verify archive-verify; do
  s=$(LAB_ROOT="$GO" "$GO/tools/atlas/bin/atlas" op "$v" full-op 2>&1 | awk -F': ' '$1=="Verification Status"{print $2}')
  echo "  op $v -> $s"; [ "$s" = verified ] || fail=1
done

echo "== Go verifiers on shell packets =="
for v in verify audit-verify archive-verify; do
  s=$(LCOAT_ROOT="$SH" "$lcoat" op "$v" full-op 2>&1 | awk -F': ' '$1=="Verification Status"{print $2}')
  echo "  op $v -> $s"; [ "$s" = verified ] || fail=1
done

if [ "$fail" -eq 0 ]; then echo "CONFORMANCE OK"; else echo "CONFORMANCE FAILED"; fi
exit "$fail"
