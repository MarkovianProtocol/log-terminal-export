#!/bin/sh
# Carry every OpenTimestamps proof in this export from a calendar commitment to
# a Bitcoin attestation, and keep SHA256SUMS.ots consistent with SHA256SUMS.
#
# Two things make this fiddly enough to be worth a script.
#
# `ots upgrade` writes its result by first moving the old proof aside to
# <file>.bak, and it aborts if that .bak already exists. A leftover .bak from an
# earlier run therefore makes every subsequent upgrade fail *after* it has
# already fetched the Bitcoin attestation from the calendars: the proof is
# downloaded and then discarded. That happened 28 times in ots_upgrade.log and
# is why the shipped manifest carried three pending calendar commitments and no
# Bitcoin attestation.
#
# And the order is circular unless you break it deliberately. Upgrading an
# anchor proof changes that .ots file's bytes; anchors/*.ots are listed in
# SHA256SUMS; SHA256SUMS.ots commits to SHA256SUMS. So maturing an anchor
# invalidates the manifest proof and resets its clock -- which is exactly how
# the manifest stayed pending across four refreshes. It terminates only because
# SHA256SUMS.ots is itself excluded from SHA256SUMS (see make_sha256sums.py):
# upgrading the manifest proof changes nothing the manifest covers.
#
# Hence two phases, never interleaved:
#   A  mature the anchor proofs; if any moved, regenerate SHA256SUMS and
#      re-stamp the manifest, accepting that its clock restarts.
#   B  once no anchor moved, upgrade the manifest proof alone. Fixed point.
#
#   ./stamp_manifest.sh refresh   run both phases; this is the scheduled job
#   ./stamp_manifest.sh stamp     re-stamp the manifest over the current bytes
#   ./stamp_manifest.sh upgrade   phase B alone
#   ./stamp_manifest.sh check     what the proofs actually carry right now
#
set -eu
cd "$(dirname "$0")"

BITCOIN=0588960d73d71901
PENDING=83dfe30d2ef90c8e

has_bitcoin() {
    python3 -c "import sys;sys.exit(0 if bytes.fromhex('$BITCOIN') in open(sys.argv[1],'rb').read() else 1)" "$1"
}

case "${1:-check}" in
stamp)
    [ -f SHA256SUMS ] || { echo "no SHA256SUMS; run make_sha256sums.py first" >&2; exit 1; }
    rm -f SHA256SUMS.ots SHA256SUMS.ots.bak
    ots stamp SHA256SUMS
    echo "manifest stamped; pending until a calendar aggregates into a block"
    ;;
upgrade)
    rm -f SHA256SUMS.ots.bak          # the collision that silently ate 27 attestations
    ots upgrade SHA256SUMS.ots || true
    rm -f SHA256SUMS.ots.bak          # leave nothing behind to block the next run
    "$0" check
    ;;
refresh)
    # A manifest already stale on entry (a file added or a proof matured outside
    # this script) has to go down the phase-A branch too, or the new bytes never
    # get listed and the stamp covers the wrong set.
    if python3 make_sha256sums.py --check >/dev/null; then changed=0; else changed=1; fi

    # any checkpoint that was never stamped at all
    for c in anchors/*.checkpoint; do
        [ -f "$c.ots" ] && continue
        ots stamp "$c" && changed=1
    done

    # phase A: mature the anchor proofs that are still calendar-only
    for f in anchors/*.checkpoint.ots; do
        has_bitcoin "$f" && continue
        rm -f "$f.bak"
        cp "$f" "$f.before"
        ots upgrade "$f" || true
        rm -f "$f.bak"
        cmp -s "$f" "$f.before" || { changed=1; echo "anchored: $f"; }
        rm -f "$f.before"
    done

    if [ "$changed" = 1 ]; then
        # An anchor moved, so the manifest it is listed in is stale. Restamp.
        python3 make_sha256sums.py
        "$0" stamp
    else
        # Nothing the manifest covers changed: safe to mature the manifest.
        "$0" upgrade
    fi
    "$0" check
    ;;
check)
    python3 - <<PY
import glob, hashlib
B = bytes.fromhex("$BITCOIN")
P = bytes.fromhex("$PENDING")
pend = [f for f in sorted(glob.glob("anchors/*.ots")) if B not in open(f, "rb").read()]
missing = [c for c in sorted(glob.glob("anchors/*.checkpoint")) if not glob.glob(c + ".ots")]
total = len(glob.glob("anchors/*.checkpoint"))
print("anchor proofs: %d of %d carry a Bitcoin attestation" % (total - len(pend) - len(missing), total))
if pend:
    print("  pending: %s" % ", ".join(pend[:5]))
if missing:
    print("  unstamped: %s" % ", ".join(missing[:5]))
b = open("SHA256SUMS.ots", "rb").read()
print("SHA256SUMS.ots: %d pending calendar commitment(s), %d Bitcoin attestation(s)"
      % (b.count(P), b.count(B)))
digest = hashlib.sha256(open("SHA256SUMS", "rb").read()).digest()
print("  commits to the SHA256SUMS in this tree: %s" % (digest in b))
if not b.count(B):
    print("  NOT YET ANCHORED -- the scheduled refresh will carry it")
PY
    ;;
*)
    echo "usage: $0 refresh|stamp|upgrade|check" >&2; exit 2 ;;
esac
