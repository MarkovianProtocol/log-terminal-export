#!/bin/sh
# Timestamp SHA256SUMS to Bitcoin via OpenTimestamps.
#
# Why this is a script and not two commands typed by hand: `ots upgrade` writes
# its result by first moving the old proof to SHA256SUMS.ots.bak, and it aborts
# if that .bak already exists. A leftover .bak from an earlier refresh therefore
# makes every subsequent upgrade fail *after* it has already fetched the Bitcoin
# attestation from the calendars -- the proof is downloaded and then discarded.
# That happened 28 times in ots_upgrade.log and is why the shipped manifest
# carried three pending calendar commitments and no Bitcoin attestation.
#
# Order matters. SHA256SUMS.ots commits to specific SHA256SUMS bytes, so the
# stamp must come after make_sha256sums.py, never before.
#
#   ./stamp_manifest.sh stamp     right after regenerating SHA256SUMS
#   ./stamp_manifest.sh upgrade   a few hours later, until it reports Bitcoin
#   ./stamp_manifest.sh check     what the current proof actually carries
#
set -eu
cd "$(dirname "$0")"

case "${1:-check}" in
stamp)
    [ -f SHA256SUMS ] || { echo "no SHA256SUMS; run make_sha256sums.py first" >&2; exit 1; }
    rm -f SHA256SUMS.ots SHA256SUMS.ots.bak
    ots stamp SHA256SUMS
    echo "stamped. Pending until a calendar aggregates into a block; run 'upgrade' later."
    ;;
upgrade)
    # Deliberately not logged to a file inside the export. ots_upgrade.log is
    # listed in SHA256SUMS, so appending to it during an upgrade would change
    # the very bytes the proof being upgraded commits to.
    rm -f SHA256SUMS.ots.bak          # the collision that silently ate 27 attestations
    ots upgrade SHA256SUMS.ots
    rm -f SHA256SUMS.ots.bak          # leave nothing behind to block the next run
    "$0" check
    ;;
check)
    python3 - <<'PY'
b = open("SHA256SUMS.ots", "rb").read()
pending = b.count(bytes.fromhex("83dfe30d2ef90c8e"))
bitcoin = b.count(bytes.fromhex("0588960d73d71901"))
import hashlib
digest = hashlib.sha256(open("SHA256SUMS", "rb").read()).digest()
print("SHA256SUMS.ots: %d pending calendar commitment(s), %d Bitcoin attestation(s)"
      % (pending, bitcoin))
print("commits to the SHA256SUMS in this tree: %s" % (digest in b))
if not bitcoin:
    print("NOT YET ANCHORED -- rerun './stamp_manifest.sh upgrade' later")
PY
    ;;
*)
    echo "usage: $0 stamp|upgrade|check" >&2; exit 2 ;;
esac
