"""Regenerate SHA256SUMS.

Two files are deliberately not listed: SHA256SUMS.ots and its .bak. Their bytes
are derived from SHA256SUMS and change every time the OpenTimestamps proof is
upgraded from a calendar commitment to a Bitcoin attestation, so listing them
makes the manifest disagree with itself the moment the proof matures -- a fresh
clone then fails one line out of the whole set for no reason a reader can act
on. Everything an offline verifier reads is listed; the timestamp over the
manifest is checked with `ots verify SHA256SUMS.ots`, not with sha256sum.

Output is sorted by path so a refresh produces a reviewable diff.

    python3 make_sha256sums.py          # write SHA256SUMS
    python3 make_sha256sums.py --check  # exit 1 if the file on disk is stale
"""
import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SELF_REFERENTIAL = {"SHA256SUMS.ots", "SHA256SUMS.ots.bak"}
SKIP_DIRS = {".git"}


def entries():
    for root, dirs, files in os.walk(HERE):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            rel = os.path.relpath(os.path.join(root, f), HERE)
            if rel == "SHA256SUMS" or rel in SELF_REFERENTIAL:
                continue
            h = hashlib.sha256(open(os.path.join(root, f), "rb").read()).hexdigest()
            yield "%s  %s\n" % (h, rel)


def main():
    text = "".join(sorted(entries(), key=lambda l: l.split("  ", 1)[1]))
    path = os.path.join(HERE, "SHA256SUMS")
    if "--check" in sys.argv:
        current = open(path).read() if os.path.exists(path) else ""
        if current == text:
            print("SHA256SUMS up to date (%d files)" % text.count("\n"))
            return 0
        print("SHA256SUMS is stale; run make_sha256sums.py")
        return 1
    open(path, "w").write(text)
    print("wrote %d entries" % text.count("\n"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
