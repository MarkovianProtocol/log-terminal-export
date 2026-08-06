# Terminal export — markovianprotocol.com/log

This is everything needed to verify any receipt this log ever issued, after the
log stops existing.

A receipt says: *these bytes sit at index N of a tree whose head is X, signed by
this log key.* Checking it later needs three things — the leaf data, the tree,
and the key. Normally all three live on one machine. When that machine goes away,
a receipt holder is left with a signature over a root hash and nothing to compare
it against.

None of the standards cover this. RFC 9943 puts key discovery (§6) and revocation
(§9.4.2) out of scope; RFC 9942 puts receipt validity periods (§7.2) and receipt
status (§7.3) out of scope. There is no specified way for a transparency service
to end.

This bundle is our answer: the log's ending is a published, verifiable artifact
rather than an absence.

## What is here

| file | what it is |
|---|---|
| `leaves.jsonl` | every leaf, raw bytes, base64, in index order |
| `checkpoint.txt` | the final signed checkpoint with all cosignatures |
| `log_vkey.txt` | this log's own verifier key |
| `witness_keys.json` | the pinned keys of the independent witnesses |
| `anchors/` | 584 anchored checkpoints with their OpenTimestamps proofs |
| `trust-root.json` | the signed trust-root manifest |
| `manifest.json` | tree size, final root, and the claim boundary |
| `SHA256SUMS` | digest of every file above |
| `SHA256SUMS.ots` | Bitcoin timestamp over that digest |
| `verify_export.py` | offline verifier, Python standard library only |

## Verifying

    python3 verify_export.py

No network, no dependencies, no installation. It recomputes the RFC 6962 tree
from the leaves, compares the result to the final checkpoint root, checks every
Ed25519 signature on that checkpoint against the bundled keys, and recomputes an
inclusion proof against the frozen tree.

At the time of export it reported: tree size 7,123; recomputed root matching the
checkpoint; 8 of 8 checkable Ed25519 signatures verifying — this log plus seven
independent witnesses; 3 post-quantum ML-DSA cosignatures reported as skipped
rather than silently ignored.

To check that the bundle itself has not been altered:

    shasum -a 256 -c SHA256SUMS
    ots verify SHA256SUMS.ots

## Wind-down policy

If this log ceases operation, we commit to the following, in this order.

1. Stop accepting appends, and publish a final checkpoint with whatever witness
   cosignatures are obtainable at that time.
2. Produce this bundle at that final tree size.
3. Anchor the bundle's `SHA256SUMS` digest to Bitcoin via OpenTimestamps, so the
   ending carries a timestamp that does not depend on us.
4. Publish the bundle in at least one location outside our own infrastructure,
   and state where. Hosting the record of our death on our own server would
   defeat the point.
5. Leave this repository in place as the pointer.

A log that simply stops leaves every receipt it issued in an ambiguous state
forever. A log that ends this way leaves them checkable.

## What this proves, and what it does not

It proves that these leaf bytes in this order produce the final root; that the
log key signed that root at that size; that the named witnesses cosigned the same
root; and that any receipt naming an index within the final tree size can be
rechecked against this frozen tree.

It does not prove the recorded claims are true. It does not prove the log was
complete — nothing here shows what was never submitted. And it does not establish
that this key belonged to any particular operator: key-to-identity binding is a
social fact, and this bundle freezes the evidence for it rather than creating it.
Certificate Transparency survives its retired logs only because browsers keep
shipping the old log keys; a small operator has no equivalent distribution
channel, and we are not pretending otherwise.

The idea for a terminal export came from RACK Protocol, raised in
[c2pa-org/specifications#122](https://github.com/c2pa-org/specifications/issues/122).

Apache-2.0.
