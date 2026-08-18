import os
import base64
import hashlib
import json
import secrets
import struct
import sys

b64 = lambda b: base64.b64encode(b).decode()
sha256hex = lambda b: hashlib.sha256(b).hexdigest()

# ---------------- Ed25519 (RFC 8032, pure python) ----------------
_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)

def _inv(x):
    return pow(x, _P - 2, _P)

def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P != 0:
        x = (x * _I) % _P
    if (x * x - xx) % _P != 0:
        raise ValueError("point decompression failed")
    if x % 2 != 0:
        x = _P - x
    return x

_BY = (4 * _inv(5)) % _P
_BX = _xrecover(_BY)
_B = (_BX, _BY, 1, (_BX * _BY) % _P)      # extended homogeneous coordinates
_IDENT = (0, 1, 1, 0)

def _pt_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % _P
    b = (y1 + x1) * (y2 + x2) % _P
    c = 2 * t1 * t2 * _D % _P
    d = 2 * z1 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)

def _pt_mul(p, e):
    q = _IDENT
    while e:
        if e & 1:
            q = _pt_add(q, p)
        p = _pt_add(p, p)
        e >>= 1
    return q

def _pt_compress(p):
    x, y, z, _ = p
    zi = _inv(z)
    x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")

def _pt_decompress(s):
    n = int.from_bytes(s, "little")
    y = n & ((1 << 255) - 1)
    if y >= _P:
        raise ValueError("bad point encoding")
    x = _xrecover(y)
    if x & 1 != (n >> 255):
        x = _P - x
    return (x, y, 1, (x * y) % _P)

def _pt_equal(p, q):
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % _P == 0 and (y1 * z2 - y2 * z1) % _P == 0

def _sha512(b):
    return hashlib.sha512(b).digest()

class Ed25519PrivateKey:
    """RFC 8032 Ed25519 signer over a 32-byte seed. sign() self-verifies."""

    def __init__(self, seed):
        if len(seed) != 32:
            raise ValueError("seed must be 32 bytes")
        h = _sha512(seed)
        a = int.from_bytes(h[:32], "little")
        a &= (1 << 254) - 8
        a |= 1 << 254
        self._a = a
        self._prefix = h[32:]
        self._pub = _pt_compress(_pt_mul(_B, a))

    @classmethod
    def generate(cls):
        return cls(secrets.token_bytes(32))

    def public_bytes_raw(self):
        return self._pub

    def sign(self, msg):
        r = int.from_bytes(_sha512(self._prefix + msg), "little") % _L
        rp = _pt_compress(_pt_mul(_B, r))
        k = int.from_bytes(_sha512(rp + self._pub + msg), "little") % _L
        s = (r + k * self._a) % _L
        sig = rp + s.to_bytes(32, "little")
        if not ed25519_verify(self._pub, sig, msg):   # fail closed at the source
            raise RuntimeError("self-verification of a fresh signature failed")
        return sig

def ed25519_verify(pub, sig, msg):
    """RFC 8032 verification: [8s]B == [8]R + [8k]A (cofactored)."""
    if len(sig) != 64 or len(pub) != 32:
        return False
    try:
        a = _pt_decompress(pub)
        r = _pt_decompress(sig[:32])
    except ValueError:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= _L:
        return False
    k = int.from_bytes(_sha512(sig[:32] + pub + msg), "little") % _L
    lhs = _pt_mul(_B, 8 * s)
    rhs = _pt_add(_pt_mul(r, 8), _pt_mul(a, 8 * k))
    return _pt_equal(lhs, rhs)

# ---------------- canonical JSON (RFC 8785 on a guarded domain) ----------------

def _leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()

def _node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()

def _split_point(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k

def merkle_tree_hash(leaves):
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return _leaf_hash(leaves[0])
    k = _split_point(n)
    return _node_hash(merkle_tree_hash(leaves[:k]), merkle_tree_hash(leaves[k:]))

def inclusion_proof(leaves, index):
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError("index out of range")
    if n == 1:
        return []
    k = _split_point(n)
    if index < k:
        return inclusion_proof(leaves[:k], index) + [merkle_tree_hash(leaves[k:])]
    return inclusion_proof(leaves[k:], index - k) + [merkle_tree_hash(leaves[:k])]

def consistency_proof(leaves, first):
    if not 0 < first <= len(leaves):
        raise ValueError("require 0 < first <= len(leaves)")
    return _subproof(first, leaves, True)

def _subproof(m, leaves, b):
    n = len(leaves)
    if m == n:
        return [] if b else [merkle_tree_hash(leaves)]
    k = _split_point(n)
    if m <= k:
        return _subproof(m, leaves[:k], b) + [merkle_tree_hash(leaves[k:])]
    return _subproof(m - k, leaves[k:], False) + [merkle_tree_hash(leaves[:k])]

# ---------------- C2SP tlog-checkpoint / tlog-cosignature framing ----------------
_EM_DASH = "—"
_LOG_ALG = 0x01          # Ed25519 log signature
_COSIG_ALG = 0x04        # Ed25519 cosignature/v1 (domain-separated from 0x01)



def prefix_roots(leaves, wanted):
    """MTH(leaves[:n]) for every n in `wanted`, in one pass over the leaves.

    Recomputing merkle_tree_hash for each of ~660 anchored sizes separately is
    O(sizes x n). Instead carry the perfect subtrees on a stack as leaves are
    appended; the root at size n is those subtrees folded right to left, which
    is the same value the split-point recursion produces."""
    wanted = set(wanted)
    out = {}
    if 0 in wanted:
        out[0] = hashlib.sha256(b"").digest()
    stack = []                                  # [(width, hash)], left to right
    for i, leaf in enumerate(leaves, 1):
        node = (1, _leaf_hash(leaf))
        while stack and stack[-1][0] == node[0]:
            left = stack.pop()
            node = (left[0] * 2, _node_hash(left[1], node[1]))
        stack.append(node)
        if i in wanted:
            h = stack[-1][1]
            for j in range(len(stack) - 2, -1, -1):
                h = _node_hash(stack[j][1], h)
            out[i] = h
    return out


# ---------------------------------------------------------------- verifier

def _read(p):
    return open(os.path.join(HERE, p), "rb").read()


HERE = os.path.dirname(os.path.abspath(__file__))


def crlf_files(names):
    """Files whose bytes carry a carriage return. Everything here is covered by
    a signature, so a \\r added in transport changes what is being verified."""
    out = []
    for n in names:
        try:
            if b"\r" in _read(n):
                out.append(n)
        except OSError:
            continue
    return out


def show(s):
    """repr, not the bare string: a trailing \\r makes two different values
    render identically in a terminal, so 'computed X / expected X' would be
    printed for a genuine mismatch."""
    return repr(s)


def parse_checkpoint(text):
    lines = text.split("\n")
    origin, size, root = lines[0], int(lines[1]), lines[2]
    sigs = [l for l in lines if l.startswith("\u2014 ")]
    return origin, size, root, sigs


def _add_vkey(out, v):
    # name+keyid+base64(alg||key): split from the LEFT, because base64 itself
    # contains "+" and splitting from the right shreds the key
    parts = v.strip().split("+", 2)
    if len(parts) < 3:
        return
    name = parts[0]
    b = parts[2]
    try:
        blob = base64.b64decode(b + "=" * (-len(b) % 4))
    except Exception:
        return
    out.setdefault(name, []).append(blob)


def load_keys():
    """c2sp vkeys: name+keyid+base64(alg||pubkey). Witness keys plus the log's
    own key, since a bundle that cannot check the log signature is not
    self-contained."""
    out = {}
    try:
        d = json.loads(_read("witness_keys.json").decode())
        for e in d.get("keys", []):
            _add_vkey(out, e.get("vkey", ""))
    except Exception:
        pass
    try:
        _add_vkey(out, _read("log_vkey.txt").decode())
    except Exception:
        pass
    return out


def sig_ok(body, sig_line, keys):
    """Two shapes appear in a witnessed checkpoint. 68 bytes is a 4-byte key
    hash plus a 64-byte signature over the note body. 76 bytes is a key hash,
    an 8-byte big-endian timestamp, and a signature over the C2SP
    cosignature/v1 framing."""
    parts = sig_line.split(" ", 2)
    if len(parts) < 3:
        return False
    name = parts[1]
    try:
        blob = base64.b64decode(parts[2])
    except Exception:
        return False
    for kb in keys.get(name, []):
        pub = kb[1:] if len(kb) == 33 else kb
        if len(pub) != 32:
            continue
        if len(blob) == 68:
            msg, sig = body, blob[4:]
        elif len(blob) == 76:
            ts = int.from_bytes(blob[4:12], "big")
            msg = "cosignature/v1" + chr(10) + "time " + str(ts) + chr(10) + body
            sig = blob[12:]
        else:
            continue
        try:
            if ed25519_verify(pub, sig, msg.encode()):
                return True
        except Exception:
            continue
    return False


def _elide(items, n=5):
    more = " (+%d more)" % (len(items) - n) if len(items) > n else ""
    return ", ".join(items[:n]) + more


_ML_DSA_44_COSIG = 2432          # 4-byte key id + 8-byte timestamp + 2420-byte sig


def classify(sigs, origin, body, keys):
    """Sort a checkpoint's signature lines into what they are worth.

    The log signing its own checkpoint proves the operator held the key. It is
    not evidence against the operator, so it can never count toward a quorum --
    a single-signer log can keep two sets of books, one tree for you and a
    different one for whoever checks later, and sign both. Only signatures from
    parties who are not the log make the books singular.

    Returns (log_verified, independent_verified, failed, unverifiable, malformed).
    A line is 'unverifiable' only at exactly the ML-DSA-44 cosignature length;
    anything else off-shape is malformed and fails. Classifying by length alone
    would let an attacker retire an inconvenient signature by padding it a byte."""
    log_ok, independent, failed, unverifiable, malformed = 0, [], [], [], []
    for line in sigs:
        parts = line.split(" ", 2)
        name = parts[1] if len(parts) > 2 else "?"
        try:
            blen = len(base64.b64decode(parts[2]))
        except Exception:
            blen = -1
        if blen == _ML_DSA_44_COSIG:
            unverifiable.append(name)
            continue
        if blen not in (68, 76):
            malformed.append("%s (%d bytes, not a signature shape this tool knows)"
                             % (name, blen))
            continue
        if not sig_ok(body, line, keys):
            failed.append(name)
        elif name == origin:
            log_ok += 1
        else:
            independent.append(name)
    return log_ok, independent, failed, unverifiable, malformed


def stated_quorum():
    """The witness quorum this log published for itself. A bundle that states no
    policy cannot be checked against one, so its absence is a failure rather
    than a default."""
    try:
        d = json.loads(_read("trust-root.json").decode())
        q = int(d["witness_quorum"])
        return q if q > 0 else None
    except Exception:
        return None


def check_anchored_history(leaves, keys):
    """Every anchored checkpoint must be a prefix of *these* leaves.

    Without this the bundle proves only that the final head is well formed --
    a snapshot. Checking each anchored checkpoint's root against the prefix
    root at its own stated size ties the whole anchored history to these
    bytes, which is what makes it a terminal export."""
    d = os.path.join(HERE, "anchors")
    if not os.path.isdir(d):
        print("FAIL anchors/ missing: no anchored history to check")
        return False

    names = sorted((f for f in os.listdir(d) if f.endswith(".checkpoint")),
                   key=lambda f: int(f.split(".")[0]))
    if not names:
        print("FAIL anchors/ contains no checkpoints")
        return False

    parsed, bad = [], []
    for f in names:
        try:
            text = open(os.path.join(d, f), "rb").read().decode()
            o, n, r, ss = parse_checkpoint(text)
        except Exception as e:
            bad.append("%s unreadable (%s)" % (f, e))
            continue
        if n != int(f.split(".")[0]):
            bad.append("%s states size %d" % (f, n))
            continue
        if n > len(leaves):
            bad.append("%s size %d exceeds the exported %d leaves"
                       % (f, n, len(leaves)))
            continue
        parsed.append((f, o, n, r, ss, text))

    roots = prefix_roots(leaves, [p[2] for p in parsed])
    unstamped, unsigned, forked = [], [], []
    witnessed = {}                       # size -> independent cosignatures verified
    for f, o, n, r, ss, text in parsed:
        if base64.b64encode(roots[n]).decode() != r:
            forked.append("%s root %s != prefix root %s"
                          % (f, show(r), show(base64.b64encode(roots[n]).decode())))
        body = chr(10).join(text.split(chr(10))[:3]) + chr(10)
        _, ind, _, _, _ = classify(ss, o, body, keys)
        witnessed[n] = len(ind)
        if not any(sig_ok(body, l, keys) for l in ss
                   if l.split(" ", 2)[1:2] == [o]):
            unsigned.append(f)
        if not os.path.exists(os.path.join(d, f + ".ots")):
            unstamped.append(f)

    # Witnessing started partway through this log's life, so the earliest
    # anchors carry no cosignatures. That is a fact about the history, not a
    # defect, but it has to be stated rather than passed over: below the first
    # witnessed size the anchor rests on the operator's signature alone.
    quorum = stated_quorum()
    met = sorted(n for n, c in witnessed.items() if quorum and c >= quorum)
    first_witnessed = met[0] if met else None
    short = sorted(n for n, c in witnessed.items()
                   if first_witnessed is not None and n >= first_witnessed
                   and c < quorum)

    print("anchored checkpoints: %d" % len(names))
    for line in bad + forked:
        print("  FAIL  %s" % line)
    if unsigned:
        print("  FAIL  no verifying log signature: %s" % _elide(unsigned))
    if quorum is None:
        print("  FAIL  trust-root.json states no witness quorum, so the "
              "cosignatures on these anchors cannot be judged against a policy")
    elif first_witnessed is None:
        print("  FAIL  not one of these %d anchored checkpoints carries the "
              "stated quorum of %d independent cosignatures; the whole anchored "
              "history rests on the log's own key" % (len(names), quorum))
    elif short:
        print("  FAIL  %d anchor(s) at or above size %d carry fewer than the "
              "stated quorum of %d independent cosignatures: %s"
              % (len(short), first_witnessed, quorum,
                 _elide(["%d (%d)" % (n, witnessed[n]) for n in short])))
    ok = (not (bad or forked or unsigned or short)
          and quorum is not None and first_witnessed is not None)
    if ok:
        print("  PASS  each equals the prefix root of these leaves at its stated"
              " size, under a verifying log signature")
        unwitnessed = sorted(n for n in witnessed if n < first_witnessed)
        if unwitnessed:
            print("  PASS  %d of %d carry %d or more independent cosignatures; "
                  "the %d below size %d predate witnessing and rest on the log's "
                  "own signature alone"
                  % (len(names) - len(unwitnessed), len(names), quorum,
                     len(unwitnessed), first_witnessed))
        else:
            print("  PASS  all %d carry %d or more independent cosignatures"
                  % (len(names), quorum))
    if unstamped:
        # Presence of an .ots is all this tool checks -- verifying an
        # OpenTimestamps attestation needs Bitcoin headers and a network, and
        # this verifier has neither. See does_not_prove in manifest.json.
        print("  note  %d without an OpenTimestamps proof file: %s"
              % (len(unstamped), _elide(unstamped)))
    return ok


def main():
    ok = True

    bad_eol = crlf_files(["checkpoint.txt", "leaves.jsonl", "log_vkey.txt",
                          "witness_keys.json"])
    if bad_eol:
        print("FAIL carriage returns in: %s" % ", ".join(bad_eol))
        print("     These bytes are covered by a signature, so a \\r inserted in")
        print("     transport changes what is verified and every check below will")
        print("     fail for that reason and no other. Git for Windows defaults to")
        print("     core.autocrlf=true; this export ships a .gitattributes with")
        print("     '* -text' to prevent it, so a clone predating that file is the")
        print("     likely cause. Re-clone, or run:")
        print("       git -c core.autocrlf=false clone <url>")
        ok = False

    ck = _read("checkpoint.txt").decode()
    origin, size, root_b64, sigs = parse_checkpoint(ck)
    print("checkpoint: origin=%s size=%d" % (origin, size))
    print("signature lines: %d" % len(sigs))

    leaves = []
    for line in _read("leaves.jsonl").decode().splitlines():
        if line.strip():
            r = json.loads(line)
            leaves.append(base64.b64decode(r["data_b64"]))
    print("leaves in export: %d" % len(leaves))

    if len(leaves) != size:
        print("FAIL leaf count %d != checkpoint size %d" % (len(leaves), size))
        ok = False

    computed = merkle_tree_hash(leaves)
    computed_b64 = base64.b64encode(computed).decode()
    if computed_b64 == root_b64:
        print("PASS recomputed root matches the checkpoint root")
    else:
        print("FAIL root mismatch\n  computed   %s\n  checkpoint %s"
              % (show(computed_b64), show(root_b64)))
        if computed_b64 == root_b64.strip():
            print("     The two differ only in surrounding whitespace, so the file")
            print("     was rewritten in transport rather than the tree being wrong.")
        ok = False

    body = chr(10).join(ck.split(chr(10))[:3]) + chr(10)
    keys = load_keys()
    quorum = stated_quorum()
    log_ok, independent, failed, unverifiable, malformed = classify(
        sigs, origin, body, keys)

    for name in independent:
        print("  PASS  %-52s independent witness" % name[:52])
    if log_ok:
        print("  PASS  %-52s the log's own key" % origin[:52])
    for name in failed:
        print("  FAIL  %-52s no bundled key verifies it" % name[:52])
    for item in malformed:
        print("  FAIL  %s" % item)
    for name in unverifiable:
        print("  ----  %-52s ML-DSA-44, no key for it in this bundle"
              % name[:52])

    # The count that matters is the independent one. The log's own signature is
    # reported separately and never added to it: it says the operator held the
    # key, which is not evidence about the operator.
    print("log signature: %s" % ("verifies" if log_ok else "MISSING"))
    print("independent witness cosignatures verified: %d (quorum %s)"
          % (len(independent), quorum if quorum is not None else "UNSTATED"))
    if unverifiable:
        print("post-quantum lines present but uncheckable here: %d "
              "(no ML-DSA-44 verifier and no key for them in this bundle)"
              % len(unverifiable))

    if failed or malformed:
        ok = False
    if not log_ok:
        print("FAIL the log's own signature over this checkpoint does not verify")
        ok = False
    if quorum is None:
        print("FAIL trust-root.json states no witness quorum, so this "
              "checkpoint cannot be judged against a policy")
        ok = False
    elif len(independent) < quorum:
        print("FAIL %d independent cosignature(s), below the stated quorum of %d."
              % (len(independent), quorum))
        print("     Without a quorum this bundle shows only that whoever held "
              "the log key signed these bytes. A single-signer log can keep two")
        print("     sets of books and sign both; independent witnesses are what "
              "make the books singular.")
        ok = False

    # spot-check an inclusion proof against the frozen tree
    if leaves:
        i = min(len(leaves) - 1, 6907)
        proof = inclusion_proof(leaves, i)
        h = _leaf_hash(leaves[i])
        fn, sn = i, len(leaves) - 1
        for p in proof:
            if fn == sn or fn % 2 == 1:
                h = _node_hash(p, h)
                while fn % 2 == 0 and fn != 0:
                    fn //= 2
                    sn //= 2
            else:
                h = _node_hash(h, p)
            fn //= 2
            sn //= 2
        print("inclusion proof for leaf %d: %s"
              % (i, "PASS" if h == computed else "FAIL"))
        ok = ok and h == computed

    ok = check_anchored_history(leaves, keys) and ok

    print("\n%s" % ("EXPORT VERIFIES" if ok else "EXPORT FAILED"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
