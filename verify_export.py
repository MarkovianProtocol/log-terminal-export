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



# ---------------------------------------------------------------- verifier

def _read(p):
    return open(os.path.join(HERE, p), "rb").read()


HERE = os.path.dirname(os.path.abspath(__file__))


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


def main():
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

    ok = True
    if len(leaves) != size:
        print("FAIL leaf count %d != checkpoint size %d" % (len(leaves), size))
        ok = False

    computed = merkle_tree_hash(leaves)
    computed_b64 = base64.b64encode(computed).decode()
    if computed_b64 == root_b64:
        print("PASS recomputed root matches the checkpoint root")
    else:
        print("FAIL root mismatch\n  computed %s\n  checkpoint %s"
              % (computed_b64, root_b64))
        ok = False

    body = chr(10).join(ck.split(chr(10))[:3]) + chr(10)
    keys = load_keys()
    ed, pq, failed = 0, 0, []
    for line in sigs:
        parts = line.split(" ", 2)
        name = parts[1] if len(parts) > 1 else "?"
        try:
            blen = len(base64.b64decode(parts[2]))
        except Exception:
            blen = 0
        if blen not in (68, 76):
            pq += 1
            print("  skip  %-50s post-quantum cosignature (%d bytes)" % (name[:50], blen))
            continue
        if sig_ok(body, line, keys):
            ed += 1
            print("  PASS  %s" % name[:60])
        else:
            failed.append(name)
            print("  FAIL  %-50s no bundled key verifies it" % name[:50])
    print("Ed25519 signatures verified: %d of %d checkable (%d post-quantum skipped)"
          % (ed, ed + len(failed), pq))
    if ed == 0:
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

    print("\n%s" % ("EXPORT VERIFIES" if ok else "EXPORT FAILED"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
