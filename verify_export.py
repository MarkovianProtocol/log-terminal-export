from __future__ import annotations
# --- vendored: filippo.io/mldsa-py (ML-DSA-44 verification, FIPS 204) ---
# Source: https://github.com/FiloSottile/mldsa-py, ISC-style licence:
# permission to use, copy, modify, and/or distribute is granted.
# Vendored verbatim apart from hoisting `from __future__ import annotations`
# to the top of this generated file. Verification only; it cannot sign.
# mldsa-py by Filippo Valsorda is marked CC0 1.0 Universal. To view a copy of
# this mark, visit https://creativecommons.org/publicdomain/zero/1.0/
#
# Alternatively, you may use this source code under the terms of the 0BSD
# license that can be found in the LICENSE file.

"""Pure-Python implementation of ML-DSA (FIPS 204) signature verification."""


import sys
from dataclasses import dataclass
from enum import Enum
from hashlib import shake_128, shake_256
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing_extensions import Buffer, Self, override
elif sys.version_info >= (3, 12):
    from typing import override
else:
    from typing import Any, Callable

    def override(method: Callable[..., Any]) -> Callable[..., Any]:
        return method


__all__ = [
    "InvalidContextError",
    "InvalidVerificationKeyError",
    "ParameterSet",
    "VerificationError",
    "VerificationKey",
]

Q = 8380417
N = 256


@dataclass(frozen=True)
class _Parameters:
    name: str
    verification_key_size: int
    signature_size: int
    k: int
    l: int
    η: int
    γ1: int
    γ2: int
    λ: int
    τ: int
    ω: int


class ParameterSet(Enum):
    """ML-DSA parameter sets as defined in FIPS 204."""

    ML_DSA_44 = _Parameters(name="ML-DSA-44", verification_key_size=1312, signature_size=2420,
        k=4, l=4, η=2, γ1=17, γ2=(Q - 1) // 88, λ=128, τ=39, ω=80)  # fmt: skip
    ML_DSA_65 = _Parameters(name="ML-DSA-65", verification_key_size=1952, signature_size=3309,
        k=6, l=5, η=4, γ1=19, γ2=(Q - 1) // 32, λ=192, τ=49, ω=55)  # fmt: skip
    ML_DSA_87 = _Parameters(name="ML-DSA-87", verification_key_size=2592, signature_size=4627,
        k=8, l=7, η=2, γ1=19, γ2=(Q - 1) // 32, λ=256, τ=60, ω=75)  # fmt: skip

    @property
    def verification_key_size(self) -> int:
        """The encoded verification key size in bytes."""
        return self.value.verification_key_size

    @property
    def signature_size(self) -> int:
        """The signature size in bytes."""
        return self.value.signature_size

    @override
    def __str__(self) -> str:
        """Return the human-readable parameter set name, e.g. ``ML-DSA-44``."""
        return self.value.name

    @override
    def __repr__(self) -> str:
        """Return a concise representation, e.g. ``<ParameterSet.ML_DSA_44>``."""
        return f"<{type(self).__name__}.{self.name}>"


class VerificationError(Exception):
    """Raised when signature verification fails."""


class InvalidVerificationKeyError(ValueError):
    """Raised when a verification key is invalid."""


class InvalidContextError(ValueError):
    """Raised when a context string is invalid."""


class VerificationKey:
    """An ML-DSA verification key."""

    _p: _Parameters

    def __init__(self, pk: Buffer, /, *, parameters: ParameterSet | None = None) -> None:
        """Decode an ML-DSA verification key.

        If *parameters* is ``None``, the parameter set is inferred from
        the length of *pk*.

        Raises:
            InvalidVerificationKeyError: If the key is the wrong size or doesn't
                match the specified parameter set.
        """
        pk = memoryview(pk).cast("B")
        if parameters is None:
            size_to_params = {p.verification_key_size: p for p in ParameterSet}
            if len(pk) not in size_to_params:
                raise InvalidVerificationKeyError(f"unexpected verification key size {len(pk)}")
            parameters = size_to_params[len(pk)]
        self._p = parameters.value

        if len(pk) != self._p.verification_key_size:
            raise InvalidVerificationKeyError(
                f"expected {self._p.verification_key_size} bytes, got {len(pk)}"
            )
        self._enc = bytes(pk)
        self._tr = public_key_hash(pk)
        ρ = bytes(pk[:32])
        pkv = memoryview(pk[32:])

        self._t1: list[NTTPoly] = []  # NTT(t₁ ⋅ 2ᵈ)
        for _ in range(self._p.k):
            self._t1.append(ntt(Poly([F(z.v << 13) for z in unpack(bytes(pkv[:320]), N, 10)])))
            pkv = pkv[320:]

        self._A: list[list[NTTPoly]] = [[] for _ in range(self._p.k)]
        for r in range(self._p.k):
            for s in range(self._p.l):
                self._A[r].append(sample_ntt(ρ, s, r))

    def __bytes__(self) -> bytes:
        """Return the encoded verification key."""
        return self._enc

    @override
    def __repr__(self) -> str:
        """Return a concise representation, e.g. ``<VerificationKey ML-DSA-44>``."""
        return f"<{type(self).__name__} {self._p.name}>"

    @property
    def parameters(self) -> ParameterSet:
        """The parameter set of this key."""
        return ParameterSet(self._p)

    def verify(self, signature: Buffer, message: Buffer, *, context: Buffer = b"") -> None:
        """Verify a signature over *message*.

        Raises:
            VerificationError: If the signature is invalid.
            InvalidContextError: If the context is too long (more than 255 bytes).
        """
        signature = memoryview(signature).cast("B")
        μ = message_hash(self._tr, message, context)

        if len(signature) != self._p.signature_size:
            raise VerificationError(
                f"invalid signature size: expected {self._p.signature_size} bytes, got {len(signature)}"
            )
        ch = bytes(signature[: self._p.λ // 4])
        sigv = memoryview(signature[self._p.λ // 4 :])
        z: list[Poly] = []
        for _ in range(self._p.l):
            length = (self._p.γ1 + 1) * N // 8
            z.append(Poly(unpack_signed(bytes(sigv[:length]), N, self._p.γ1 + 1)))
            sigv = sigv[length:]
        h: list[list[int]] = [[0] * N for _ in range(self._p.k)]
        idx = 0
        for i in range(self._p.k):
            limit = sigv[self._p.ω + i]
            if limit < idx or limit > self._p.ω:
                raise VerificationError("invalid signature encoding")
            first = idx
            while idx < limit:
                if idx > first and sigv[idx - 1] >= sigv[idx]:
                    raise VerificationError("invalid signature encoding")
                h[i][sigv[idx]] = 1
                idx += 1
        for i in range(idx, self._p.ω):
            if sigv[i] != 0:
                raise VerificationError("invalid signature encoding")

        c = ntt(sample_in_ball(ch, self._p))

        z_hat = [ntt(x) for x in z]
        w: list[Poly] = []  # Â ∘ NTT(z) − NTT(c) ∘ NTT(t₁ ⋅ 2ᵈ)
        for i in range(self._p.k):
            w_hat = NTTPoly.zero()
            for j in range(self._p.l):
                w_hat += z_hat[j] * self._A[i][j]
            w_hat -= c * self._t1[i]
            w.append(inverse_ntt(w_hat))

        w1 = [use_hint(w[i], h[i], self._p) for i in range(self._p.k)]

        H = shake_256()
        H.update(μ)
        w1_bit_length = ((Q - 1) // (2 * self._p.γ2) - 1).bit_length()
        for i in range(self._p.k):
            H.update(pack(w1[i], w1_bit_length))
        if H.digest(self._p.λ // 4) != ch:
            raise VerificationError("invalid signature")

        β = self._p.τ * self._p.η
        γ1 = 1 << self._p.γ1
        γ1β = γ1 - β

        for v in z:
            if any(x.infinity_norm() >= γ1β for x in v.cs):
                raise VerificationError("invalid signature")


def public_key_hash(pk: Buffer) -> bytes:
    h = shake_256()
    h.update(pk)
    return h.digest(64)


def message_hash(tr: bytes, m: Buffer, ctx: Buffer) -> bytes:
    ctx = memoryview(ctx).cast("B")
    if len(ctx) > 255:
        raise InvalidContextError(f"expected context of at most 255 bytes, got {len(ctx)}")
    h = shake_256()
    h.update(tr)
    h.update(b"\x00")
    h.update(bytes([len(ctx)]))
    h.update(ctx)
    h.update(m)
    return h.digest(64)


class F:
    __slots__ = ("v",)

    def __init__(self, v: int) -> None:
        assert 0 <= v < Q
        self.v = v

    @classmethod
    def reduce(cls, v: int) -> F:
        return cls(v % Q)

    def __add__(self, other: F) -> F:
        return F.reduce(self.v + other.v)

    def __sub__(self, other: F) -> F:
        return F.reduce(self.v - other.v)

    def __mul__(self, other: F) -> F:
        return F.reduce(self.v * other.v)

    def infinity_norm(self) -> int:
        return self.v if self.v <= Q // 2 else Q - self.v


def centered_mod(v: int, m: int) -> int:
    r = v % m
    if r > m // 2:
        r -= m
    return r


def decompose(r: F, p: _Parameters) -> tuple[int, int]:
    r0 = centered_mod(r.v, 2 * p.γ2)
    if r.v - r0 == Q - 1:
        return 0, r0 - 1
    r1 = (r.v - r0) // (2 * p.γ2)
    return r1, r0


def unpack(buf: bytes, n: int, bit_length: int) -> list[F]:
    assert n * bit_length == len(buf) * 8
    res: list[F] = []
    acc = 0
    acc_len = 0
    for b in buf:
        acc |= b << acc_len
        acc_len += 8
        while acc_len >= bit_length:
            res.append(F(acc & ((1 << bit_length) - 1)))
            acc >>= bit_length
            acc_len -= bit_length
    return res


def unpack_signed(buf: bytes, n: int, bit_length: int) -> list[F]:
    b = F(1 << (bit_length - 1))
    return [b - x for x in unpack(buf, n, bit_length)]


def pack(cs: list[int], bit_length: int) -> bytes:
    acc = 0
    acc_len = 0
    res = bytearray()
    for c in cs:
        acc |= c << acc_len
        acc_len += bit_length
        while acc_len >= 8:
            res.append(acc & 0xFF)
            acc >>= 8
            acc_len -= 8
    if acc_len > 0:
        res.append(acc & 0xFF)
    return bytes(res)


class Poly:
    __slots__ = ("cs",)
    cs: list[F]

    def __init__(self, cs: list[F]) -> None:
        assert len(cs) == N
        self.cs = cs

    def __add__(self, other: Self) -> Self:
        if type(self) is not type(other):
            return NotImplemented
        return type(self)([a + b for a, b in zip(self.cs, other.cs)])

    def __sub__(self, other: Self) -> Self:
        if type(self) is not type(other):
            return NotImplemented
        return type(self)([a - b for a, b in zip(self.cs, other.cs)])


class NTTPoly:
    __slots__ = ("cs",)
    cs: list[int]  # don't use F to avoid function call overhead in hot loops

    def __init__(self, cs: list[int]) -> None:
        assert len(cs) == N
        self.cs = cs

    @classmethod
    def zero(cls) -> Self:
        return cls([0 for _ in range(N)])

    def __iadd__(self, other: Self) -> Self:
        if type(self) is not type(other):
            return NotImplemented
        for i in range(N):
            self.cs[i] = (self.cs[i] + other.cs[i]) % Q
        return self

    def __isub__(self, other: Self) -> Self:
        if type(self) is not type(other):
            return NotImplemented
        for i in range(N):
            self.cs[i] = (self.cs[i] - other.cs[i]) % Q
        return self

    def __mul__(self, other: NTTPoly) -> NTTPoly:
        if type(self) is not type(other):
            return NotImplemented
        return NTTPoly([a * b % Q for a, b in zip(self.cs, other.cs)])


def ntt(f: Poly) -> NTTPoly:
    m = 0
    w = [c.v for c in f.cs]
    for len in [128, 64, 32, 16, 8, 4, 2, 1]:
        for start in range(0, N, 2 * len):
            m += 1
            zeta = ZETAS[m]
            for j in range(start, start + len):
                t = zeta * w[j + len] % Q
                w[j + len] = (w[j] - t) % Q
                w[j] = (w[j] + t) % Q
    return NTTPoly(w)


def inverse_ntt(f: NTTPoly) -> Poly:
    m = 255
    w = [c for c in f.cs]
    for len in [1, 2, 4, 8, 16, 32, 64, 128]:
        for start in range(0, N, 2 * len):
            zeta = ZETAS[m]
            m -= 1
            for j in range(start, start + len):
                t = w[j]
                w[j] = (t + w[j + len]) % Q
                w[j + len] = zeta * (w[j + len] - t) % Q
    return Poly([F(v * 8347681 % Q) for v in w])


def sample_ntt(ρ: bytes, s: int, r: int) -> NTTPoly:
    G = shake_128()
    G.update(ρ)
    G.update(bytes([s, r]))
    buf = G.digest(894)

    a: list[int] = []
    while len(a) < N:
        v = int.from_bytes(buf[:3], "little") & 0x7FFFFF
        buf = buf[3:]
        if v < Q:
            a.append(v)
    return NTTPoly(a)


def sample_in_ball(rho: bytes, p: _Parameters) -> Poly:
    G = shake_256()
    G.update(rho)
    buf = G.digest(221)
    s = buf[:8]
    j = memoryview(buf)[8:]

    c = [F(0) for _ in range(N)]
    for i in range(256 - p.τ, 256):
        while j[0] > i:
            j = j[1:]
        c[i] = c[j[0]]
        bit_idx = i + p.τ - 256
        bit = (s[bit_idx // 8] >> (bit_idx % 8)) & 1
        c[j[0]] = F(1) if bit == 0 else F(Q - 1)
        j = j[1:]

    return Poly(c)


def use_hint(w: Poly, h: list[int], p: _Parameters) -> list[int]:
    m = (Q - 1) // (2 * p.γ2)
    w1: list[int] = []
    for i in range(N):
        r1, r0 = decompose(w.cs[i], p)
        if h[i] == 0:
            w1.append(r1)
        elif r0 > 0:
            w1.append((r1 + 1) % m)
        else:
            w1.append((r1 - 1) % m)
    return w1


ZETAS = [1, 4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987, 7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458, 7159240, 5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590, 7044481, 5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733, 3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875, 394148, 928749, 1095468, 4874037, 2071829, 4361428, 3241972, 2156050, 3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364, 5483103, 3192354, 556856, 3870317, 2917338, 1853806, 3345963, 1858416, 3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357, 2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088, 1528066, 482649, 1148858, 5418153, 7814814, 169688, 2462444, 5046034, 4213992, 4892034, 1987814, 5183169, 1736313, 235407, 5130263, 3258457, 5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354, 7062739, 2461387, 3035980, 621164, 3901472, 7153756, 2925816, 3374250, 1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254, 348812, 8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507, 1753, 6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600, 1182243, 87208, 636927, 4415111, 4423672, 6084020, 5095502, 4663471, 8352605, 822541, 1009365, 5926272, 6400920, 1596822, 4423473, 4620952, 6695264, 4969849, 2678278, 4611469, 4829411, 635956, 8129971, 5925040, 4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961, 3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000, 2998219, 141835, 8291116, 2513018, 7025525, 613238, 7070156, 6161950, 7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452, 6757063, 2105286, 6006015, 6346610, 586241, 7200804, 527981, 5637006, 6903432, 1994046, 2491325, 6987258, 507927, 7192532, 7655613, 6545891, 5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577, 4357667, 3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144, 3994671, 8368538, 7009900, 3020393, 3363542, 214880, 545376, 7609976, 3105558, 7277073, 508145, 7826699, 860144, 3430436, 140244, 6866265, 6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710, 8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983]  # fmt: skip  # ruff: ignore[line-too-long]

import os
import struct
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


"""OpenTimestamps proof parsing and replay. Stdlib only.

An .ots proof is a hash chain: start from the digest of the file, apply a list of
append/prepend/hash operations, and arrive at a value that some attestation
claims is committed somewhere. For a Bitcoin attestation, that value is a block's
merkle root and the attestation names the height.

This module does the replay. It does not fetch anything, and it does not decide
whether a block is real -- see verify_anchors.py for that half.

Format: https://github.com/opentimestamps/python-opentimestamps
"""
import hashlib

MAGIC = (b"\x00OpenTimestamps\x00\x00Proof\x00"
         b"\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

OP_SHA1 = 0x02
OP_RIPEMD160 = 0x03
OP_SHA256 = 0x08
OP_KECCAK256 = 0x67
OP_APPEND = 0xf0
OP_PREPEND = 0xf1
OP_REVERSE = 0xf2
OP_HEXLIFY = 0xf3
OP_FORK = 0xff
OP_ATTESTATION = 0x00

TAG_BITCOIN = bytes.fromhex("0588960d73d71901")
TAG_PENDING = bytes.fromhex("83dfe30d2ef90c8e")
TAG_LITECOIN = bytes.fromhex("06869a0d73d71b45")
TAG_ETHEREUM = bytes.fromhex("30fe8087b5c7ead7")

TAG_NAMES = {
    TAG_BITCOIN: "bitcoin",
    TAG_PENDING: "pending",
    TAG_LITECOIN: "litecoin",
    TAG_ETHEREUM: "ethereum",
}


class OTSError(Exception):
    pass


class _Reader:
    def __init__(self, buf):
        self.buf = buf
        self.i = 0

    def byte(self):
        if self.i >= len(self.buf):
            raise OTSError("truncated proof")
        b = self.buf[self.i]
        self.i += 1
        return b

    def take(self, n):
        if self.i + n > len(self.buf):
            raise OTSError("truncated proof")
        out = self.buf[self.i:self.i + n]
        self.i += n
        return out

    def varuint(self):
        val, shift = 0, 0
        while True:
            b = self.byte()
            val |= (b & 0x7f) << shift
            if not b & 0x80:
                return val
            shift += 7
            if shift > 63:
                raise OTSError("varuint too long")

    def varbytes(self):
        return self.take(self.varuint())

    def done(self):
        return self.i >= len(self.buf)


def _ripemd160(b):
    try:
        h = hashlib.new("ripemd160")
    except ValueError:
        raise OTSError("ripemd160 unavailable in this Python's hashlib")
    h.update(b)
    return h.digest()


def _apply(op, arg, msg):
    if op == OP_APPEND:
        return msg + arg
    if op == OP_PREPEND:
        return arg + msg
    if op == OP_REVERSE:
        return msg[::-1]
    if op == OP_HEXLIFY:
        return msg.hex().encode()
    if op == OP_SHA256:
        return hashlib.sha256(msg).digest()
    if op == OP_SHA1:
        return hashlib.sha1(msg).digest()
    if op == OP_RIPEMD160:
        return _ripemd160(msg)
    if op == OP_KECCAK256:
        raise OTSError("keccak256 is not in the standard library")
    raise OTSError("unknown operation 0x%02x" % op)


def _walk(r, msg, out):
    """Replay one branch, recording every attestation it reaches."""
    while True:
        if r.done():
            return
        op = r.byte()
        if op == OP_FORK:
            # Each branch continues from the same message. Parse them in turn;
            # the last one runs on after the fork ends.
            _walk(r, msg, out)
            continue
        if op == OP_ATTESTATION:
            tag = r.take(8)
            payload = r.varbytes()
            rec = {"tag": tag, "name": TAG_NAMES.get(tag, "unknown:" + tag.hex()),
                   "message": msg}
            if tag == TAG_BITCOIN:
                rec["height"] = _Reader(payload).varuint()
            elif tag == TAG_PENDING:
                rec["uri"] = _Reader(payload).varbytes().decode("utf-8", "replace")
            out.append(rec)
            return
        arg = b""
        if op in (OP_APPEND, OP_PREPEND):
            arg = r.varbytes()
        msg = _apply(op, arg, msg)


def parse(data):
    """Return (file_digest, attestations).

    Each attestation is a dict with name, message (the value it commits to), and
    for bitcoin a height. `message` for a bitcoin attestation is the block's
    merkle root, in internal byte order.
    """
    if not data.startswith(MAGIC):
        raise OTSError("not an OpenTimestamps proof")
    r = _Reader(data[len(MAGIC):])
    version = r.varuint()
    if version != 1:
        raise OTSError("unsupported proof version %d" % version)
    op = r.byte()
    sizes = {OP_SHA1: 20, OP_RIPEMD160: 20, OP_SHA256: 32, OP_KECCAK256: 32}
    if op not in sizes:
        raise OTSError("unknown file hash operation 0x%02x" % op)
    digest = r.take(sizes[op])
    out = []
    _walk(r, digest, out)
    return digest, out


def bitcoin_attestations(data):
    digest, ats = parse(data)
    return digest, [a for a in ats if a["tag"] == TAG_BITCOIN]


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


def pq_keys():
    """Shipped ML-DSA-44 verifier keys, indexed by name -> (key_id, alg, pubkey).

    The standard library has no ML-DSA-44, so this tool carries a vendored
    copy of filippo.io/mldsa-py and verifies the signatures with it, offline.
    It also recomputes each key id from the key material and binds it to the
    line that carries it, which settles *which* key signed -- the question that
    otherwise dies with the operator's machine."""
    out = {}
    try:
        d = json.loads(_read("pq_keys.json").decode())
    except Exception:
        return out
    for e in d.get("keys", []):
        try:
            name, _, b64 = e["vkey"].split("+", 2)
            blob = base64.b64decode(b64 + "=" * (-len(b64) % 4))
            kid = hashlib.sha256(name.encode() + b"\x0a" + blob[:1]
                                 + blob[1:]).digest()[:4]
            out[name] = (kid, blob[0], blob[1:])
        except Exception:
            continue
    return out


def rooted_names():
    """The witness names the SIGNED trust root vouches for.

    witness_keys.json is an unsigned convenience file: it ships every key needed
    to check every line on a checkpoint, and a log may be cosigned by a witness
    its manifest does not cover. Counting those toward the quorum would let an
    unsigned file raise the quorum's roof -- the number would come from the
    signed manifest while the key set came from beside it. Returns None when no
    trust root is present, in which case the quorum is UNSTATED and the bundle
    fails on that ground anyway."""
    try:
        d = json.loads(_read("trust-root.json").decode())
        return {v.split("+")[0] for v in d["witness_vkeys"]}
    except Exception:
        return None


def split_by_root(names):
    """(quorum_bearing, advisory) -- advisory cosignatures verify but are not in
    the signed trust root, so they are reported and never counted."""
    rooted = rooted_names()
    if rooted is None:
        return list(names), []
    return ([n for n in names if n in rooted],
            [n for n in names if n not in rooted])


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


def distinct_hosts(names):
    """Witness names are c2sp origins: a host, optionally then a path. Two keys under
    one host are one machine and one operator, so counting keys overstates how many
    parties actually saw the tree. Grouping by host is mechanical and checkable;
    grouping by organisation would need a curated table and a judgment call, so this
    reports what it can compute and says plainly what it cannot."""
    return {n.split("/", 1)[0] for n in names}


def check_manifest(leaves, size, root_b64):
    """manifest.json describes this bundle in prose and numbers. Nothing else here
    reads it, so until now a wrong number in it verified clean: an export shipped
    with leaves_exported=76 beside 7578 real leaves and this verifier passed it.
    A reader who trusts the manifest and a reader who recomputes would then have
    been told different things by the same bundle, which is the one failure this
    whole artifact exists to prevent. Every field that restates a fact the bundle
    carries is checked against the bundle."""
    try:
        m = json.loads(_read("manifest.json").decode())
    except Exception as e:
        print("FAIL manifest.json unreadable: %r" % (e,))
        return False

    good = True
    checks = [("final_tree_size", size),
              ("leaves_exported", len(leaves)),
              ("final_root_b64", root_b64)]
    for field, actual in checks:
        stated = m.get(field)
        if stated is None:
            print("FAIL manifest.json has no %s" % field)
            good = False
        elif stated != actual:
            print("FAIL manifest.json says %s=%r; this bundle has %r"
                  % (field, stated, actual))
            good = False

    n_anchors = 0
    d = os.path.join(HERE, "anchors")
    if os.path.isdir(d):
        n_anchors = len([f for f in os.listdir(d) if f.endswith(".checkpoint")])
    if m.get("anchored_checkpoints") != n_anchors:
        print("FAIL manifest.json says anchored_checkpoints=%r; anchors/ holds %d"
              % (m.get("anchored_checkpoints"), n_anchors))
        good = False

    if good:
        print("PASS manifest.json agrees with the bundle "
              "(size, leaf count, root, anchor count)")
    return good


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
        witnessed[n] = len(split_by_root(ind)[0])
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
        print("  note  %d without an OpenTimestamps proof file: %s"
              % (len(unstamped), _elide(unstamped)))
    ok = verify_anchor_proofs(names) and ok
    return ok


def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def _bits_to_target(bits):
    e, m = bits >> 24, bits & 0xffffff
    return m >> (8 * (3 - e)) if e <= 3 else m << (8 * (e - 3))


def verify_anchor_proofs(names):
    """Replay each OpenTimestamps proof and check it against shipped headers.

    Verifying an attestation needs Bitcoin headers, not a network. A header is
    80 bytes, so they ship here. What this cannot settle is whether these
    headers are the main chain: a linked run meeting its own difficulty is work,
    not consensus.
    """
    try:
        raw = _read("headers.bin")
        meta = json.loads(_read("headers.json").decode())
    except Exception:
        print("  ----  no headers.bin in this bundle, so the OpenTimestamps "
              "proofs cannot be checked here")
        return True
    start, count = meta["start_height"], len(raw) // 80
    def hdr(h):
        i = h - start
        return raw[i * 80:(i + 1) * 80] if 0 <= i < count else None

    broken = weak = 0
    prev = None
    for i in range(count):
        h = raw[i * 80:(i + 1) * 80]
        if prev is not None and h[4:36] != sha256d(prev):
            broken += 1
        if int.from_bytes(sha256d(h)[::-1], "big") > _bits_to_target(
                int.from_bytes(h[72:76], "little")):
            weak += 1
        prev = h
    print("  %s  %d block headers: chain linkage %s, proof of work %s"
          % ("PASS" if not (broken or weak) else "FAIL", count,
             "intact" if not broken else "BROKEN at %d" % broken,
             "valid" if not weak else "SHORT at %d" % weak))

    good = bad = outside = pending = 0
    for name in names:
        try:
            proof = _read(os.path.join("anchors", name + ".ots"))
        except Exception:
            continue
        try:
            digest, ats = bitcoin_attestations(proof)
        except Exception:
            bad += 1
            continue
        if hashlib.sha256(_read(os.path.join("anchors", name))).digest() != digest:
            bad += 1
            continue
        if not ats:
            pending += 1
            continue
        hit = False
        for at in ats:
            h = hdr(at["height"])
            if h is None:
                outside += 1
            elif h[36:68] == at["message"]:
                hit = True
            else:
                bad += 1
        if hit:
            good += 1
    if bad:
        print("  FAIL  %d anchor proof(s) do not replay to the merkle root in "
              "those headers (%d do)" % (bad, good))
    else:
        print("  PASS  %d anchor proof(s) replay to a merkle root in those "
              "headers" % good)
    if pending:
        print("  ----  %d still pending a Bitcoin attestation" % pending)
    if outside:
        print("  ----  %d name a height outside the shipped headers" % outside)
    return bad == 0


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

    independent, advisory = split_by_root(independent)
    for name in independent:
        print("  PASS  %-52s independent witness" % name[:52])
    for name in advisory:
        print("  ----  %-52s verifies, but the signed trust root does not "
              "name it: not counted" % name[:52])
    if log_ok:
        print("  PASS  %-52s the log's own key" % origin[:52])
    for name in failed:
        print("  FAIL  %-52s no bundled key verifies it" % name[:52])
    for item in malformed:
        print("  FAIL  %s" % item)
    pq = pq_keys()
    pq_bound, pq_unkeyed, pq_mismatch = 0, [], []
    pq_verified, pq_badsig = 0, []
    for line in sigs:
        parts = line.split(" ", 2)
        if len(parts) < 3:
            continue
        name = parts[1]
        try:
            blob = base64.b64decode(parts[2])
        except Exception:
            continue
        if len(blob) != _ML_DSA_44_COSIG:
            continue
        if name not in pq:
            pq_unkeyed.append(name)
            print("  ----  %-52s ML-DSA-44, no key for it in this bundle"
                  % name[:52])
        elif pq[name][0] == blob[:4]:
            pq_bound += 1
            _ts = int.from_bytes(blob[4:12], "big")
            _msg = (b"subtree/v1\n\x00"
                    + bytes([len(name)]) + name.encode()
                    + _ts.to_bytes(8, "big")
                    + bytes([len(origin)]) + origin.encode()
                    + (0).to_bytes(8, "big")
                    + size.to_bytes(8, "big")
                    + base64.b64decode(root_b64))
            try:
                VerificationKey(pq[name][2]).verify(blob[12:], _msg)
                pq_verified += 1
                print("  PASS  %-52s ML-DSA-44 under shipped key %s"
                      % (name[:52], pq[name][0].hex()))
            except VerificationError:
                pq_badsig.append(name)
                print("  FAIL  %-52s ML-DSA-44 signature did not verify"
                      % name[:52])
        else:
            pq_mismatch.append(name)
            print("  FAIL  %-52s ML-DSA-44 line names key %s, but the key "
                  "shipped for it is %s"
                  % (name[:52], blob[:4].hex(), pq[name][0].hex()))

    # The count that matters is the independent one. The log's own signature is
    # reported separately and never added to it: it says the operator held the
    # key, which is not evidence about the operator.
    print("log signature: %s" % ("verifies" if log_ok else "MISSING"))
    print("independent witness cosignatures verified: %d (quorum %s)"
          % (len(independent), quorum if quorum is not None else "UNSTATED"))
    if advisory:
        print("   ...and %d verified cosignature(s) not named by the signed "
              "trust root, excluded from that count: %s"
              % (len(advisory), ", ".join(sorted(advisory))))
    hosts = distinct_hosts(independent)
    print("   ...held by %d distinct host name(s): %s"
          % (len(hosts), ", ".join(sorted(hosts))))
    if len(hosts) < len(independent):
        print("   Fewer hosts than cosignatures: some keys above share a host, so")
        print("   they are not independent of each other. Count hosts, not keys.")
    print("   A host is not an operator. Two hosts can be one organisation, and")
    print("   this bundle cannot tell you which: that is a social fact, like the")
    print("   key-to-identity binding under does_not_prove. The count above is an")
    print("   upper bound on independence, never a floor.")
    if unverifiable:
        print("ML-DSA-44 lines: %d, of which %d verified against a key "
              "shipped in this bundle. Verification is done here, offline, by a "
              "vendored copy of filippo.io/mldsa-py; see pq_keys.json for the "
              "algorithm, the message format, and the keys."
              % (len(unverifiable), pq_verified))
        if pq_badsig:
            print("     SIGNATURE DID NOT VERIFY: %s" % _elide(pq_badsig))
        if pq_unkeyed:
            print("     no key shipped for: %s" % _elide(pq_unkeyed))

    if failed or malformed or pq_mismatch or pq_badsig:
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

    ok = check_manifest(leaves, size, root_b64) and ok

    ok = check_anchored_history(leaves, keys) and ok

    print("\n%s" % ("EXPORT VERIFIES" if ok else "EXPORT FAILED"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
