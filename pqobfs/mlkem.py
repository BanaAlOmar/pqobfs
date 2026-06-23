"""ML-KEM wrapper with a unified interface.

Prefers the real ``kyber-py`` library. If unavailable, falls back to a simulator
that produces byte strings of the correct sizes AND reproduces the 12-bit
lattice-coefficient bias that the GFW classifier (Surface 1) detects.

FIPS 203 public-key layout (important for Kemeleon parsing):

    ek = ByteEncode_12(t_hat) || rho

i.e. the 32-byte seed ``rho`` is the LAST 32 bytes, and the coefficient block
(``k*256`` coefficients packed at 12 bits each) comes FIRST. The spec prose
assumed rho-first; the real library and FIPS 203 put it last, and the code below
follows the real layout.
"""

from __future__ import annotations

import os

Q = 3329
N = 256

# k (module rank) for each named parameter set.
K_BY_PARAM = {512: 2, 768: 3, 1024: 4}

# du/dv compression parameters for the ciphertext, per FIPS 203.
COMPRESS_BY_PARAM = {
    512: (10, 4),
    768: (10, 4),
    1024: (11, 5),
}

try:  # pragma: no cover - import path depends on environment
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

    _REAL_LIB = {512: ML_KEM_512, 768: ML_KEM_768, 1024: ML_KEM_1024}
    HAVE_REAL_MLKEM = True
except Exception:  # pragma: no cover
    _REAL_LIB = {}
    HAVE_REAL_MLKEM = False


def _pack_12bit(coeffs: list[int]) -> bytes:
    """Pack a list of 12-bit values little-endian into bytes (FIPS 203 ByteEncode_12)."""
    bits = bytearray()
    out = bytearray()
    acc = 0
    nbits = 0
    for c in coeffs:
        acc |= (c & 0xFFF) << nbits
        nbits += 12
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


def _sample_biased_coeff() -> int:
    """Sample a coefficient in Z_q (uniform), used to reproduce the natural bias.

    Because q = 3329 < 4096 = 2^12, a uniform coefficient in [0, q) has its
    leading (12th) bit set only when c >= 2048, i.e. with probability
    (q-2048)/q ~= 0.385. So ~61.5% of 12th bits are 0 -> popcount deficit.
    """
    return int.from_bytes(os.urandom(2), "little") % Q


class MLKEM:
    """Unified ML-KEM interface over the real library or a faithful simulator."""

    PARAM_SETS = {
        512: {"pk_size": 800, "ct_size": 768, "sk_size": 1632},
        768: {"pk_size": 1184, "ct_size": 1088, "sk_size": 2400},
        1024: {"pk_size": 1568, "ct_size": 1568, "sk_size": 3168},
    }

    def __init__(self, k: int):
        if k not in self.PARAM_SETS:
            raise ValueError(f"unsupported parameter set {k}")
        self.param = k
        self.k = K_BY_PARAM[k]
        self.q = Q
        self.n = N
        self.simulated = not HAVE_REAL_MLKEM
        self._lib = _REAL_LIB.get(k)

    # -- info ---------------------------------------------------------------
    @property
    def pk_size(self) -> int:
        return self.PARAM_SETS[self.param]["pk_size"]

    @property
    def ct_size(self) -> int:
        return self.PARAM_SETS[self.param]["ct_size"]

    @property
    def sk_size(self) -> int:
        return self.PARAM_SETS[self.param]["sk_size"]

    @property
    def coeff_bytes(self) -> int:
        """Length of the 12-bit-packed coefficient block in the public key."""
        return self.k * self.n * 12 // 8

    # -- operations ---------------------------------------------------------
    def keygen(self) -> tuple[bytes, bytes]:
        if self._lib is not None:
            return self._lib.keygen()
        return self._sim_keygen()

    def encap(self, pk: bytes) -> tuple[bytes, bytes]:
        if self._lib is not None:
            ss, ct = self._lib.encaps(pk)
            return ct, ss
        return self._sim_encap(pk)

    def decap(self, sk: bytes, ct: bytes) -> bytes:
        if self._lib is not None:
            return self._lib.decaps(sk, ct)
        return self._sim_decap(sk, ct)

    # -- simulator ----------------------------------------------------------
    def _sim_keygen(self) -> tuple[bytes, bytes]:
        coeffs = [_sample_biased_coeff() for _ in range(self.k * self.n)]
        coeff_block = _pack_12bit(coeffs)
        rho = os.urandom(32)
        pk = coeff_block + rho  # FIPS 203 layout: coeffs || rho
        # secret key embeds pk so decap can recover a deterministic shared secret.
        sk = os.urandom(self.sk_size - len(pk))[: self.sk_size - len(pk)] + pk
        if len(sk) < self.sk_size:
            sk = sk + os.urandom(self.sk_size - len(sk))
        return pk[: self.pk_size], sk[: self.sk_size]

    def _sim_encap(self, pk: bytes) -> tuple[bytes, bytes]:
        import hashlib

        # Ciphertext: u (k*256 coeffs, du bits) || v (256 coeffs, dv bits).
        du, dv = COMPRESS_BY_PARAM[self.param]
        u = [int.from_bytes(os.urandom(2), "little") % (1 << du) for _ in range(self.k * self.n)]
        v = [int.from_bytes(os.urandom(2), "little") % (1 << dv) for _ in range(self.n)]
        ct = _pack_bits(u, du) + _pack_bits(v, dv)
        ct = (ct + os.urandom(self.ct_size))[: self.ct_size]
        ss = hashlib.sha256(ct + pk).digest()
        return ct, ss

    def _sim_decap(self, sk: bytes, ct: bytes) -> bytes:
        import hashlib

        pk = sk[-self.pk_size :]
        return hashlib.sha256(ct + pk).digest()


def _pack_bits(values: list[int], width: int) -> bytes:
    out = bytearray()
    acc = 0
    nbits = 0
    for v in values:
        acc |= (v & ((1 << width) - 1)) << nbits
        nbits += width
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)
