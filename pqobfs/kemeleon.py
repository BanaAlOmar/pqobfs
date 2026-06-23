"""Kemeleon encoding for ML-KEM public keys and ciphertexts.

Core idea (IETF draft-veitch-kemeleon / the paper): treat the ``k*n``
coefficients of an ML-KEM public key as digits of a mixed-radix integer in base
``q`` and accumulate them into one big integer

    r = sum_i  q^i * coeff[i]

The maximum possible value is ``q^(k*n) - 1``, whose bit length is
``L = (q^(k*n)).bit_length()``. We accept iff the top bit is unset, i.e.
``r < 2^(L-1)``, and emit ``r`` as exactly ``L-1`` bits. Under module-LWE the
resulting bytes are computationally indistinguishable from uniform, removing the
12-bit coefficient bias that the GFW classifier detects (Surface 1).

Rejection (returning ``None``) happens with probability
``1 - 2^(L-1)/q^(k*n)``; the caller retries with a fresh keypair.

The FIPS 203 public key is ``coeff_block || rho`` (rho LAST 32 bytes), so the
encoded output is ``rho || encode(r)`` to keep the seed recoverable.
"""

from __future__ import annotations

from .mlkem import COMPRESS_BY_PARAM, K_BY_PARAM, N, Q


def _bytes_to_coeffs(data: bytes, count: int, width: int) -> list[int]:
    """Unpack ``count`` little-endian ``width``-bit values from ``data``."""
    coeffs = []
    acc = 0
    nbits = 0
    idx = 0
    mask = (1 << width) - 1
    for _ in range(count):
        while nbits < width:
            acc |= data[idx] << nbits
            nbits += 8
            idx += 1
        coeffs.append(acc & mask)
        acc >>= width
        nbits -= width
    return coeffs


def _coeffs_to_bytes(coeffs: list[int], width: int) -> bytes:
    out = bytearray()
    acc = 0
    nbits = 0
    mask = (1 << width) - 1
    for c in coeffs:
        acc |= (c & mask) << nbits
        nbits += width
        while nbits >= 8:
            out.append(acc & 0xFF)
            acc >>= 8
            nbits -= 8
    if nbits:
        out.append(acc & 0xFF)
    return bytes(out)


class Kemeleon:
    def __init__(self, k: int):
        if k not in K_BY_PARAM:
            raise ValueError(f"unsupported parameter set {k}")
        self.param = k
        self.k = K_BY_PARAM[k]
        self.q = Q
        self.n = N
        self.du, self.dv = COMPRESS_BY_PARAM[k]

        # --- public-key encoding range ---
        self._pk_ncoeffs = self.k * self.n
        self._pk_range = self.q ** self._pk_ncoeffs
        self._pk_bitlen = self._pk_range.bit_length()
        self._pk_out_bytes = (self._pk_bitlen - 1 + 7) // 8

        # --- ciphertext encoding range ---
        # The u-vector (k*n coeffs) is decompressed back into Z_q and accumulated
        # in base q exactly like the public key; this is the part that carries
        # lattice structure and is made uniform by Kemeleon. The v-polynomial
        # (n coeffs, dv bits each) is already near-uniform after compression and
        # is appended verbatim. Thus the ct accept rate is governed by q^(k*n),
        # the same quantity as the pk -> in this clean big-integer model the ct
        # and pk accept rates coincide (see README "Deviations").
        self._ct_u = self.k * self.n
        self._ct_v = self.n
        self._ct_range = self.q ** self._ct_u
        self._ct_bitlen = self._ct_range.bit_length()
        self._ct_u_bytes = (self._ct_bitlen - 1 + 7) // 8
        self._ct_v_bytes = self._ct_v * self.dv // 8
        self._ct_out_bytes = self._ct_u_bytes + self._ct_v_bytes

    # ---- sizes ------------------------------------------------------------
    @property
    def encoded_pk_size(self) -> int:
        """Total encoded public key: 32-byte rho + accumulator bytes."""
        return 32 + self._pk_out_bytes

    @property
    def encoded_ct_size(self) -> int:
        return self._ct_out_bytes

    @property
    def pk_success_prob(self) -> float:
        return min((1 << (self._pk_bitlen - 1)) / self._pk_range, 1.0)

    @property
    def ct_success_prob(self) -> float:
        return min((1 << (self._ct_bitlen - 1)) / self._ct_range, 1.0)

    # ---- public key -------------------------------------------------------
    def _split_pk(self, pk: bytes) -> tuple[bytes, bytes]:
        """Return (coeff_block, rho). FIPS 203 layout: coeffs || rho."""
        coeff_bytes = self._pk_ncoeffs * 12 // 8
        return pk[:coeff_bytes], pk[coeff_bytes:]

    def encode_pk(self, pk: bytes) -> bytes | None:
        coeff_block, rho = self._split_pk(pk)
        coeffs = _bytes_to_coeffs(coeff_block, self._pk_ncoeffs, 12)
        # Coefficients are valid Z_q digits (real library guarantees < q).
        r = 0
        for c in reversed(coeffs):
            r = r * self.q + (c % self.q)
        if r >= (1 << (self._pk_bitlen - 1)):
            return None  # reject: top bit set
        body = r.to_bytes(self._pk_out_bytes, "big")
        return rho + body

    def decode_pk(self, encoded: bytes) -> bytes:
        rho = encoded[:32]
        body = encoded[32:]
        r = int.from_bytes(body, "big")
        coeffs = []
        for _ in range(self._pk_ncoeffs):
            coeffs.append(r % self.q)
            r //= self.q
        coeff_block = _coeffs_to_bytes(coeffs, 12)
        return coeff_block + rho

    def encode_pk_no_reject(self, pk: bytes) -> bytes:
        """Rejection-free variant: always succeeds, output padded to a fixed size.

        Uses the full ``_pk_bitlen`` (one extra bit of range) so the accumulator
        never overflows the field, giving a deterministic, slightly larger output.
        """
        coeff_block, rho = self._split_pk(pk)
        coeffs = _bytes_to_coeffs(coeff_block, self._pk_ncoeffs, 12)
        r = 0
        for c in reversed(coeffs):
            r = r * self.q + (c % self.q)
        out_bytes = (self._pk_bitlen + 7) // 8  # full range, no MSB drop
        return rho + r.to_bytes(out_bytes, "big")

    # ---- ciphertext -------------------------------------------------------
    def _split_ct(self, ct: bytes) -> tuple[list[int], list[int]]:
        u_bytes = self._ct_u * self.du // 8
        u = _bytes_to_coeffs(ct[:u_bytes], self._ct_u, self.du)
        v = _bytes_to_coeffs(ct[u_bytes:], self._ct_v, self.dv)
        return u, v

    def _decompress_u(self, val: int) -> int:
        """Decompress a du-bit value into Z_q (FIPS 203 Decompress_du)."""
        return (val * self.q + (1 << (self.du - 1))) >> self.du

    def _compress_u(self, val: int) -> int:
        return ((val << self.du) + self.q // 2) // self.q & ((1 << self.du) - 1)

    def encode_ct(self, ct: bytes) -> bytes | None:
        u, v = self._split_ct(ct)
        u_zq = [self._decompress_u(x) % self.q for x in u]
        r = 0
        for c in reversed(u_zq):
            r = r * self.q + c
        if r >= (1 << (self._ct_bitlen - 1)):
            return None
        u_body = r.to_bytes(self._ct_u_bytes, "big")
        v_body = _coeffs_to_bytes(v, self.dv)
        return u_body + v_body

    def decode_ct(self, encoded: bytes) -> bytes:
        u_body = encoded[: self._ct_u_bytes]
        v_body = encoded[self._ct_u_bytes :]
        r = int.from_bytes(u_body, "big")
        u_zq = []
        for _ in range(self._ct_u):
            u_zq.append(r % self.q)
            r //= self.q
        u = [self._compress_u(x) for x in u_zq]
        v = _bytes_to_coeffs(v_body, self._ct_v, self.dv)
        return _coeffs_to_bytes(u, self.du) + _coeffs_to_bytes(v, self.dv)


def kemeleon_encode_with_retry(encode_fn, generate_fn):
    """Regenerate fresh KEM material until Kemeleon encoding succeeds.

    ``generate_fn`` returns fresh material (e.g. a public key);
    ``encode_fn`` returns the encoded bytes or ``None`` on rejection.
    Returns ``(encoded, material, attempts)``.
    """
    attempts = 0
    while True:
        attempts += 1
        material = generate_fn()
        encoded = encode_fn(material)
        if encoded is not None:
            return encoded, material, attempts
