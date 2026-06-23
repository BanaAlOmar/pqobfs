"""pq-obfs wire format and handshake (paper Table II).

The handshake is a KEM-based analogue of obfs4's ntor:

    Client -> Bridge
        * fresh ephemeral ML-KEM keypair (eph_pk, eph_sk)
        * encapsulation to the bridge's long-term public key B
              (ct_static, ss_static) = MLKEM.encap(B)
        * both eph_pk and ct_static are Kemeleon-encoded so they look uniform
        * MACs key off the static shared secret ss_static

    Bridge -> Client
        * encapsulation to the client's ephemeral public key eph_pk
              (ct_eph, ss_eph) = MLKEM.encap(eph_pk)
        * Kemeleon-encoded ct_eph + auth tag + MACs keyed off ss_eph
        * final session key = HKDF(ss_static || ss_eph)

Both parties therefore derive the same session secret. ``normalize=True`` pads
each message to ``LCOVER`` (4096) bytes (Defense 2).

Wire layout, client message (lengths vary by parameter set):
    [ enc_eph_pk | enc_ct_static | PC(padding) | MC (32) | MACC (32) ]
Server message:
    [ enc_ct_eph | auth (32) | PS(padding) | MS (32) | MACS (32) ]

Because the Kemeleon-encoded fields are variable-length, each message is framed
with 2-byte big-endian length prefixes so the receiver can parse it
unambiguously even after random padding is appended.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import struct

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .kemeleon import Kemeleon, kemeleon_encode_with_retry
from .mlkem import MLKEM
from .padding import LCOVER

MAC_LEN = 32


def _mac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def _derive_session(ss_static: bytes, ss_eph: bytes, node_id: bytes) -> bytes:
    hkdf = HKDF(algorithm=SHA256(), length=32, salt=node_id, info=b"pq-obfs-v1")
    return hkdf.derive(ss_static + ss_eph)


def _frame(*fields: bytes) -> bytes:
    out = bytearray()
    for f in fields:
        out += struct.pack(">H", len(f))
        out += f
    return bytes(out)


def _unframe(data: bytes, n: int) -> list[bytes]:
    fields = []
    off = 0
    for _ in range(n):
        (ln,) = struct.unpack_from(">H", data, off)
        off += 2
        fields.append(data[off : off + ln])
        off += ln
    return fields


class PQObfsHandshake:
    LCOVER = LCOVER

    def __init__(self, k: int = 768):
        self.param = k
        self.mlkem = MLKEM(k)
        self.kemeleon = Kemeleon(k)

    # -- bridge identity ----------------------------------------------------
    def generate_bridge_identity(self) -> tuple[bytes, bytes, bytes]:
        """Return (bridge_pk, bridge_sk, node_id) for a bridge long-term key."""
        pk, sk = self.mlkem.keygen()
        node_id = os.urandom(20)
        return pk, sk, node_id

    # -- client step 1 ------------------------------------------------------
    def client_hello(
        self, bridge_pk: bytes, bridge_node_id: bytes, normalize: bool = False
    ) -> tuple[bytes, dict]:
        # fresh ephemeral keypair, Kemeleon-encoded with rejection retry
        enc_eph_pk, (eph_pk, eph_sk), _ = kemeleon_encode_with_retry(
            lambda m: self.kemeleon.encode_pk(m[0]),
            lambda: self._keygen_pair(),
        )
        # static encapsulation to the bridge's long-term key
        enc_ct_static, (ct_static, ss_static), _ = kemeleon_encode_with_retry(
            lambda m: self.kemeleon.encode_ct(m[0]),
            lambda: self.mlkem.encap(bridge_pk),
        )

        mc = _mac(ss_static + bridge_node_id, enc_eph_pk + enc_ct_static)
        pad = self._padding()
        body = _frame(enc_eph_pk, enc_ct_static, pad, mc)
        macc = _mac(ss_static + bridge_node_id, body)
        msg = body + macc

        if normalize:
            from .padding import normalize_message

            msg = normalize_message(msg, self.LCOVER)

        state = {
            "eph_pk": eph_pk,
            "eph_sk": eph_sk,
            "ss_static": ss_static,
            "node_id": bridge_node_id,
            "enc_eph_pk": enc_eph_pk,
        }
        return msg, state

    # -- bridge step --------------------------------------------------------
    def server_hello(
        self,
        client_msg: bytes,
        bridge_sk: bytes,
        bridge_node_id: bytes,
        normalize: bool = False,
    ) -> tuple[bytes, bytes]:
        enc_eph_pk, enc_ct_static, pad_c, mc = _unframe(client_msg, 4)
        # recover static shared secret
        ct_static = self.kemeleon.decode_ct(enc_ct_static)
        ss_static = self.mlkem.decap(bridge_sk, ct_static)

        # verify intermediate MAC
        expected_mc = _mac(ss_static + bridge_node_id, enc_eph_pk + enc_ct_static)
        if not hmac.compare_digest(mc, expected_mc):
            raise ValueError("client MAC (MC) verification failed")

        # encapsulate to client's ephemeral public key
        eph_pk = self.kemeleon.decode_pk(enc_eph_pk)
        enc_ct_eph, (ct_eph, ss_eph), _ = kemeleon_encode_with_retry(
            lambda m: self.kemeleon.encode_ct(m[0]),
            lambda: self.mlkem.encap(eph_pk),
        )

        es = _mac(bridge_node_id, ss_eph)  # ephemeral secret per paper keying
        auth = _mac(es, enc_ct_eph + ss_static)
        pad = self._padding()
        ms = _mac(es, enc_ct_eph)
        body = _frame(enc_ct_eph, auth, pad, ms)
        macs = _mac(es, body)
        msg = body + macs

        session = _derive_session(ss_static, ss_eph, bridge_node_id)

        if normalize:
            from .padding import normalize_message

            msg = normalize_message(msg, self.LCOVER)

        return msg, session

    # -- client step 2 ------------------------------------------------------
    def client_finish(self, server_msg: bytes, state: dict) -> bytes:
        enc_ct_eph, auth, pad_s, ms = _unframe(server_msg, 4)
        ct_eph = self.kemeleon.decode_ct(enc_ct_eph)
        ss_eph = self.mlkem.decap(state["eph_sk"], ct_eph)

        es = _mac(state["node_id"], ss_eph)
        expected_auth = _mac(es, enc_ct_eph + state["ss_static"])
        if not hmac.compare_digest(auth, expected_auth):
            raise ValueError("server auth tag verification failed")
        expected_ms = _mac(es, enc_ct_eph)
        if not hmac.compare_digest(ms, expected_ms):
            raise ValueError("server MAC (MS) verification failed")

        return _derive_session(state["ss_static"], ss_eph, state["node_id"])

    # -- helpers ------------------------------------------------------------
    def _keygen_pair(self):
        pk, sk = self.mlkem.keygen()
        return (pk, sk)

    def _padding(self) -> bytes:
        # small random padding PC/PS in [0, 64) bytes (the variable padding field)
        return os.urandom(int.from_bytes(os.urandom(1), "big") % 64)
