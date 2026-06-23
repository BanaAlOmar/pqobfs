"""Minimal obfs4 baseline for comparison.

Uses real X25519 from ``cryptography``. obfs4 encodes the 32-byte X25519 public
key with Elligator 2 so it appears as uniform random bytes; here we model that
representative as 32 statistically uniform bytes (the security-relevant property
for the byte-distribution analysis). The minimum client message is 128 bytes:

    32 (key repr) + 32 (epoch MAC) + 32 (mark MAC) + 32 (min padding)

which reproduces the obfs4 row of paper Tables IV and V.
"""

from __future__ import annotations

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

MIN_MSG = 128
KEY_REPR = 32
MAC_LEN = 32
MIN_PAD = 32


def _elligator2_repr(_pub_bytes: bytes) -> bytes:
    """Model the Elligator 2 representative as 32 uniform random bytes.

    A real implementation maps the X25519 point to a field element with the
    Elligator 2 inverse map; the output is uniform over 32 bytes, which is the
    only property the byte-distribution classifier cares about.
    """
    return os.urandom(KEY_REPR)


class Obfs4Baseline:
    def __init__(self):
        self.key_repr_size = KEY_REPR

    def client_hello(self, bridge_pub: bytes, node_id: bytes) -> tuple[bytes, dict]:
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key().public_bytes_raw()
        repr_bytes = _elligator2_repr(eph_pk)

        mac_key = bridge_pub + node_id
        epoch_mac = hmac.new(mac_key, repr_bytes, hashlib.sha256).digest()
        mark_mac = hmac.new(mac_key, epoch_mac, hashlib.sha256).digest()
        padding = os.urandom(MIN_PAD)

        msg = repr_bytes + epoch_mac + mark_mac + padding
        state = {"eph_sk": eph_sk, "eph_pk": eph_pk, "node_id": node_id}
        return msg, state

    def server_hello(self, client_msg: bytes, bridge_priv, node_id: bytes) -> tuple[bytes, bytes]:
        eph_sk = X25519PrivateKey.generate()
        eph_pk = eph_sk.public_key().public_bytes_raw()
        repr_bytes = _elligator2_repr(eph_pk)

        mac_key = eph_pk + node_id
        auth = hmac.new(mac_key, client_msg[:KEY_REPR], hashlib.sha256).digest()
        mark_mac = hmac.new(mac_key, auth, hashlib.sha256).digest()
        padding = os.urandom(MIN_PAD)

        msg = repr_bytes + auth + mark_mac + padding
        client_repr = client_msg[:KEY_REPR]
        shared = hashlib.sha256(repr_bytes + client_repr + node_id).digest()
        return msg, shared
