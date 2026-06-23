import pytest

from pqobfs.classifier import gfw_classify
from pqobfs.kemeleon import Kemeleon
from pqobfs.mlkem import MLKEM
from pqobfs.padding import normalize_message, tcp_segments
from pqobfs.wire import PQObfsHandshake


def test_end_to_end_pqobfs768():
    hs = PQObfsHandshake(768)
    pk, sk, nid = hs.generate_bridge_identity()
    cmsg, state = hs.client_hello(pk, nid)
    smsg, ss_server = hs.server_hello(cmsg, sk, nid)
    ss_client = hs.client_finish(smsg, state)
    assert ss_client == ss_server


def test_kemeleon_eliminates_surface1():
    mlkem, kem = MLKEM(768), Kemeleon(768)
    # before encoding: coefficient block is biased
    pk, _ = mlkem.keygen()
    coeff_block = pk[: 768 * 12 // 8]
    assert gfw_classify(coeff_block, ncoeffs=768)["verdict"] == "biased"
    # after encoding: uniform
    enc = None
    while enc is None:
        pk, _ = mlkem.keygen()
        enc = kem.encode_pk(pk)
    assert gfw_classify(enc)["verdict"] == "random"


def test_padding_eliminates_surface2():
    # all parameter sets normalize to the same 3-segment profile
    profiles = set()
    for k in (512, 768, 1024):
        hs = PQObfsHandshake(k)
        pk, sk, nid = hs.generate_bridge_identity()
        cmsg, _ = hs.client_hello(pk, nid, normalize=True)
        assert len(cmsg) == hs.LCOVER
        profiles.add(tuple(tcp_segments(len(cmsg))))
    assert profiles == {(1460, 1460, 1176)}
