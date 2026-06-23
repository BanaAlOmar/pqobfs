import pytest

from pqobfs.wire import PQObfsHandshake


@pytest.fixture
def bridge():
    hs = PQObfsHandshake(768)
    pk, sk, nid = hs.generate_bridge_identity()
    return hs, pk, sk, nid


def test_client_hello_size(bridge):
    hs, pk, sk, nid = bridge
    msg, _ = hs.client_hello(pk, nid)
    # encoded eph pk ~1156 + encoded ct ~1252 + MACs + framing + small padding
    assert 2200 < len(msg) < 2700


def test_full_handshake(bridge):
    hs, pk, sk, nid = bridge
    cmsg, state = hs.client_hello(pk, nid)
    smsg, ss_server = hs.server_hello(cmsg, sk, nid)
    ss_client = hs.client_finish(smsg, state)
    assert ss_client == ss_server
    assert len(ss_client) == 32


def test_mac_verification(bridge):
    hs, pk, sk, nid = bridge
    cmsg, _ = hs.client_hello(pk, nid)
    tampered = bytearray(cmsg)
    tampered[5] ^= 0xFF
    with pytest.raises(ValueError):
        hs.server_hello(bytes(tampered), sk, nid)


def test_normalized_size(bridge):
    hs, pk, sk, nid = bridge
    cmsg, state = hs.client_hello(pk, nid, normalize=True)
    smsg, _ = hs.server_hello(cmsg, sk, nid, normalize=True)
    assert len(cmsg) == hs.LCOVER
    assert len(smsg) == hs.LCOVER


def test_normalized_handshake_still_works(bridge):
    hs, pk, sk, nid = bridge
    cmsg, state = hs.client_hello(pk, nid, normalize=True)
    smsg, ss_server = hs.server_hello(cmsg, sk, nid, normalize=True)
    ss_client = hs.client_finish(smsg, state)
    assert ss_client == ss_server
