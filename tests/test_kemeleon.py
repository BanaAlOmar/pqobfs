import pytest

from pqobfs.classifier import gfw_classify
from pqobfs.kemeleon import Kemeleon
from pqobfs.mlkem import MLKEM

PAPER_PK_SUCCESS = {512: 0.56, 768: 0.83, 1024: 0.62}


def _encode_one(mlkem, kem):
    while True:
        pk, _ = mlkem.keygen()
        enc = kem.encode_pk(pk)
        if enc is not None:
            return pk, enc


@pytest.mark.parametrize("k", [512, 768, 1024])
def test_encode_decode_roundtrip(k):
    mlkem, kem = MLKEM(k), Kemeleon(k)
    pk, enc = _encode_one(mlkem, kem)
    assert kem.decode_pk(enc) == pk


@pytest.mark.parametrize("k", [512, 768, 1024])
def test_ct_roundtrip(k):
    mlkem, kem = MLKEM(k), Kemeleon(k)
    pk, _ = mlkem.keygen()
    for _ in range(50):
        ct, _ = mlkem.encap(pk)
        enc = kem.encode_ct(ct)
        if enc is not None:
            assert kem.decode_ct(enc) == ct
            return
    pytest.fail("no ct encoding succeeded in 50 attempts")


@pytest.mark.parametrize("k", [512, 768, 1024])
def test_rejection_rate_in_range(k):
    mlkem, kem = MLKEM(k), Kemeleon(k)
    trials = 1000
    successes = sum(1 for _ in range(trials) if kem.encode_pk(mlkem.keygen()[0]) is not None)
    rate = successes / trials
    assert abs(rate - PAPER_PK_SUCCESS[k]) < 0.05, f"k={k} rate={rate}"


def test_encoded_appears_uniform():
    mlkem, kem = MLKEM(768), Kemeleon(768)
    passes = 0
    for _ in range(100):
        _, enc = _encode_one(mlkem, kem)
        if gfw_classify(enc)["verdict"] == "random":
            passes += 1
    assert passes >= 95, f"only {passes}/100 encoded keys looked uniform"


@pytest.mark.parametrize("k", [512, 768, 1024])
def test_no_reject_variant(k):
    mlkem, kem = MLKEM(k), Kemeleon(k)
    sizes = set()
    for _ in range(50):
        pk, _ = mlkem.keygen()
        enc = kem.encode_pk_no_reject(pk)
        assert enc is not None
        sizes.add(len(enc))
    # deterministic output size, never rejects
    assert len(sizes) == 1


def test_success_prob_matches_math():
    for k, expected in PAPER_PK_SUCCESS.items():
        assert abs(Kemeleon(k).pk_success_prob - expected) < 0.05
