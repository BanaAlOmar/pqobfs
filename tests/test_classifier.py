import os

from pqobfs.classifier import gfw_classify, popcount_per_byte
from pqobfs.mlkem import MLKEM


def test_uniform_bytes_pass():
    data = os.urandom(1184)
    assert gfw_classify(data)["verdict"] == "random"


def test_biased_bytes_fail():
    mlkem = MLKEM(768)
    pk, _ = mlkem.keygen()
    coeff_block = pk[: 768 * 12 // 8]
    result = gfw_classify(coeff_block, ncoeffs=768)
    assert result["verdict"] == "biased"


def test_popcount_uniform():
    pc = popcount_per_byte(os.urandom(8192))
    assert abs(pc - 4.0) < 0.1


def test_msb_bias_detected():
    mlkem = MLKEM(768)
    pk, _ = mlkem.keygen()
    coeff_block = pk[: 768 * 12 // 8]
    result = gfw_classify(coeff_block, ncoeffs=768)
    # raw ML-KEM 12th-bits are set ~38.5% of the time, well below 0.5
    assert result["msb_set_fraction"] < 0.45
    assert result["msb_p"] < 1e-3
