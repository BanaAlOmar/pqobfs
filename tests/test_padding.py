import pytest

from pqobfs.padding import LCOVER, normalize_message, segment_profile, tcp_segments


def test_normalize_exact():
    out = normalize_message(b"hello", LCOVER)
    assert len(out) == LCOVER
    assert out.startswith(b"hello")


def test_normalize_overflow():
    with pytest.raises(ValueError):
        normalize_message(b"x" * (LCOVER + 1), LCOVER)


def test_tcp_segments_obfs4():
    assert tcp_segments(128) == [128]


def test_tcp_segments_mlkem512():
    assert tcp_segments(1664) == [1460, 204]


def test_tcp_segments_mlkem768():
    assert tcp_segments(2308) == [1460, 848]


def test_tcp_segments_mlkem1024():
    assert tcp_segments(3232) == [1460, 1460, 312]


def test_tcp_segments_normalized():
    assert tcp_segments(4096) == [1460, 1460, 1176]


def test_segment_profile():
    prof = segment_profile(4096)
    assert prof["num_segments"] == 3
    assert prof["segments"] == [1460, 1460, 1176]
    assert prof["length"] == 4096
