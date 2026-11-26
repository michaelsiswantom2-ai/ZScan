"""The ML features must equal what the official EMBER2024 extractor computes."""
import json
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")

from zscan.ml import features as F  # noqa: E402

import ml_inputs  # noqa: E402

GOLDEN = json.loads((Path(__file__).parent / "data" / "ml_golden.json").read_text())


def golden_vector(name: str):
    g = GOLDEN[name]
    v = np.zeros(g["dim"], dtype=np.float32)
    for i, x in g["nonzero"].items():
        v[int(i)] = x
    return v


def string_counts(data: bytes) -> dict:
    return F.raw_features(data)["strings"]["string_counts"]


@pytest.mark.parametrize("name", sorted(ml_inputs.INPUTS))
def test_matches_the_official_extractor(name):
    """Golden numbers were produced by the official code (not by zscan) for these inputs.
    Counts and fractions must agree; entropy sums may differ in the last bits between numpy builds."""
    data = ml_inputs.INPUTS[name]()
    assert len(data) == GOLDEN[name]["size"]
    got = F.feature_vector(data)
    assert got.shape == (F.NON_PE_DIM,) and got.dtype == np.float32
    np.testing.assert_allclose(got, golden_vector(name), rtol=1e-5, atol=1e-7)


def test_layout():
    assert F.NON_PE_DIM == 696 and F.FULL_DIM == 2568
    assert F.STRING_NAMES == sorted(F.STRING_NAMES) and len(F.STRING_NAMES) == 77
    v = F.feature_vector(ml_inputs.elf_like())
    hist = v[7:263]
    entropy_hist = v[263:519]
    assert hist.sum() == pytest.approx(1.0, abs=1e-5) and entropy_hist.sum() == pytest.approx(1.0, abs=1e-5)


def test_general_group():
    raw = F.raw_features(b"\x7fELF\x02\x01")["general"]
    assert raw["size"] == 6 and raw["is_pe"] == 0 and raw["start_bytes"] == [0x7F, ord("E"), ord("L"), ord("F")]
    assert F.raw_features(b"ab")["general"]["start_bytes"] == [ord("a"), ord("b"), 0, 0]
    assert F.raw_features(bytes(range(256)) * 4)["general"]["entropy"] == pytest.approx(8.0)
    assert F.raw_features(bytes(100))["general"]["entropy"] == 0


def test_byte_entropy_histogram():
    # 4096 zero bytes: three 2048-byte windows (step 1024), all in the lowest entropy row, first column
    out = F.raw_features(bytes(4096))["byteentropy"]
    assert out[0] == 3 * 2048 and sum(out) == 3 * 2048
    # every byte value equally often: maximum entropy row, mass spread evenly over the 16 columns
    out = F.raw_features(bytes(range(256)) * 16)["byteentropy"]
    assert out[:240] == [0] * 240 and out[240:] == [384] * 16
    # less than one window: one block holding everything
    out = F.raw_features(bytes(100))["byteentropy"]
    assert out[0] == 100 and sum(out) == 100


def test_strings_are_counted_per_string_not_per_match():
    data = b"cache cache cache\x00\x00more cache here\x00\x00nothing"
    assert string_counts(data)["cache"] == 2
    raw = F.raw_features(data)["strings"]
    assert raw["numstrings"] == 3 and raw["printables"] == len(b"cache cache cache" b"more cache here" b"nothing")


def test_patterns_never_match_across_strings():
    # "http:" and "//example.com" are separate strings: 'http://' must not be found
    assert "http://" not in string_counts(b"http:\x00//example.com")
    assert string_counts(b"\x00http://example.com/x\x00")["http://"] == 1
    # '.click' needs a character before "click" inside the same string
    assert ".click(" not in string_counts(b"\x00\x00click here\x00\x00")
    assert string_counts(b"\x00\x00.click here\x00\x00")[".click("] == 1


def test_word_boundaries_are_judged_inside_each_string():
    assert string_counts(b"\x00C:/dir\x00")["file_path"] == 1
    assert "file_path" not in string_counts(b"\x00xC:/dir\x00")
    assert string_counts(b"\x00connect to 192.168.1.20 now\x00")["ipv4_addr"] == 1
    assert "ipv4_addr" not in string_counts(b"\x00connect to 192.168.1.2003 now\x00")


def test_official_quirks_are_kept():
    # the "email_addr" pattern in the official extractor is the MAC address pattern
    c = string_counts(b"\x00device 00:1A:2b:3C:4d:5E ok\x00")
    assert c["mac_addr"] == 1 and c["email_addr"] == 1 and "url" not in c


def test_printable_distribution():
    raw = F.raw_features(b"\x00\x00AAAAAB\x00")["strings"]
    assert raw["printabledist"][ord("A") - 32] == 5 and raw["printabledist"][ord("B") - 32] == 1
    assert raw["avlength"] == 6 and raw["entropy"] == pytest.approx(0.6500, abs=1e-3)


def test_tiny_and_empty_inputs_do_not_crash():
    for n in range(0, 70):
        v = F.feature_vector(bytes(range(n)))
        assert v.shape == (F.NON_PE_DIM,) and np.isfinite(v).all()


def test_pad_for_model():
    v = F.feature_vector(ml_inputs.short_text())
    assert F.pad_for_model(v, F.NON_PE_DIM) is v
    p = F.pad_for_model(v, F.FULL_DIM)
    assert p.shape == (F.FULL_DIM,) and (p[:F.NON_PE_DIM] == v).all() and not p[F.NON_PE_DIM:].any()
    with pytest.raises(ValueError):
        F.pad_for_model(v, 100)
