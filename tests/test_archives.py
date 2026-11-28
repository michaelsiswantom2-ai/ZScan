import bz2
import gzip
import io
import lzma
import tarfile
import zipfile

import pytest

from zscan.archives import Limits
from zscan.scanner import Scanner
from zscan.yara_engine import YaraEngine

from samples import CODE_RX, DATA_RW, EICAR, benign_pe, build_pe, make_tar, make_zip, packed_like_pe
from zscan.cli import main


@pytest.fixture(scope="module")
def engine():
    return YaraEngine(community=False)


def scan(engine, tmp_path, name, data, **kw):
    p = tmp_path / name
    p.write_bytes(data)
    return Scanner(engine, **kw).scan_file(p)


def test_eicar_inside_zip(engine, tmp_path):
    rep = scan(engine, tmp_path, "a.zip", make_zip({"readme.txt": b"hi", "dir/eicar.com": EICAR}))
    assert rep.file_type == "zip"
    assert rep.verdict == "malicious"
    assert [c.path.split("!")[-1] for c in rep.children] == ["readme.txt", "dir/eicar.com"]
    assert rep.children[1].verdict == "malicious"
    assert any(f.title == "Contains malicious file" and f.detail == "dir/eicar.com" for f in rep.findings)


def test_clean_zip(engine, tmp_path):
    rep = scan(engine, tmp_path, "ok.zip", make_zip({"a.txt": b"hello", "b.exe": benign_pe()}))
    assert rep.verdict == "clean"
    assert len(rep.children) == 2


def test_nested_zip_in_tar_gz(engine, tmp_path):
    inner = make_zip({"eicar.txt": EICAR})
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w") as t:
        info = tarfile.TarInfo("payload/inner.zip")
        info.size = len(inner)
        t.addfile(info, io.BytesIO(inner))
    rep = scan(engine, tmp_path, "x.tar.gz", gzip.compress(tbuf.getvalue()))
    assert rep.file_type == "gzip"
    leaf = list(rep.iter_tree())[-1]
    assert leaf.path.endswith("x.tar.gz!(decompressed)!payload/inner.zip!eicar.txt")
    assert leaf.verdict == "malicious"
    assert rep.verdict == "malicious"


def test_depth_limit(engine, tmp_path):
    data = EICAR
    for i in range(5):
        data = make_zip({f"level{i}": data})
    rep = scan(engine, tmp_path, "deep.zip", data, limits=Limits(max_depth=2))
    titles = [f.title for n in rep.iter_tree() for f in n.findings]
    assert "Archive nested too deep, not unpacked" in titles
    assert rep.verdict != "malicious"  # EICAR was never reached


# A real bomb expands to gigabytes; the tests lower that limit instead of building one.
BOMB_LIMITS = Limits(bomb_bytes=8 * 1024 * 1024)


def test_zip_bomb_not_unpacked(engine, tmp_path):
    rep = scan(engine, tmp_path, "bomb.zip", make_zip({"zeros.bin": b"\0" * (20 * 1024 * 1024)}),
               limits=BOMB_LIMITS)
    assert rep.children == []
    assert any(f.title == "Possible zip bomb" for f in rep.findings)
    assert rep.verdict == "suspicious"


def test_extreme_compression_that_fits_the_limits_is_read(engine, tmp_path):
    # Empty terrain tiles in game packs compress at about 1030:1, like a bomb, but they are small.
    tile = b"\0" * (4 * 1024 * 1024) + b"vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet"
    rep = scan(engine, tmp_path, "terraintexture.pak", make_zip({"tile0_0.raw": tile}))
    assert "Possible zip bomb" not in [f.title for f in rep.findings]
    assert [c.path.split("!")[-1] for c in rep.children] == ["tile0_0.raw"]
    assert rep.children[0].verdict != "clean"      # it was read, so what it hides is found


def test_encrypted_member_flagged(engine, tmp_path):
    data = bytearray(make_zip({"invoice.exe": b"MZ" + b"\0" * 100}, zipfile.ZIP_STORED))
    # Set the "encrypted" flag bit in both the local and central headers.
    for sig in (b"PK\x03\x04", b"PK\x01\x02"):
        i = data.index(sig)
        off = i + (6 if sig == b"PK\x03\x04" else 8)
        data[off] |= 1
    rep = scan(engine, tmp_path, "locked.zip", bytes(data))
    assert any(f.title == "Password-protected archive members" for f in rep.findings)
    assert rep.verdict == "suspicious"


def test_no_unpack(engine, tmp_path):
    rep = scan(engine, tmp_path, "a.zip", make_zip({"eicar.com": EICAR}), unpack=False)
    assert rep.children == []


def test_corrupt_zip_does_not_crash(engine, tmp_path):
    rep = scan(engine, tmp_path, "bad.zip", b"PK\x03\x04" + b"garbage" * 10)
    assert rep.verdict in ("clean", "suspicious")


def test_overlapping_zip_entries_are_a_bomb(engine, tmp_path):
    data = bytearray(make_zip({"a.txt": b"A" * 5000, "b.txt": b"B" * 5000}, zipfile.ZIP_STORED))
    # Point the second central-directory entry at the first entry's data.
    entries = [i for i in range(len(data)) if data[i:i + 4] == b"PK\x01\x02"]
    first_offset = data[entries[0] + 42:entries[0] + 46]
    data[entries[1] + 42:entries[1] + 46] = first_offset
    rep = scan(engine, tmp_path, "overlap.zip", bytes(data))
    assert rep.children == []
    bomb = [f for f in rep.findings if f.title == "Possible zip bomb"]
    assert bomb and "overlapping entries" in bomb[0].detail
    assert rep.verdict == "suspicious"


@pytest.mark.parametrize("name,compress", [("a.bz2", bz2.compress), ("a.xz", lzma.compress)])
def test_bzip2_and_xz(engine, tmp_path, name, compress):
    rep = scan(engine, tmp_path, name, compress(EICAR))
    assert rep.file_type in ("bzip2", "xz")
    assert rep.verdict == "malicious"
    assert rep.children[0].path.endswith(f"{name}!(decompressed)")


def test_tar_xz_holds_tar_holds_eicar(engine, tmp_path):
    rep = scan(engine, tmp_path, "x.tar.xz", lzma.compress(make_tar({"pkg/run.sh": EICAR})))
    leaf = list(rep.iter_tree())[-1]
    assert leaf.path.endswith("x.tar.xz!(decompressed)!pkg/run.sh")
    assert rep.verdict == "malicious"
    # the archive points at the file that caused it, not just the next layer down
    assert [f.detail for f in rep.findings if f.title == "Contains malicious file"] == [
        "(decompressed)!pkg/run.sh"]


def test_archive_of_a_malicious_by_score_file_is_malicious(engine, tmp_path):
    """A file can be malicious through several independent findings and no single CRIT one:
    here an entry point outside every section plus ransomware recovery-blocking commands."""
    inner = build_pe([(b".text", b"\x90" * 300 + b"\xc3", CODE_RX),
                      (b".data", b"vssadmin delete shadows /all /quiet\x00"
                                 b"wbadmin delete catalog -quiet\x00", DATA_RW)], entry_rva=0x9000)
    rep = scan(engine, tmp_path, "tool.zip", make_zip({"setup.exe": inner}))
    assert rep.children[0].verdict == "malicious"
    assert not any(f.severity == 5 for f in rep.children[0].findings)
    assert rep.verdict == "malicious"


def test_archive_of_a_packed_program_is_only_suspicious(engine, tmp_path):
    rep = scan(engine, tmp_path, "tool.zip", make_zip({"setup.exe": packed_like_pe()}))
    assert rep.children[0].verdict == "suspicious" and rep.verdict == "suspicious"


@pytest.mark.parametrize("magic,kind,label", [
    (b"Rar!\x1a\x07\x01\x00", "rar", "RAR"),
    (b"7z\xbc\xaf\x27\x1c\x00\x04", "7z", "7-Zip"),
    (b"\x28\xb5\x2f\xfd\x04\x58", "zstd", "Zstandard"),
])
def test_unsupported_formats_are_reported_not_called_clean(engine, tmp_path, capsys, magic, kind, label):
    p = tmp_path / "x.bin"
    p.write_bytes(magic + bytes(range(256)))
    rep = Scanner(engine).scan_file(p)
    assert rep.file_type == kind
    assert rep.verdict == "clean"
    assert rep.partly_scanned and f"{label} archive" in rep.unscanned[0]
    assert Scanner(engine, unpack=False).scan_file(p).partly_scanned is False
    # shown even with --quiet, and counted in the summary
    code = main([str(p), "-q", "--no-color", "--no-community"])
    out = capsys.readouterr().out
    assert code == 0
    assert f"not fully scanned: {label} archive" in out and "1 not fully scanned" in out


def test_gaps_in_coverage_are_recorded(engine, tmp_path):
    deep = EICAR
    for i in range(5):
        deep = make_zip({f"l{i}": deep})
    rep = scan(engine, tmp_path, "deep.zip", deep, limits=Limits(max_depth=2))
    assert rep.partly_scanned
    assert any("nested more than 2 levels" in n for node in rep.iter_tree() for n in node.unscanned)

    bomb = scan(engine, tmp_path, "bomb.zip", make_zip({"zeros.bin": b"\0" * (20 * 1024 * 1024)}),
                limits=BOMB_LIMITS)
    assert bomb.partly_scanned
