import gzip
import io
import tarfile
import zipfile

import pytest

from zscan.archives import Limits
from zscan.scanner import Scanner
from zscan.yara_engine import YaraEngine

from samples import EICAR, benign_pe


@pytest.fixture(scope="module")
def engine():
    return YaraEngine(community=False)


def make_zip(files, compression=zipfile.ZIP_DEFLATED):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


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


def test_zip_bomb_not_unpacked(engine, tmp_path):
    rep = scan(engine, tmp_path, "bomb.zip", make_zip({"zeros.bin": b"\0" * (20 * 1024 * 1024)}))
    assert rep.children == []
    assert any(f.title == "Possible zip bomb" for f in rep.findings)
    assert rep.verdict == "suspicious"


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
