import io
import zipfile

import pytest

from zscan import yara_engine
from zscan.scanner import Scanner

FAKE_PACK = """/*
 * YARA-Forge YARA Rule Package
 * YARA-Forge Version: 9.9.9
 * Creation Date: 2026-11-22
 */
import "pe"
rule TEST_Forge_Rule {
  meta: description = "test rule" author = "tester" score = 90
  strings: $a = "zscan-community-test-marker"
  condition: $a
}
rule TEST_Forge_Low {
  meta: description = "weak" score = 50
  strings: $a = "weak-marker"
  condition: $a
}
"""


def pack_zip(source):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("packages/core/yara-rules-core.yar", source)
    return buf.getvalue()


def test_update_and_load_community(tmp_path):
    meta = yara_engine.update_community("core", fetch=lambda url: pack_zip(FAKE_PACK))
    assert meta["rules"] == 2 and meta["version"] == "9.9.9"
    engine = yara_engine.YaraEngine()
    assert engine.community is not None
    p = tmp_path / "f.txt"
    p.write_bytes(b"xx zscan-community-test-marker weak-marker")
    rep = Scanner(engine).scan_file(p)
    sev = {f.title: f.severity for f in rep.findings}
    assert sev["YARA-Forge: TEST_Forge_Rule"] == 5
    assert sev["YARA-Forge: TEST_Forge_Low"] == 2
    assert rep.verdict == "malicious"
    assert yara_engine.YaraEngine(community=False).community is None


def test_broken_pack_leaves_old_rules(tmp_path):
    yara_engine.update_community("core", fetch=lambda url: pack_zip(FAKE_PACK))
    with pytest.raises(Exception):
        yara_engine.update_community("core", fetch=lambda url: pack_zip("rule broken {"))
    assert yara_engine.YaraEngine().community is not None


def test_not_a_zip():
    with pytest.raises(ValueError):
        yara_engine.update_community("core", fetch=lambda url: b"<html>")


@pytest.mark.parametrize("score,sev", [(95, 5), (85, 5), (75, 4), (65, 3), (40, 2), (None, 3)])
def test_forge_severity(score, sev):
    assert yara_engine.forge_severity(score) == sev
