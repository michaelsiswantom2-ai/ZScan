"""False alarms seen on a real Windows PC, and the checks that keep them away
without hiding real findings."""
import json
import os
import random
import zipfile
from pathlib import Path

import pytest

import zscan.analysis
from zscan.cli import main
from zscan.scanner import OWN_FILE, Scanner
from zscan.yara_engine import DEFAULT_RULES, YaraEngine

from samples import CODE_RX, EICAR, build_pe, make_zip

CORE_RULES = DEFAULT_RULES / "core.yar"
INJECTION_TRIO = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]


@pytest.fixture(scope="module")
def scanner():
    return Scanner(YaraEngine(community=False))


def scan(scanner, tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return scanner.scan_file(p)


def titles(rep):
    return [f.title for f in rep.findings]


# ------------------------------------------------------------ programs

def test_high_entropy_data_sections_are_not_packing(scanner, tmp_path):
    # Compressed icons in .rsrc and the compressed debug sections of MinGW and Go programs
    # ("/19", "/32") look random, but they are data, not packed code.
    pe = build_pe([(b".text", b"\x90" * 300 + b"\xc3", CODE_RX),
                   (b".rsrc", os.urandom(16 * 1024), 0x40000040),
                   (b"/19", os.urandom(8 * 1024), 0x42000040)])
    rep = scan(scanner, tmp_path, "tool.exe", pe)
    assert not [t for t in titles(rep) if t.startswith("High-entropy")]
    assert rep.verdict == "clean"


def test_high_entropy_code_is_still_flagged(scanner, tmp_path):
    pe = build_pe([(b".text", os.urandom(16 * 1024), CODE_RX)])
    rep = scan(scanner, tmp_path, "packed.exe", pe)
    assert "High-entropy code section '.text'" in titles(rep)
    assert rep.verdict == "suspicious"


def test_injection_imports_and_the_yara_rule_count_once(scanner, tmp_path):
    # The API names sit in the import table as text, so the import check and the bundled
    # YARA rule both see them: one trait, counted once.
    pe = build_pe([(b".text", b"\x90" * 300 + b"\xc3", CODE_RX)],
                  imports={"KERNEL32.dll": INJECTION_TRIO + ["ExitProcess"]})
    rep = scan(scanner, tmp_path, "injector.exe", pe)
    assert "Imports suggest process injection" in titles(rep)
    assert "YARA: Process_Injection_API_Strings" in titles(rep)
    assert rep.score == 15 and rep.verdict == "suspicious"


def test_two_injection_imports_alone_are_not_suspicious(scanner, tmp_path):
    pe = build_pe([(b".text", b"\x90" * 300 + b"\xc3", CODE_RX)],
                  imports={"KERNEL32.dll": ["VirtualAllocEx", "WriteProcessMemory", "ExitProcess"]})
    rep = scan(scanner, tmp_path, "debugger.exe", pe)
    assert "Imports suggest process injection" in titles(rep)
    assert rep.verdict == "clean"


# ------------------------------------------------------------ archives

def test_well_compressed_office_images_are_not_zip_bombs(scanner, tmp_path):
    # EMF pictures in slides were seen at 259:1; bombs sit near deflate's limit of about 1030:1.
    rnd = random.Random(7)
    picture = b"".join(b"\0" * 1500 + bytes([rnd.randrange(256)]) for _ in range(1400))
    data = make_zip({"ppt/media/image1.emf": picture})
    info = zipfile.ZipFile(__import__("io").BytesIO(data)).infolist()[0]
    assert 200 < info.file_size / info.compress_size < 1000
    rep = scan(scanner, tmp_path, "lecture.pptx", data)
    assert "Possible zip bomb" not in titles(rep)
    assert [c.path.split("!")[-1] for c in rep.children] == ["ppt/media/image1.emf"]   # it was unpacked


def test_many_bomb_like_members_count_once(scanner, tmp_path):
    # A game data pack full of empty terrain tiles: five members at 1000:1 used to add up to
    # "malicious". It is one trait of the file, so it counts once.
    tiles = {f"terrain/tile{i}.dds": b"\0" * (4 * 1024 * 1024) for i in range(5)}
    rep = scan(scanner, tmp_path, "terraintexture.pak", make_zip(tiles))
    assert titles(rep).count("Possible zip bomb") == 5
    assert rep.score == 15 and rep.verdict == "suspicious"


# ------------------------------------------------------------ ZScan's own files

def test_zscans_own_files_are_recognised(scanner, tmp_path):
    assert scanner.scan_file(CORE_RULES).skipped == OWN_FILE
    rep = scanner.scan_file(Path(zscan.analysis.__file__))       # lists the API names it looks for
    assert rep.verdict == "skipped" and rep.skipped == OWN_FILE
    # A copy inside an archive, such as a wheel in pip's cache, is recognised too.
    wheel = make_zip({"zscan/rules/core.yar": CORE_RULES.read_bytes(),
                      "zscan/analysis.py": Path(zscan.analysis.__file__).read_bytes()})
    rep = scan(scanner, tmp_path, "zscan-0.5.2-py3-none-any.whl", wheel)
    assert [c.skipped for c in rep.children] == [OWN_FILE, OWN_FILE]
    assert rep.verdict == "clean"


def test_an_edited_copy_of_zscans_rules_is_still_scanned(scanner, tmp_path):
    # Matching is by exact content, never by name or folder, so nothing can hide behind it.
    rep = scan(scanner, tmp_path, "core.yar", CORE_RULES.read_bytes() + b"\n// edited\n")
    assert rep.verdict == "malicious"
    rep = scan(scanner, tmp_path, "zscan/rules/core.yar".replace("/", "_"), EICAR)
    assert rep.verdict == "malicious"


def test_downloaded_community_rules_are_recognised(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / "rules").mkdir(parents=True)
    monkeypatch.setenv("ZSCAN_HOME", str(home))
    forge = home / "rules" / "yara-forge.yar"
    forge.write_bytes(b'rule Shadow_Wipe { strings: $a = "vssadmin delete shadows" '
                      b'$b = "wbadmin delete catalog" condition: all of them }')
    assert Scanner(YaraEngine(community=False)).scan_file(forge).skipped == OWN_FILE


def test_own_files_are_recognised_in_parallel_scans(tmp_path, capsys):
    (tmp_path / "copy-of-core.yar").write_bytes(CORE_RULES.read_bytes())
    (tmp_path / "eicar.com").write_bytes(EICAR)
    assert main(["--no-community", "--json", "-j", "2", str(tmp_path)]) == 2
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert summary["skipped_reasons"] == {OWN_FILE: 1} and summary["malicious"] == 1
