"""False alarms seen on a real Windows PC, and the checks that keep them away
without hiding real findings."""
import hashlib
import io
import json
import os
import random
import struct
import zipfile
from pathlib import Path

import pytest

import zscan.analysis
import zscan.scanner as scanner_mod
from zscan.analysis import detect_type
from zscan.archives import Limits
from zscan.cli import main
from zscan.scanner import OWN_FILE, OWN_HISTORY, Scanner, reports_registry
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


def test_many_bomb_like_members_count_once(tmp_path):
    # Five bomb-like members used to add up to "malicious". It is one trait of the file, so it
    # counts once. (A bomb expands to gigabytes; the limit is lowered here instead.)
    tiles = {f"terrain/tile{i}.dds": b"\0" * (4 * 1024 * 1024) for i in range(5)}
    small_bombs = Scanner(YaraEngine(community=False), limits=Limits(bomb_bytes=2 * 1024 * 1024))
    rep = scan(small_bombs, tmp_path, "terraintexture.pak", make_zip(tiles))
    assert titles(rep).count("Possible zip bomb") == 6      # each member, and the archive as a whole
    assert rep.score == 15 and rep.verdict == "suspicious"


def test_a_game_pack_of_empty_tiles_is_read_not_flagged(scanner, tmp_path):
    tiles = {f"terrain/tile{i}.dds": b"\0" * (4 * 1024 * 1024) for i in range(5)}
    rep = scan(scanner, tmp_path, "terraintexture.pak", make_zip(tiles))
    assert "Possible zip bomb" not in titles(rep) and len(rep.children) == 5
    assert rep.verdict == "clean" and not rep.partly_scanned


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


def test_the_whole_package_folder_is_recognised(tmp_path, monkeypatch):
    # Bytecode of another Python version, or a module this run never imported, is ZScan's too.
    # A file of any other kind dropped into the folder is not.
    pkg = tmp_path / "zscan"
    (pkg / "__pycache__").mkdir(parents=True)
    pyc = pkg / "__pycache__" / "analysis.cpython-399.pyc"
    pyc.write_bytes(b"\x00\x00\r\n" + b"vssadmin delete shadows /all /quiet")
    dropped = pkg / "update.exe"
    dropped.write_bytes(b"MZ" + b"\x00" * 62 + b"wbadmin delete catalog -quiet")
    monkeypatch.setattr(scanner_mod, "PACKAGE_DIR", pkg)
    own = scanner_mod.own_file_hashes(None)
    assert hashlib.sha256(pyc.read_bytes()).hexdigest() in own
    assert hashlib.sha256(dropped.read_bytes()).hexdigest() not in own


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


# ------------------------------------------------------------ MZ files that are not Windows programs

def mz_header(e_lfanew: int, size: int = 0x40) -> bytearray:
    head = bytearray(size)
    head[:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, e_lfanew)
    return head


def test_16_bit_programs_and_fonts_are_not_broken_windows_programs(scanner, tmp_path):
    # Bitmap fonts (.fon) and the Win16 stubs in SysWOW64 are NE files: 913 of them were
    # reported as "Malformed PE header" on one PC.
    font = bytes(mz_header(0x80, 0x80)) + b"NE\x05\x01\x94\x00\x02\x00" + bytes(400)
    rep = scan(scanner, tmp_path, "8514fix.fon", font)
    assert rep.file_type == "dos" and rep.findings == [] and rep.verdict == "clean"
    assert detect_type(b"MZ\x90\x00" + bytes(100)) == "dos"                   # a DOS program
    assert detect_type(bytes(mz_header(0x319A000)) + os.urandom(8000)) == "dos"  # a Windows update delta


def test_text_that_starts_with_mz_is_text():
    assert detect_type(b"MZ,Mozambique,Maputo\nNA,Namibia,Windhoek\n") == "text"


def test_a_real_windows_program_is_still_one():
    from samples import benign_pe
    assert detect_type(benign_pe()) == "pe"


# ------------------------------------------------------------ game packs with "\\" in local headers

def zip_with_local_name(central: str, local: str) -> bytes:
    data = bytearray(make_zip({central: b"r_shadows = 1\n" * 50}))
    i = data.index(b"PK\x03\x04")
    n = struct.unpack_from("<H", data, i + 26)[0]
    assert n == len(local)
    data[i + 30:i + 30 + n] = local.encode()
    return bytes(data)


def test_backslashes_in_local_headers_are_read(scanner, tmp_path):
    # CryEngine paks write "Config\\a.cfg" in the local header and "Config/a.cfg" in the directory.
    rep = scan(scanner, tmp_path, "engine.pak", zip_with_local_name("Config/a.cfg", "Config\\a.cfg"))
    assert [c.path.split("!")[-1] for c in rep.children] == ["Config/a.cfg"]
    assert not rep.partly_scanned


def test_other_name_mismatches_are_still_refused(scanner, tmp_path):
    rep = scan(scanner, tmp_path, "odd.zip", zip_with_local_name("Config/a.cfg", "Config/b.cfg"))
    assert rep.children == [] and rep.partly_scanned
    assert "differ" in " ".join(rep.unscanned)


# ------------------------------------------------------------ ZScan's history and its reports

def test_the_shipped_history_list_is_well_formed():
    rows = [ln.split()[0] for ln in OWN_HISTORY.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")]
    assert len(rows) >= 10
    assert all(len(r) == 64 and int(r, 16) >= 0 for r in rows)


def test_files_from_older_versions_are_recognised(tmp_path, monkeypatch):
    old_rules = b'rule Old { strings: $a = "vssadmin delete shadows" $b = "wbadmin delete catalog" condition: all of them }'
    history = tmp_path / "own-history.sha256"
    history.write_text(f"# test\n{hashlib.sha256(old_rules).hexdigest()}  zscan/rules/core.yar @ 0000000\n")
    monkeypatch.setattr(scanner_mod, "OWN_HISTORY", history)
    s = Scanner(YaraEngine(community=False))
    rep = scan(s, tmp_path, "zscan-0.4.0-py3-none-any.whl", make_zip({"zscan/rules/core.yar": old_rules}))
    assert [c.skipped for c in rep.children] == [OWN_FILE] and rep.verdict == "clean"


def test_reports_are_recognised_in_later_scans(tmp_path, capsys):
    # A report quotes what it found, so on its own it looks like what it describes.
    target = tmp_path / "files"
    target.mkdir()
    (target / "cleanup.bat").write_bytes(b"vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet\r\n")
    report = tmp_path / "reports" / "scan.txt"
    report.parent.mkdir()
    assert main(["--no-community", "-v", "-o", str(report), str(target)]) == 2
    assert reports_registry().is_file()
    edited = tmp_path / "reports" / "edited.txt"
    edited.write_bytes(report.read_bytes() + b"\nnotes\n")
    capsys.readouterr()

    main(["--no-community", "--json", str(tmp_path / "reports")])
    data = json.loads(capsys.readouterr().out)
    assert data["own_files"] == [str(report)]                    # the report, recognised
    verdicts = {f["path"]: f["verdict"] for f in data["files"]}
    assert verdicts[str(edited)] in ("suspicious", "malicious")  # an edited copy is scanned as usual

    main(["--no-community", "-q", "--no-color", str(tmp_path / "reports")])
    out = capsys.readouterr().out
    assert "Skipped as ZScan's own files (1), recognised by exact content:" in out and str(report) in out


# ------------------------------------------------------------ where cloud-only files are

def test_cloud_only_files_are_summed_up_by_folder(tmp_path, monkeypatch, capsys):
    for rel in ("Sync/Photos/2024/a.jpg", "Sync/Photos/2024/b.jpg", "Sync/Docs/c.docx"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x")
    monkeypatch.setattr(scanner_mod, "not_local", lambda st: True)
    main(["--no-community", "--json", str(tmp_path)])
    folders = json.loads(capsys.readouterr().out)["cloud_only_folders"]
    assert sum(folders.values()) == 3 and len(folders) >= 1
    main(["--no-community", "-q", "--no-color", str(tmp_path)])
    assert "Cloud-only files (not downloaded, so not scanned), by folder:" in capsys.readouterr().out
