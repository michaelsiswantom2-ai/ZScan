"""Windows signatures: ZScan's general warning signs do not count on validly signed programs,
while malware rules still do; programs changed after signing are flagged. Off Windows the
signature check is faked; the tests at the end run only on Windows, against real files."""
import base64
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

import zscan.signature as signature
from zscan.analysis import certificate_table, string_findings
from zscan.cli import main
from zscan.scanner import Scanner
from zscan.signature import Signature
from zscan.yara_engine import YaraEngine

from samples import CODE_RWX, CODE_RX, DATA_RW, benign_pe, build_pe, make_zip

on_windows = pytest.mark.skipif(sys.platform != "win32", reason="needs Windows' WinVerifyTrust")

# Three LOW import hints add up to "suspicious" (15): what plenty of signed vendor programs import.
EVERYDAY_IMPORTS = {"KERNEL32.dll": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetKeyState",
                                     "GetAsyncKeyState", "OpenProcessToken", "AdjustTokenPrivileges"]}
RANSOM = b"vssadmin delete shadows /all /quiet & wbadmin delete catalog -quiet"


def vendor_pe(data=b"\x90" * 300 + b"\xc3", certificate=b"\x30\x82fake-pkcs7"):
    return build_pe([(b".text", data, CODE_RX), (b".data", b"settings\x00" * 10, DATA_RW)],
                    imports=EVERYDAY_IMPORTS, certificate=certificate)


@pytest.fixture(scope="module")
def scanner():
    return Scanner(YaraEngine(community=False))


@pytest.fixture
def signed_as(monkeypatch):
    """Make the signature check answer `sig` and record which files it was asked about."""
    asked = []

    def fake(sig):
        def check(path):
            asked.append(Path(path).name)
            return sig
        monkeypatch.setattr(signature, "check", check)
        return asked
    return fake


def scan(scanner, tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return scanner.scan_file(p)


def titles(rep, counted_only=False):
    return [f.title for f in rep.findings if not (counted_only and f.not_counted)]


# ------------------------------------------------------------ what a valid signature changes

def test_general_warning_signs_do_not_count_on_validly_signed_programs(scanner, tmp_path, signed_as):
    signed_as(Signature(signature.VALID, signature.EMBEDDED, "Contoso Ltd"))
    rep = scan(scanner, tmp_path, "tool.exe", vendor_pe())
    assert rep.verdict == "clean" and rep.verdict_if_all_counted == "suspicious"
    hints = [f for f in rep.findings if f.heuristic and f.severity >= 2]
    assert len(hints) == 3 and all(f.not_counted == "validly signed by Contoso Ltd" for f in hints)
    assert "Validly signed by Contoso Ltd" in titles(rep)
    assert rep.signature == {"status": "valid", "kind": "embedded", "signer": "Contoso Ltd", "reason": ""}


def test_the_same_program_unsigned_counts_in_full(scanner, tmp_path, signed_as):
    signed_as(Signature(signature.NOT_SIGNED))
    rep = scan(scanner, tmp_path, "tool.exe", vendor_pe(certificate=None))
    assert rep.verdict == "suspicious" and rep.score == 15
    assert "Not signed" in titles(rep) and not any(f.not_counted for f in rep.findings)


def test_malware_rules_still_count_on_signed_programs(scanner, tmp_path, signed_as):
    # Signed malware exists (stolen certificates); rules that describe malware are not general signs.
    signed_as(Signature(signature.VALID, signature.EMBEDDED, "Contoso Ltd"))
    rep = scan(scanner, tmp_path, "wiper.exe", vendor_pe(data=b"\x90" * 64 + RANSOM))
    assert "YARA: Ransomware_Commands" in titles(rep, counted_only=True)
    assert rep.verdict != "clean"


def test_zscans_heuristic_yara_rules_do_not_count_on_signed_programs(scanner, tmp_path, signed_as):
    signed_as(Signature(signature.VALID, signature.CATALOG, "Microsoft Windows"))
    apis = b"VirtualAllocEx\x00WriteProcessMemory\x00CreateRemoteThread\x00"
    rep = scan(scanner, tmp_path, "debugger.exe", vendor_pe(data=b"\x90" * 64 + apis))
    rule = next(f for f in rep.findings if f.title == "YARA: Process_Injection_API_Strings")
    assert rule.heuristic and rule.not_counted
    assert rep.verdict == "clean"


def test_programs_changed_after_signing_are_flagged(scanner, tmp_path, signed_as):
    signed_as(Signature(signature.MISMATCH, signature.EMBEDDED, "Adobe Inc.",
                        "the file was changed after it was signed"))
    rep = scan(scanner, tmp_path, "Acrobat.dll", vendor_pe())
    assert "Changed after it was signed" in titles(rep)
    assert rep.score == 30 and rep.verdict == "suspicious"     # 15 for the change, 15 for the hints


def test_a_certificate_windows_distrusts_is_high(scanner, tmp_path, signed_as):
    signed_as(Signature(signature.DISTRUSTED, signature.EMBEDDED, "Stolen Cert Co"))
    rep = scan(scanner, tmp_path, "update.exe", vendor_pe())
    finding = next(f for f in rep.findings if f.title == "Signed with a certificate Windows distrusts")
    assert finding.severity == 4 and rep.verdict == "suspicious"


def test_an_invalid_signature_is_noted_but_lowers_nothing(scanner, tmp_path, signed_as):
    signed_as(Signature(signature.UNTRUSTED, signature.EMBEDDED, "EaseUS",
                        "the certificate has expired and the signature has no timestamp"))
    rep = scan(scanner, tmp_path, "Main.exe", vendor_pe())
    assert "Signature not valid" in titles(rep) and rep.verdict == "suspicious" and rep.score == 15


# ------------------------------------------------------------ when the check runs

def test_no_check_when_a_signature_could_change_nothing(scanner, tmp_path, signed_as):
    asked = signed_as(Signature(signature.VALID, signature.EMBEDDED, "Contoso Ltd"))
    plain = build_pe([(b".text", b"\x90" * 300 + b"\xc3", CODE_RX)], imports={"KERNEL32.dll": ["ExitProcess"]})
    rep = scan(scanner, tmp_path, "plain.exe", plain)                 # no warning signs, no signature
    assert asked == [] and not [f for f in rep.findings if f.severity >= 2]
    scan(scanner, tmp_path, "signed.exe", vendor_pe(data=b"\xc3"))    # an embedded signature: verify it
    assert asked == ["signed.exe"]


def test_a_failed_check_changes_nothing(scanner, tmp_path, signed_as):
    signed_as(None)
    rep = scan(scanner, tmp_path, "tool.exe", vendor_pe())
    assert rep.signature is None and rep.verdict == "suspicious"


def test_archive_members_are_not_signature_checked(scanner, tmp_path, signed_as):
    asked = signed_as(Signature(signature.VALID, signature.EMBEDDED, "Contoso Ltd"))
    rep = scan(scanner, tmp_path, "tools.zip", make_zip({"tool.exe": vendor_pe()}))
    assert asked == [] and rep.verdict == "suspicious"


def test_no_signatures_option(tmp_path, signed_as, capsys):
    asked = signed_as(Signature(signature.VALID, signature.EMBEDDED, "Contoso Ltd"))
    (tmp_path / "tool.exe").write_bytes(vendor_pe())
    assert main(["--no-community", "-q", "--no-color", "--no-signatures", str(tmp_path)]) == 1
    assert asked == []


def test_the_summary_says_how_many_signed_programs_were_not_flagged(tmp_path, signed_as, capsys):
    signed_as(Signature(signature.VALID, signature.CATALOG, "Microsoft Windows"))
    (tmp_path / "tool.exe").write_bytes(vendor_pe())
    assert main(["--no-community", "--json", str(tmp_path)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["signed_not_flagged"] == 1
    assert data["files"][0]["signature"]["signer"] == "Microsoft Windows"
    assert main(["--no-community", "-v", "--no-color", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "1 validly signed program(s) with only general warning signs not flagged" in out
    assert "[not counted: validly signed by Microsoft Windows]" in out
    assert "signature=valid (Microsoft Windows)" in out


# ------------------------------------------------------------ smaller fixes

def test_a_signature_block_is_not_appended_data(tmp_path):
    from zscan.analysis import pe_findings
    blob = os.urandom(6000)
    signed = vendor_pe(certificate=blob)
    offset, size = certificate_table(signed)
    assert signed[offset + 8:offset + 8 + len(blob)] == blob and offset + size == len(signed)
    assert "Appended overlay data" not in [f.title for f in pe_findings(signed)]
    # Data appended before the signature (installers carry their payload there) still counts.
    installer = build_pe([(b".text", b"\xc3", CODE_RX)], overlay=os.urandom(5000), certificate=blob)
    overlay = next(f for f in pe_findings(installer) if f.title == "Appended overlay data")
    assert overlay.detail.startswith("5000 bytes")
    assert certificate_table(benign_pe()) is None and certificate_table(b"MZ" + b"\0" * 100) is None


def test_letter_runs_and_word_lists_are_not_base64():
    def has_blob(data):
        return "Large base64 blob" in [f.title for f in string_findings(data)]
    assert has_blob(b"x=" + base64.b64encode(os.urandom(300)) + b"\n")
    assert has_blob(b"x=" + base64.b64encode(b"The quick brown fox jumps over the lazy dog. " * 8))
    assert not has_blob(b"".join(bytes([c]) * 16 for c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"))   # lookup table
    assert not has_blob(b"abandonabilityableaboardabolishabortionaboveabroadabruptabsence" * 5)
    # A fake one first does not hide a real one later in the file.
    assert has_blob(b"J" * 400 + b"\n" + base64.b64encode(os.urandom(300)))


# ------------------------------------------------------------ the real check, on Windows

def test_nothing_is_checked_off_windows():
    if sys.platform == "win32":
        pytest.skip("this is the non-Windows behaviour")
    assert signature.check(sys.executable) is None


def _embedded_signed_program():
    candidates = [sys.executable,
                  r"C:\Program Files\PowerShell\7\pwsh.exe",
                  r"C:\Program Files\Git\cmd\git.exe",
                  r"C:\Windows\System32\drivers\ntfs.sys",
                  r"C:\Windows\explorer.exe"]
    for c in candidates:
        if os.path.isfile(c):
            sig = signature.check(c)
            if sig and sig.status == signature.VALID and sig.kind == signature.EMBEDDED:
                return Path(c), sig
    pytest.skip("no program with a valid embedded signature found")


@on_windows
def test_a_windows_system_file_is_validly_signed():
    sig = signature.check(r"C:\Windows\System32\kernel32.dll")
    assert sig is not None and sig.status == signature.VALID, sig
    assert "Microsoft" in sig.signer


@on_windows
def test_a_hand_built_program_is_not_signed(tmp_path):
    p = tmp_path / "plain.exe"
    p.write_bytes(benign_pe())
    sig = signature.check(p)
    assert sig is not None and sig.status == signature.NOT_SIGNED, sig


@on_windows
def test_a_changed_copy_of_a_signed_program_no_longer_matches(tmp_path):
    import pefile
    original, sig = _embedded_signed_program()
    copy = tmp_path / original.name
    shutil.copyfile(original, copy)
    assert signature.check(copy).status == signature.VALID       # a copy keeps its signature
    data = bytearray(copy.read_bytes())
    first = pefile.PE(data=bytes(data), fast_load=True).sections[0]
    data[first.PointerToRawData + 64] ^= 0xFF
    copy.write_bytes(bytes(data))
    changed = signature.check(copy)
    assert changed is not None and changed.status == signature.MISMATCH, changed


@on_windows
def test_scanning_a_signed_program_on_windows(tmp_path):
    original, sig = _embedded_signed_program()
    rep = Scanner(YaraEngine(community=False)).scan_file(original)
    assert rep.signature["status"] == "valid" and rep.signature["signer"] == sig.signer
