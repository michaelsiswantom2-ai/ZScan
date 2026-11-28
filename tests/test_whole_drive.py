"""Scanning a whole drive: cloud-only files, junctions, folders that cannot be opened,
report files, odd file names and progress lines. Mostly matters on Windows."""
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import zscan.cli as cli
import zscan.scanner as scanner_mod
from zscan.cli import main
from zscan.scanner import CLOUD_ONLY, Scanner, is_junction, not_local
from zscan.yara_engine import YaraEngine

from samples import EICAR

THAI = "ไฟล์ทดสอบ.txt"      # "test file" in Thai


def make_tree(root: Path, files: dict) -> Path:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


# ------------------------------------------------------------ cloud-only files

def test_windows_cloud_attributes_mean_not_local():
    assert not_local(SimpleNamespace(st_file_attributes=0x400000))    # OneDrive online-only
    assert not_local(SimpleNamespace(st_file_attributes=0x40000))     # recall on open
    assert not_local(SimpleNamespace(st_file_attributes=0x1000 | 0x20))  # offline
    assert not not_local(SimpleNamespace(st_file_attributes=0x20))    # ordinary archive bit
    assert not not_local(SimpleNamespace())                           # Linux and macOS: no attributes


def test_cloud_only_files_are_skipped_without_reading_them(tmp_path, monkeypatch):
    f = tmp_path / "Documents" / "big-video.mp4"
    make_tree(tmp_path, {"Documents/big-video.mp4": EICAR})
    monkeypatch.setattr(scanner_mod, "not_local", lambda st: True)

    def must_not_read(self):
        raise AssertionError(f"read {self}, which would download it")
    monkeypatch.setattr(Path, "read_bytes", must_not_read)
    rep = Scanner(YaraEngine(community=False)).scan_file(f)
    assert rep.verdict == "skipped" and rep.skipped == CLOUD_ONLY


def test_summary_counts_skip_reasons(tmp_path, monkeypatch, capsys):
    make_tree(tmp_path, {"a.txt": b"hello", "b.bin": b"\0" * (2 * 1024 * 1024)})
    assert main(["--no-community", "--max-size", "1", str(tmp_path)]) == 0
    assert "skipped: 1 larger than 1 MiB" in capsys.readouterr().out

    monkeypatch.setattr(scanner_mod, "not_local", lambda st: True)
    main(["--no-community", "--json", str(tmp_path)])
    summary = json.loads(capsys.readouterr().out)["summary"]
    assert summary["skipped"] == 2 and summary["skipped_reasons"] == {CLOUD_ONLY: 2}


# ------------------------------------------------------------ junctions

def test_junctions_are_not_entered(tmp_path, monkeypatch):
    make_tree(tmp_path, {"real/a.txt": b"a", "linked/b.txt": b"b"})
    monkeypatch.setattr(scanner_mod, "is_junction", lambda p: os.path.basename(p) == "linked")
    found = [p.relative_to(tmp_path).as_posix() for p in Scanner(YaraEngine(community=False)).iter_paths(tmp_path)]
    assert found == ["real/a.txt"]


def test_ordinary_folders_are_not_junctions(tmp_path):
    assert not is_junction(str(tmp_path)) and not is_junction(str(tmp_path / "missing"))


@pytest.mark.skipif(sys.platform != "win32", reason="directory junctions exist only on Windows")
def test_a_real_junction_loop_is_walked_once(tmp_path):
    make_tree(tmp_path, {"top/file.txt": b"x"})
    # A junction pointing back at its own parent, like the old "Application Data" links.
    subprocess.run(["cmd", "/c", "mklink", "/J", str(tmp_path / "top" / "loop"), str(tmp_path / "top")],
                   check=True, capture_output=True)
    assert is_junction(str(tmp_path / "top" / "loop"))
    found = list(Scanner(YaraEngine(community=False)).iter_paths(tmp_path))
    assert [p.name for p in found] == ["file.txt"]


# ------------------------------------------------------------ folders that cannot be opened

def deny(monkeypatch, blocked: Path):
    real = os.scandir

    def scandir(path="."):
        if os.path.abspath(path) == str(blocked):
            raise PermissionError(13, "Permission denied", str(path))
        return real(path)
    monkeypatch.setattr(os, "scandir", scandir)


def test_unopenable_folders_are_reported_not_hidden(tmp_path, monkeypatch, capsys):
    make_tree(tmp_path, {"ok/a.txt": b"hello", "locked/b.txt": EICAR})
    deny(monkeypatch, tmp_path / "locked")
    code = main(["--no-community", str(tmp_path)])
    out = capsys.readouterr().out
    assert "Folders that could not be opened (1)" in out and "locked" in out
    assert "1 folder(s) could not be opened" in out
    assert code == 3            # nothing found, but part of the tree went unchecked


def test_unopenable_folders_in_json(tmp_path, monkeypatch, capsys):
    make_tree(tmp_path, {"ok/a.txt": b"hello", "locked/b.txt": b"x"})
    deny(monkeypatch, tmp_path / "locked")
    main(["--no-community", "--json", "-j", "2", str(tmp_path)])
    data = json.loads(capsys.readouterr().out)
    assert data["summary"]["unreadable_folders"] == 1
    assert data["unreadable_folders"][0].startswith(str(tmp_path / "locked"))


# ------------------------------------------------------------ report file, names, progress

def test_report_file_is_utf8_and_skips_itself(tmp_path, capsys):
    make_tree(tmp_path, {THAI: b"hello", "eicar.com": EICAR})
    report = tmp_path / "report.txt"
    assert main(["--no-community", "-v", "-o", str(report), str(tmp_path)]) == 2
    text = report.read_text(encoding="utf-8")
    assert THAI in text and "MALICIOUS" in text and "eicar.com" in text
    assert "report.txt" not in text.replace(str(report), "")      # it did not scan its own report
    err = capsys.readouterr().err
    assert "Scanned 2 file(s)" in err and f"report written to {report}" in err


def test_names_the_console_cannot_show_do_not_stop_the_scan(tmp_path, monkeypatch):
    make_tree(tmp_path, {THAI: b"hello", "z.txt": b"bye"})
    console = io.TextIOWrapper(io.BytesIO(), encoding="cp1252")    # an English Windows code page
    monkeypatch.setattr(sys, "stdout", console)
    assert main(["--no-community", "-v", "--no-color", str(tmp_path)]) == 0
    console.flush()
    shown = console.buffer.getvalue().decode("cp1252")
    assert "\\u0e44" in shown and "z.txt" in shown and "Scanned 2 file(s)" in shown


def test_progress_lines(tmp_path, monkeypatch, capsys):
    make_tree(tmp_path, {f"f{i}.txt": b"hello" for i in range(3)})
    monkeypatch.setattr(cli, "PROGRESS_EVERY", 0.0)
    main(["--no-community", "--progress", str(tmp_path)])
    err = capsys.readouterr().err
    assert "progress: 1 files in 0:00:00" in err and "progress: 3 files" in err
