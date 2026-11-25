import os

import pytest

from zscan import elf
from zscan.scanner import Scanner
from zscan.yara_engine import YaraEngine

from samples import build_elf

LAYOUTS = [(64, False), (32, False), (64, True), (32, True)]


@pytest.fixture(scope="module")
def scanner():
    return Scanner(YaraEngine(community=False))


def scan(scanner, tmp_path, data):
    p = tmp_path / "prog"
    p.write_bytes(data)
    return scanner.scan_file(p)


def titles(rep):
    return [f.title for f in rep.findings]


@pytest.mark.parametrize("bits,big", LAYOUTS)
def test_parser_reads_every_layout(bits, big):
    e = elf.parse(build_elf(bits=bits, big=big, imports=("socket", "printf")))
    assert (e.bits, e.etype) == (bits, 2)
    assert [s.name for s in e.sections] == ["", ".text", ".dynsym", ".dynstr", ".shstrtab"]
    assert [(s.type, s.flags) for s in e.segments] == [(1, 5)]
    assert e.imports == {"socket", "printf"}
    assert e.entry == 0x400000 + (64 + 56 if bits == 64 else 52 + 32)


@pytest.mark.parametrize("bits,big", LAYOUTS)
def test_benign_elf_is_clean(scanner, tmp_path, bits, big):
    rep = scan(scanner, tmp_path, build_elf(bits=bits, big=big, imports=("printf", "malloc")))
    assert rep.file_type == "elf"
    assert rep.findings == []
    assert rep.verdict == "clean"


def test_writable_executable_segment(scanner, tmp_path):
    rep = scan(scanner, tmp_path, build_elf(load_flags=7))
    assert "Memory segment is writable and executable" in titles(rep)
    assert rep.verdict == "suspicious"


def test_entry_outside_executable_segment(scanner, tmp_path):
    assert "Entry point is outside the executable segments" in titles(
        scan(scanner, tmp_path, build_elf(entry=0x900000)))
    # entry inside a segment that is not executable is just as wrong
    assert "Entry point is outside the executable segments" in titles(
        scan(scanner, tmp_path, build_elf(load_flags=4)))


def test_missing_section_table(scanner, tmp_path):
    rep = scan(scanner, tmp_path, build_elf(with_sections=False))
    assert "No section header table" in titles(rep)
    assert rep.verdict == "clean"          # weak signal on its own


def test_section_table_past_end_of_file(scanner, tmp_path):
    rep = scan(scanner, tmp_path, build_elf(shoff_delta=10_000_000))
    assert "Section header table lies outside the file" in titles(rep)


def test_high_entropy_code_section(scanner, tmp_path):
    rep = scan(scanner, tmp_path, build_elf(text=os.urandom(8192)))
    assert any(t.startswith("High-entropy code section '.text'") for t in titles(rep))


def test_import_hints_are_weak(scanner, tmp_path):
    rep = scan(scanner, tmp_path, build_elf(imports=("socket", "connect", "dup2", "execve", "ptrace")))
    assert "Imports suggest reverse-shell behavior" in titles(rep)
    assert "Imports ptrace" in titles(rep)
    assert rep.verdict == "clean"          # 5 + 5 points: below the suspicious line


def test_packed_style_elf_adds_up(scanner, tmp_path):
    """No sections + RWX + odd entry + random code: what a packer's output looks like."""
    rep = scan(scanner, tmp_path, build_elf(load_flags=7, entry=0x900000, with_sections=False,
                                            text=os.urandom(16384)))
    assert rep.verdict == "suspicious"


def test_upx_elf_rule(scanner, tmp_path):
    fake = (build_elf(with_sections=False)
            + b"UPX!" + b"$Id: UPX 4.2.4 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $")
    assert "YARA: UPX_Packed" in titles(scan(scanner, tmp_path, fake))
    # the marker string alone, without an ELF header, must not trigger the ELF branch
    assert "YARA: UPX_Packed" not in titles(scan(scanner, tmp_path, b"notes about UPX! and $Id: UPX"))


def test_miner_pool_url(scanner, tmp_path):
    rep = scan(scanner, tmp_path, b"pool=stratum+tcp://pool.example.invalid:3333\nuser=x\n")
    assert "Crypto-miner pool URL" in titles(rep)


def test_truncated_elf_does_not_crash(scanner, tmp_path):
    good = build_elf(imports=("socket",))
    for cut in (4, 20, 52, 63, 64, 100, 130, len(good) - 10):
        rep = scan(scanner, tmp_path, good[:cut])
        assert rep.verdict in ("clean", "suspicious", "malicious")
