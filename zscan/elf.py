"""Small, dependency-free ELF reader plus heuristics for Linux programs.

Written for hostile input: every read is bounds-checked, and nothing here
raises on a malformed file. The file is only ever read as bytes.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field

from .analysis import PACKING, Finding, shannon_entropy

ET_EXEC, ET_DYN = 2, 3
PT_LOAD = 1
PF_X, PF_W = 1, 2
SHT_NOBITS, SHT_DYNSYM = 8, 11
SHF_EXECINSTR = 4
MAX_HEADERS = 4096
MAX_SYMBOLS = 200_000
ENTROPY_SAMPLE = 4 * 1024 * 1024    # bytes of a code section to measure


@dataclass
class Segment:
    type: int
    flags: int
    vaddr: int
    filesz: int
    memsz: int


@dataclass
class Section:
    name: str
    type: int
    flags: int
    offset: int
    size: int
    link: int


@dataclass
class Elf:
    bits: int
    etype: int
    entry: int
    segments: list = field(default_factory=list)
    sections: list = field(default_factory=list)
    imports: set = field(default_factory=set)   # undefined dynamic symbols
    shnum: int = 0                              # section count the header claims
    sections_in_file: bool = True               # False if the table runs past EOF


def _cstr(data: bytes, start: int, limit: int, maxlen: int = 128) -> str:
    if start < 0 or start >= limit:
        return ""
    stop = min(limit, start + maxlen)
    end = data.find(b"\0", start, stop)
    return data[start:end if end >= 0 else stop].decode("latin-1")


def parse(data: bytes) -> Elf | None:
    """Return what could be read, or None if there is no usable ELF header."""
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[4] not in (1, 2) or data[5] not in (1, 2):
        return None
    bits = 32 if data[4] == 1 else 64
    e = "<" if data[5] == 1 else ">"
    try:
        if bits == 64:
            hdr = struct.unpack_from(e + "HHIQQQIHHHHHH", data, 16)
        else:
            hdr = struct.unpack_from(e + "HHIIIIIHHHHHH", data, 16)
    except struct.error:
        return None
    etype, _machine, _ver, entry, phoff, shoff, _flags, _ehsize, phentsize, phnum, shentsize, shnum, shstrndx = hdr
    elf = Elf(bits=bits, etype=etype, entry=entry, shnum=shnum)
    size = len(data)
    try:
        # ---- program headers
        ph_fmt = e + ("IIQQQQQQ" if bits == 64 else "IIIIIIII")
        ph_len = struct.calcsize(ph_fmt)
        if phentsize >= ph_len:
            for i in range(min(phnum, MAX_HEADERS)):
                off = phoff + i * phentsize
                if off + ph_len > size:
                    break
                f = struct.unpack_from(ph_fmt, data, off)
                if bits == 64:
                    ptype, pflags, _po, vaddr, _pa, filesz, memsz, _al = f
                else:
                    ptype, _po, vaddr, _pa, filesz, memsz, pflags, _al = f
                elf.segments.append(Segment(ptype, pflags, vaddr, filesz, memsz))

        # ---- section headers
        sh_fmt = e + ("IIQQQQIIQQ" if bits == 64 else "IIIIIIIIII")
        sh_len = struct.calcsize(sh_fmt)
        if shnum and shoff and shentsize >= sh_len:
            if shoff + shnum * shentsize > size or shnum > MAX_HEADERS:
                elf.sections_in_file = False
            else:
                raw = []
                for i in range(shnum):
                    (name, typ, flags, _addr, off, ssize, link, _info, _al, _es) = \
                        struct.unpack_from(sh_fmt, data, shoff + i * shentsize)
                    raw.append((name, typ, flags, off, ssize, link))
                names_off, names_size = (raw[shstrndx][3], raw[shstrndx][4]) if shstrndx < len(raw) else (0, 0)
                names_end = min(size, names_off + names_size)
                for name, typ, flags, off, ssize, link in raw:
                    elf.sections.append(Section(_cstr(data, names_off + name, names_end),
                                                typ, flags, off, ssize, link))

        # ---- dynamic symbols: the undefined ones are what the program imports
        sym_fmt = e + ("IBBHQQ" if bits == 64 else "IIIBBH")
        sym_len = struct.calcsize(sym_fmt)
        for sec in elf.sections:
            if sec.type != SHT_DYNSYM or sec.link >= len(elf.sections):
                continue
            strtab = elf.sections[sec.link]
            str_end = min(size, strtab.offset + strtab.size)
            count = min(sec.size // sym_len, MAX_SYMBOLS)
            if sec.offset + count * sym_len > size:
                continue
            for i in range(count):
                f = struct.unpack_from(sym_fmt, data, sec.offset + i * sym_len)
                st_name, shndx = (f[0], f[3]) if bits == 64 else (f[0], f[5])
                if shndx == 0 and st_name:
                    elf.imports.add(_cstr(data, strtab.offset + st_name, str_end))
    except (struct.error, IndexError, ValueError, OverflowError):
        pass  # keep whatever was read before the file stopped making sense
    return elf


EXEC_CALLS = {"execve", "execv", "execvp", "execl", "execlp", "system", "popen"}


def elf_findings(data: bytes) -> list[Finding]:
    elf = parse(data)
    if elf is None:
        return [Finding("elf", "Malformed ELF header", 2)]
    if elf.etype not in (ET_EXEC, ET_DYN):
        return []   # object files, core dumps: nothing useful to say

    out: list[Finding] = []
    loads = [s for s in elf.segments if s.type == PT_LOAD]

    rwx = [s for s in loads if s.flags & PF_X and s.flags & PF_W]
    if rwx:
        out.append(Finding("elf", "Memory segment is writable and executable", 3,
                           f"{len(rwx)} segment(s); normal programs keep code read-only", group=PACKING))

    if elf.entry and loads and not any(
            s.flags & PF_X and s.vaddr <= elf.entry < s.vaddr + max(s.memsz, s.filesz) for s in loads):
        out.append(Finding("elf", "Entry point is outside the executable segments", 3,
                           f"entry {elf.entry:#x}"))

    if elf.shnum == 0:
        out.append(Finding("elf", "No section header table", 2,
                           "typical of packed or hand-stripped programs", group=PACKING))
    elif not elf.sections_in_file:
        out.append(Finding("elf", "Section header table lies outside the file", 2,
                           "truncated or tampered with"))

    for sec in elf.sections:
        if sec.flags & SHF_EXECINSTR and sec.type != SHT_NOBITS and sec.size > 1024 \
                and sec.offset + sec.size <= len(data):
            ent = shannon_entropy(data[sec.offset:sec.offset + min(sec.size, ENTROPY_SAMPLE)])
            if ent > 7.2:
                out.append(Finding("elf", f"High-entropy code section '{sec.name}'", 3,
                                   f"entropy {ent:.2f} (packed or encrypted code?)", group=PACKING))

    # Weak hints. Legitimate tools (ssh, nc, strace) import these too, so they
    # are LOW and only matter when combined with other findings.
    if {"socket", "connect", "dup2"} <= elf.imports and elf.imports & EXEC_CALLS:
        out.append(Finding("elf", "Imports suggest reverse-shell behavior", 2,
                           "socket + connect + dup2 + exec"))
    if "ptrace" in elf.imports:
        out.append(Finding("elf", "Imports ptrace", 2, "debugger, anti-debugging or process injection"))
    return out
