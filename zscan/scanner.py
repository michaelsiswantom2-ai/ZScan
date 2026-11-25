"""Ties the analysers together for one file or a directory tree."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from . import analysis
from .analysis import FileReport, Finding
from .elf import elf_findings
from .archives import ARCHIVE_TYPES, Budget, Limits, iter_members
from .yara_engine import YaraEngine

MAX_BYTES_DEFAULT = 64 * 1024 * 1024
BINARY_TYPES = {"pe", "elf", "macho", "macho-fat"}
# File types worth spending a slow VirusTotal lookup on even when they look clean.
VT_TYPES = BINARY_TYPES | {"script", "ole", "pdf", "zip"}
ARCHIVE_SEP = "!"   # shown as outer.zip!inner/file.exe


class Scanner:
    def __init__(self, yara_engine: YaraEngine | None = None, max_bytes: int = MAX_BYTES_DEFAULT,
                 unpack: bool = True, limits: Limits | None = None,
                 hash_list=None, online=None):
        self.yara = yara_engine or YaraEngine()
        self.max_bytes = max_bytes
        self.unpack = unpack
        self.limits = limits or Limits(max_member_bytes=max_bytes)
        self.hash_list = hash_list   # intel.HashList or None
        self.online = online         # intel.OnlineIntel or None

    # ------------------------------------------------------------ files

    def scan_file(self, path: Path) -> FileReport:
        rep = FileReport(path=str(path))
        try:
            rep.size = path.stat().st_size
            if rep.size > self.max_bytes:
                rep.skipped = f"larger than {self.max_bytes // (1024 * 1024)} MiB"
                return rep
            data = path.read_bytes()
        except OSError as e:
            rep.error = f"cannot read: {e.strerror or e}"
            return rep
        return self.scan_bytes(data, str(path), Budget(self.limits), depth=0)

    def scan_bytes(self, data: bytes, display: str, budget: Budget, depth: int) -> FileReport:
        rep = FileReport(path=display, size=len(data))
        rep.hashes = analysis.hashes(data)
        rep.entropy = round(analysis.shannon_entropy(data), 3)
        rep.file_type = analysis.detect_type(data)

        f = rep.findings
        found, notes = self.yara.scan(data)
        f += found
        rep.unscanned += notes
        # Compressed containers are noise to a text search; their members get
        # their own string scan once unpacked.
        compressed = self.unpack and rep.file_type in ("zip", "gzip")
        strings = [] if compressed else analysis.string_findings(data)
        if rep.file_type in BINARY_TYPES:
            # Compiled programs embed lots of harmless text (help strings, docs,
            # e.g. Go tools mention Invoke-Expression), so string hits count less.
            for s in strings:
                s.severity = max(1, s.severity - 1)
        f += strings
        if rep.file_type == "pe":
            f += analysis.pe_findings(data)
        elif rep.file_type == "elf":
            f += elf_findings(data)
        # Whole-file entropy matters mostly for executables; compressed formats
        # (zip, gzip, pdf streams) are naturally near 8.0.
        if rep.entropy > 7.5 and rep.size > 4096 and rep.file_type in ("pe", "elf", "data", "script"):
            f.append(Finding("entropy", "Very high file entropy", 2,
                             f"{rep.entropy} bits/byte (encrypted or packed content?)"))

        if self.unpack and rep.file_type in ARCHIVE_TYPES:
            self._scan_archive(rep, data, budget, depth)

        self._intel(rep)
        f.sort(key=lambda x: -x.severity)
        return rep

    def _scan_archive(self, rep: FileReport, data: bytes, budget: Budget, depth: int) -> None:
        if depth >= self.limits.max_depth:
            rep.findings.append(Finding("archive", "Archive nested too deep, not unpacked", 2,
                                        f"more than {self.limits.max_depth} levels"))
            return
        encrypted = []
        for m in iter_members(data, rep.file_type, budget):
            if m.encrypted:
                encrypted.append(m.name)
                continue
            if m.bomb:
                rep.findings.append(Finding("archive", "Possible zip bomb", 4, f"{m.name}: {m.note}"))
                continue
            if m.data is None:
                rep.findings.append(Finding("archive", "Archive member not scanned", 1,
                                            f"{m.name}: {m.note}" if m.name else m.note))
                continue
            child = self.scan_bytes(m.data, f"{rep.path}{ARCHIVE_SEP}{m.name}", budget, depth + 1)
            rep.children.append(child)
        if encrypted:
            # Password-protected archives are a classic way to slip malware past
            # mail gateways, since nobody can look inside without the password.
            rep.findings.append(Finding("archive", "Password-protected archive members", 3,
                                        f"{len(encrypted)} encrypted, e.g. {encrypted[0]}"))
        # Let the worst member drive the archive's own verdict.
        worst = None
        for c in rep.iter_tree():
            if c is rep or c.verdict in ("clean", "skipped", "error"):
                continue
            top = max((x.severity for x in c.findings), default=0)
            if worst is None or (top, c.score) > worst[0]:
                worst = ((top, c.score), c)
        if worst:
            (top, _), c = worst
            inner = c.path[len(rep.path) + 1:]
            rep.findings.append(Finding("archive", f"Contains {c.verdict} file", max(top, 3), inner))

    def _intel(self, rep: FileReport) -> None:
        sha = rep.hashes.get("sha256")
        if not sha:
            return
        if self.hash_list is not None:
            rep.findings += self.hash_list.lookup(rep.hashes)
        if self.online is not None:
            worth_vt = rep.file_type in VT_TYPES or rep.verdict != "clean"
            rep.findings += self.online.lookup(sha, worth_vt)

    # ------------------------------------------------------------ trees

    def iter_paths(self, target: Path, follow_symlinks: bool = False) -> Iterator[Path]:
        if target.is_file():
            yield target
            return
        for root, dirs, files in os.walk(target, followlinks=follow_symlinks):
            dirs.sort()
            for name in sorted(files):
                p = Path(root) / name
                if p.is_symlink() and not follow_symlinks:
                    continue
                if p.is_file():
                    yield p

    def scan(self, target: Path) -> Iterator[FileReport]:
        """Yield top-level reports. Archive members hang off .children."""
        for p in self.iter_paths(target):
            yield self.scan_file(p)
