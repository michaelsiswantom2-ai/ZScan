"""Ties the analysers together for one file or a directory tree."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator

from . import analysis
from .analysis import FileReport, Finding
from .yara_engine import YaraEngine

MAX_BYTES_DEFAULT = 64 * 1024 * 1024
BINARY_TYPES = {"pe", "elf", "macho", "macho-fat"}


class Scanner:
    def __init__(self, yara_engine: YaraEngine | None = None, max_bytes: int = MAX_BYTES_DEFAULT):
        self.yara = yara_engine or YaraEngine()
        self.max_bytes = max_bytes

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

        rep.hashes = analysis.hashes(data)
        rep.entropy = round(analysis.shannon_entropy(data), 3)
        rep.file_type = analysis.detect_type(data)

        f = rep.findings
        f += self.yara.scan(data)
        strings = analysis.string_findings(data)
        if rep.file_type in BINARY_TYPES:
            # Compiled programs embed lots of harmless text (help strings, docs,
            # e.g. Go tools mention Invoke-Expression), so string hits count less.
            for s in strings:
                s.severity = max(1, s.severity - 1)
        f += strings
        if rep.file_type == "pe":
            f += analysis.pe_findings(data)
        # Whole-file entropy matters mostly for executables; compressed formats
        # (zip, pdf streams) are naturally near 8.0.
        if rep.entropy > 7.5 and rep.size > 4096 and rep.file_type in ("pe", "elf", "data", "script"):
            f.append(Finding("entropy", "Very high file entropy", 2,
                             f"{rep.entropy} bits/byte (encrypted or packed content?)"))
        f.sort(key=lambda x: -x.severity)
        return rep

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
        for p in self.iter_paths(target):
            yield self.scan_file(p)
