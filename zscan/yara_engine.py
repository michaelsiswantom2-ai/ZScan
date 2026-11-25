"""YARA rule loading and matching."""
from __future__ import annotations

from pathlib import Path

from .analysis import Finding

try:
    import yara  # optional
except ImportError:  # pragma: no cover
    yara = None

DEFAULT_RULES = Path(__file__).parent / "rules"


class YaraEngine:
    def __init__(self, rule_paths: list[Path] | None = None):
        self.rules = None
        self.error = None
        if yara is None:
            self.error = "yara-python not installed; YARA matching disabled"
            return
        files = {}
        for p in rule_paths or [DEFAULT_RULES]:
            p = Path(p)
            candidates = sorted(p.rglob("*.yar")) + sorted(p.rglob("*.yara")) if p.is_dir() else [p]
            for f in candidates:
                files[f"{f.stem}_{len(files)}"] = str(f)
        if not files:
            self.error = "no YARA rule files found"
            return
        self.rules = yara.compile(filepaths=files)

    def scan(self, data: bytes) -> list[Finding]:
        if self.rules is None:
            return []
        out = []
        for m in self.rules.match(data=data, timeout=30):
            sev = int(m.meta.get("severity", 3))
            desc = m.meta.get("description", "")
            out.append(Finding("yara", f"YARA: {m.rule}", sev, desc))
        return out
