"""YARA rule loading and matching.

Two rule sets:
  * local rules: the bundled starter rules, or whatever --rules points at
  * community rules: the YARA-Forge package fetched by `zscan --update`,
    stored precompiled in the cache folder and loaded automatically
"""
from __future__ import annotations

import io
import json
import re
import time
import warnings
import zipfile
from pathlib import Path

from .analysis import Finding
from .config import cache_dir

try:
    import yara  # optional
except ImportError:  # pragma: no cover
    yara = None

DEFAULT_RULES = Path(__file__).parent / "rules"
FORGE_URL = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{pack}.zip"
FORGE_PACKS = ("core", "extended", "full")
MAX_DOWNLOAD = 100 * 1024 * 1024


def community_dir() -> Path:
    return cache_dir() / "rules"


def forge_severity(score) -> int:
    """Map a YARA-Forge 0-100 'score' to zscan severity.

    YARA-Forge follows the THOR convention: 40-59 notable, 60-74 suspicious,
    75+ alert. Only the strongest hits go straight to CRIT.
    """
    try:
        s = int(score)
    except (TypeError, ValueError):
        return 3
    if s >= 85:
        return 5
    if s >= 70:
        return 4
    if s >= 60:
        return 3
    return 2


class YaraEngine:
    def __init__(self, rule_paths: list[Path] | None = None, community: bool = True):
        self.rule_paths = [Path(p) for p in rule_paths] if rule_paths else None   # so worker processes
        self.use_community = community                                           # can build the same engine
        self.local = None
        self.community = None
        self.community_info: dict = {}
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
        if files:
            self.local = yara.compile(filepaths=files)
        else:
            self.error = "no YARA rule files found"
        if community:
            self._load_community()

    def _load_community(self) -> None:
        compiled = community_dir() / "yara-forge.yarc"
        if not compiled.exists():
            return
        try:
            self.community = yara.load(str(compiled))
            info = compiled.with_suffix(".json")
            if info.exists():
                self.community_info = json.loads(info.read_text())
        except (yara.Error, OSError, ValueError) as e:
            self.error = f"community rules unreadable ({e}); run zscan --update"

    def scan(self, data: bytes) -> tuple[list[Finding], list[str]]:
        """Match all loaded rules. Returns (findings, notes); notes say what could not be checked."""
        out: list[Finding] = []
        notes: list[str] = []
        if self.local is not None:
            matches, note = _run(self.local, data, 30, "bundled/custom")
            notes += [note] if note else []
            for m in matches:
                sev = int(m.meta.get("severity", 3))
                out.append(Finding("yara", f"YARA: {m.rule}", sev, m.meta.get("description", "")))
        if self.community is not None:
            matches, note = _run(self.community, data, 60, "community")
            notes += [note] if note else []
            for m in matches:
                sev = forge_severity(m.meta.get("score"))
                detail = m.meta.get("description", "")
                if m.meta.get("author"):
                    detail += f" (by {m.meta['author']})"
                out.append(Finding("yara", f"YARA-Forge: {m.rule}", sev, detail.strip()))
        return out, notes


def _run(rules, data: bytes, timeout: int, label: str):
    """rules.match() that turns timeouts and engine errors into a note instead of a crash."""
    try:
        with warnings.catch_warnings():
            # YARA warns (it does not fail) when one string matches over a million
            # times, e.g. a short hex string in a big zero-filled file. Results stay valid.
            warnings.simplefilter("ignore", RuntimeWarning)
            return rules.match(data=data, timeout=timeout), None
    except yara.TimeoutError:
        return [], f"{label} YARA rules timed out after {timeout}s"
    except yara.Error as e:
        return [], f"{label} YARA rules failed: {e}"


def update_community(pack: str = "core", fetch=None) -> dict:
    """Download a YARA-Forge rule package, compile it, and store it in the cache.

    `fetch(url) -> bytes` can be swapped out in tests.
    """
    if yara is None:
        raise RuntimeError("yara-python not installed")
    if pack not in FORGE_PACKS:
        raise ValueError(f"unknown pack {pack!r}; choose from {', '.join(FORGE_PACKS)}")
    url = FORGE_URL.format(pack=pack)
    blob = (fetch or _download)(url)
    try:
        zf = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as e:
        raise ValueError(f"download from {url} is not a zip: {e}") from e
    # Read only the one expected rule file; never extract the archive.
    names = [n for n in zf.namelist() if n.endswith(".yar") and "/" + f"yara-rules-{pack}.yar" in "/" + n]
    if not names:
        raise ValueError(f"no yara-rules-{pack}.yar inside {url}")
    info = zf.getinfo(names[0])
    if info.file_size > 4 * MAX_DOWNLOAD:
        raise ValueError("rule file unexpectedly large")
    source = zf.read(info).decode("utf-8", "replace")
    rules = yara.compile(source=source)  # raises if the package is broken

    d = community_dir()
    d.mkdir(parents=True, exist_ok=True)
    tmp = d / "yara-forge.yarc.tmp"
    rules.save(str(tmp))
    tmp.replace(d / "yara-forge.yarc")
    (d / "yara-forge.yar").write_text(source)  # kept for reading / grepping

    header = source[:2000]
    meta = {
        "pack": pack,
        "rules": len(list(rules)),
        "version": _header_field(header, "YARA-Forge Version"),
        "created": _header_field(header, "Creation Date"),
        "downloaded": time.strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
    }
    (d / "yara-forge.json").write_text(json.dumps(meta, indent=2))
    return meta


def _header_field(text: str, name: str) -> str:
    m = re.search(rf"\* {re.escape(name)}:\s*(.+)", text)
    return m.group(1).strip() if m else ""


def _download(url: str) -> bytes:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "zscan/0.2"})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("download larger than 100 MiB, refusing")
    return data
