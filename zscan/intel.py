"""Hash lookups against threat-intel sources.

Only hashes are ever sent anywhere, never file contents. Online lookups are
off unless the user passes --intel.

Sources:
  * Local hash lists (offline): text files with one hash per line, optionally
    followed by a comma and a label. `zscan --update` can fetch the
    MalwareBazaar "recent" SHA-256 list into the cache.
  * MalwareBazaar API (needs a free abuse.ch Auth-Key in MALWAREBAZAAR_API_KEY).
  * VirusTotal API v3 (needs VT_API_KEY; free tier is 4 requests a minute).
  * CIRCL hashlookup (no key): tells you a file is *known good* (NSRL etc.).
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .analysis import Finding
from .config import cache_dir

USER_AGENT = "zscan/0.2 (+https://github.com/michaelsiswantom2-ai/zscan)"
CACHE_TTL = 24 * 3600
HASH_RE = re.compile(r"^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$")


# ---------------------------------------------------------------- local lists

class HashList:
    def __init__(self, paths: list[Path]):
        self.entries: dict[str, str] = {}
        for p in paths:
            self.load(Path(p))

    def load(self, path: Path) -> None:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                h, _, label = line.partition(",")
                h = h.strip().strip('"').lower()
                if HASH_RE.match(h):
                    self.entries[h] = label.strip().strip('"') or path.name

    def __len__(self):
        return len(self.entries)

    def lookup(self, hashes: dict) -> list[Finding]:
        for h in hashes.values():
            label = self.entries.get(h)
            if label:
                return [Finding("intel", "Hash on known-malware list", 5, label)]
        return []


def default_hash_lists() -> list[Path]:
    d = cache_dir() / "hashlists"
    return sorted(d.glob("*.txt")) if d.is_dir() else []


# ---------------------------------------------------------------- online

def _http(url: str, data: bytes | None = None, headers: dict | None = None,
          timeout: float = 15) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read() or b""


class OnlineIntel:
    """Queries online sources, with a small on-disk cache."""

    def __init__(self, http=_http, use_cache: bool = True):
        self.http = http
        self.mb_key = os.environ.get("MALWAREBAZAAR_API_KEY") or os.environ.get("ABUSE_CH_AUTH_KEY")
        self.vt_key = os.environ.get("VT_API_KEY")
        self.vt_interval = float(os.environ.get("VT_MIN_INTERVAL", "15"))
        self._vt_last = 0.0
        self.warnings: list[str] = []
        self.cache_path = cache_dir() / "intel-cache.json" if use_cache else None
        self.cache = self._load_cache()

    @property
    def sources(self) -> list[str]:
        s = ["CIRCL hashlookup"]
        if self.mb_key:
            s.append("MalwareBazaar")
        if self.vt_key:
            s.append("VirusTotal")
        return s

    # -- cache
    def _load_cache(self) -> dict:
        if not self.cache_path or not self.cache_path.exists():
            return {}
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            now = time.time()
            return {k: v for k, v in data.items() if now - v.get("t", 0) < CACHE_TTL}
        except (OSError, ValueError):
            return {}

    def save_cache(self) -> None:
        if not self.cache_path:
            return
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(self.cache), encoding="utf-8")
        except OSError:
            pass

    def _cached(self, source: str, sha256: str, fn):
        key = f"{source}:{sha256}"
        if key in self.cache:
            return self.cache[key]["r"]
        try:
            result = fn(sha256)
        except (OSError, ValueError) as e:  # network down, bad JSON, timeouts
            msg = f"{source} lookup failed: {e}"
            if msg not in self.warnings:
                self.warnings.append(msg)
            return None
        if result is not None:
            self.cache[key] = {"t": time.time(), "r": result}
        return result

    # -- sources: each returns a small JSON-able dict, or None on failure
    def _circl(self, sha256: str):
        code, body = self.http(f"https://hashlookup.circl.lu/lookup/sha256/{sha256}",
                               headers={"Accept": "application/json"})
        if code == 404:
            return {"known": False}
        if code != 200:
            raise OSError(f"HTTP {code}")
        d = json.loads(body)
        return {"known": True, "name": d.get("FileName") or d.get("ProductName") or "",
                "trust": d.get("hashlookup:trust")}

    def _bazaar(self, sha256: str):
        data = urllib.parse.urlencode({"query": "get_info", "hash": sha256}).encode()
        code, body = self.http("https://mb-api.abuse.ch/api/v1/", data=data,
                               headers={"Auth-Key": self.mb_key})
        if code != 200:
            raise OSError(f"HTTP {code}")
        d = json.loads(body)
        status = d.get("query_status")
        if status == "ok" and d.get("data"):
            e = d["data"][0]
            return {"found": True, "signature": e.get("signature") or "",
                    "tags": e.get("tags") or []}
        if status in ("hash_not_found", "no_results"):
            return {"found": False}
        raise OSError(f"MalwareBazaar says {status}")

    def _vt(self, sha256: str):
        wait = self._vt_last + self.vt_interval - time.time()
        if wait > 0:
            time.sleep(wait)
        self._vt_last = time.time()
        code, body = self.http(f"https://www.virustotal.com/api/v3/files/{sha256}",
                               headers={"x-apikey": self.vt_key})
        if code == 404:
            return {"found": False}
        if code != 200:
            raise OSError(f"HTTP {code}")
        attrs = json.loads(body).get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {"found": True, "malicious": stats.get("malicious", 0),
                "total": sum(stats.values()) or 0,
                "label": (attrs.get("popular_threat_classification") or {})
                .get("suggested_threat_label", "")}

    # -- public
    def lookup(self, sha256: str, worth_vt: bool) -> list[Finding]:
        out: list[Finding] = []
        if self.mb_key:
            r = self._cached("bazaar", sha256, self._bazaar)
            if r and r.get("found"):
                tags = ", ".join(r["tags"][:5])
                out.append(Finding("intel", "Known malware on MalwareBazaar", 5,
                                   " ".join(x for x in (r["signature"], f"[{tags}]" if tags else "") if x)))
        if self.vt_key and worth_vt:
            r = self._cached("vt", sha256, self._vt)
            if r and r.get("found"):
                m, total = r["malicious"], r["total"]
                if m >= 5:
                    out.append(Finding("intel", "Flagged by VirusTotal engines", 5,
                                       f"{m}/{total} {r['label']}".strip()))
                elif m >= 1:
                    out.append(Finding("intel", "Flagged by a few VirusTotal engines", 3,
                                       f"{m}/{total} {r['label']}".strip()))
                else:
                    out.append(Finding("intel", "Known to VirusTotal, no detections", 1, f"0/{total}"))
        r = self._cached("circl", sha256, self._circl)
        if r and r.get("known"):
            out.append(Finding("intel", "Known-good file (CIRCL hashlookup)", 1,
                               r.get("name") or "listed in NSRL or similar"))
        return out


# ---------------------------------------------------------------- feed update

BAZAAR_RECENT = "https://bazaar.abuse.ch/export/txt/sha256/recent/"


def update_bazaar_list(http=_http) -> tuple[Path, int]:
    """Download MalwareBazaar's recent SHA-256 list (last 48 h) into the cache."""
    code, body = http(BAZAAR_RECENT, timeout=60)
    if code != 200:
        raise OSError(f"HTTP {code} from {BAZAAR_RECENT}")
    hashes = [ln.strip().lower() for ln in body.decode("utf-8", "replace").splitlines()
              if ln.strip() and not ln.startswith("#") and HASH_RE.match(ln.strip())]
    if not hashes:
        raise ValueError("no hashes in MalwareBazaar response")
    d = cache_dir() / "hashlists"
    d.mkdir(parents=True, exist_ok=True)
    path = d / "malwarebazaar-recent.txt"
    path.write_text("# MalwareBazaar recent SHA-256 (abuse.ch, CC0)\n" +
                    "".join(f"{h},MalwareBazaar\n" for h in hashes), encoding="utf-8")
    return path, len(hashes)
