"""Where zscan keeps downloaded rules, hash lists and caches."""
from __future__ import annotations

import os
from pathlib import Path


def cache_dir() -> Path:
    """$ZSCAN_HOME, else $XDG_CACHE_HOME/zscan, else ~/.cache/zscan."""
    if os.environ.get("ZSCAN_HOME"):
        return Path(os.environ["ZSCAN_HOME"])
    base = os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache"
    return Path(base) / "zscan"
