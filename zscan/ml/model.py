"""Model files, download and scoring for the opt-in ML check.

The models are the LightGBM classifiers published with the EMBER2024 dataset
(https://huggingface.co/joyce8/EMBER2024-benchmark-models, Apache License 2.0), one each for
ELF, PDF and APK files. They are downloaded by `zscan --update-ml` into the cache folder, not
shipped with zscan. A model file is plain text read by LightGBM; nothing is unpickled.

Each model answers "how much does this file's feature profile look like the malware, and not
the benign files, it was trained on?" as a number between 0 and 1. It is a statistical guess
about unseen files, not a signature match, so zscan reports it as a hint (see `severity`).
"""
from __future__ import annotations

import hashlib
import io
import json
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ..config import cache_dir

MODEL_REPO = "joyce8/EMBER2024-benchmark-models"
MODEL_URL = "https://huggingface.co/" + MODEL_REPO + "/resolve/main/{name}"
MODEL_FILES = {"elf": "EMBER2024_ELF.model", "pdf": "EMBER2024_PDF.model", "apk": "EMBER2024_APK.model"}
MODEL_LABELS = {"elf": "ELF", "pdf": "PDF", "apk": "APK"}
MAX_MODEL_BYTES = 64 * 1024 * 1024      # the published models are about 3.7 MB each
EXPECTED_FEATURES = (2568, 696)         # full EMBER2024 vector, or only the four groups we compute
DEFAULT_THRESHOLD = 0.99                # provisional: only files the model is very sure about
MIN_FILE_BYTES = 64                     # too little to judge (an ELF header alone is 64 bytes)


class MlUnavailable(RuntimeError):
    """The ML check cannot run: libraries or model files are missing."""


@dataclass
class MlResult:
    kind: str       # elf, pdf or apk
    model: str      # e.g. EMBER2024_ELF
    score: float    # 0 = looks like the benign training files, 1 = like the malicious ones


def models_dir() -> Path:
    return cache_dir() / "ml"


def _require_lightgbm():
    try:
        import numpy  # noqa: F401
        import lightgbm
    except ImportError as e:
        raise MlUnavailable("the ML check needs numpy and lightgbm: pip install 'zscan[ml]'") from e
    return lightgbm


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "zscan"})
    with urllib.request.urlopen(req, timeout=120) as r:
        blob = r.read(MAX_MODEL_BYTES + 1)
    return blob


def _load(lgb, path: Path):
    booster = lgb.Booster(model_file=str(path))
    n = booster.num_feature()
    if n not in EXPECTED_FEATURES:
        raise ValueError(f"{path.name} reads {n} features; expected {' or '.join(map(str, EXPECTED_FEATURES))}. "
                         "It was probably built with a different feature layout than this zscan understands.")
    return booster


def update_models(kinds=None, fetch=None, directory: Path | None = None) -> dict:
    """Download the models into the cache and check that each one loads.

    Returns {kind: metadata}. A bad download never replaces a working model.
    `fetch(url) -> bytes` can be swapped out in tests.
    """
    lgb = _require_lightgbm()
    directory = directory or models_dir()
    directory.mkdir(parents=True, exist_ok=True)
    out = {}
    for kind in kinds or MODEL_FILES:
        name = MODEL_FILES[kind]
        url = MODEL_URL.format(name=name)
        blob = (fetch or _download)(url)
        if len(blob) > MAX_MODEL_BYTES:
            raise ValueError(f"{url} is larger than {MAX_MODEL_BYTES // (1024 * 1024)} MiB; not a model we know")
        tmp = directory / (name + ".tmp")
        tmp.write_bytes(blob)
        try:
            booster = _load(lgb, tmp)
        except Exception as e:  # noqa: BLE001 - LightGBM raises its own error types on a bad file
            tmp.unlink(missing_ok=True)
            raise ValueError(f"downloaded {name} is not a usable model: {e}") from e
        tmp.replace(directory / name)
        meta = {"kind": kind, "file": name, "url": url, "bytes": len(blob),
                "sha256": hashlib.sha256(blob).hexdigest(), "trees": booster.num_trees(),
                "features": booster.num_feature(), "downloaded": time.strftime("%Y-%m-%d %H:%M:%S")}
        (directory / (name + ".json")).write_text(json.dumps(meta, indent=2), encoding="utf-8")
        out[kind] = meta
    return out


def installed_models(directory: Path | None = None) -> dict:
    """{kind: metadata} for the models present in the cache (no LightGBM needed)."""
    directory = directory or models_dir()
    found = {}
    for kind, name in MODEL_FILES.items():
        if (directory / name).is_file():
            try:
                found[kind] = json.loads((directory / (name + ".json")).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                found[kind] = {"kind": kind, "file": name}
    return found


def looks_like_apk(data: bytes) -> bool:
    """An Android package is a zip with a manifest and compiled code."""
    try:
        names = zipfile.ZipFile(io.BytesIO(data)).namelist()
    except Exception:  # noqa: BLE001 - hostile or damaged zips raise many different errors
        return False
    return "AndroidManifest.xml" in names and any(n.startswith("classes") and n.endswith(".dex") for n in names)


def kind_for(file_type: str, data: bytes) -> str | None:
    """Which model (if any) judges a file of this detected type."""
    if file_type == "elf":
        return "elf"
    if file_type == "pdf":
        return "pdf"
    if file_type == "zip" and looks_like_apk(data):
        return "apk"
    return None


class MlScorer:
    """Loads the installed models and scores files with them."""

    def __init__(self, threshold: float = DEFAULT_THRESHOLD, directory: Path | None = None):
        lgb = _require_lightgbm()
        if not 0.5 <= threshold <= 1.0:
            raise ValueError("ML threshold must be between 0.5 and 1.0")
        self.threshold = threshold
        self.directory = directory or models_dir()
        self.models = {}
        for kind, name in MODEL_FILES.items():
            path = self.directory / name
            if path.is_file():
                try:
                    self.models[kind] = _load(lgb, path)
                except Exception as e:  # noqa: BLE001
                    raise MlUnavailable(f"cannot load {path}: {e}. Run `zscan --update-ml` to download it again.") from e
        if not self.models:
            raise MlUnavailable(f"no ML models found in {self.directory}; run `zscan --update-ml` to download them")

    def kind_for(self, file_type: str, data: bytes) -> str | None:
        return kind_for(file_type, data)

    def has_model(self, kind: str) -> bool:
        return kind in self.models

    def score(self, kind: str, data: bytes) -> MlResult | None:
        """Probability-like score for one file, or None if there is too little to judge."""
        from . import features
        if len(data) < MIN_FILE_BYTES:
            return None
        booster = self.models[kind]
        x = features.pad_for_model(features.feature_vector(data), booster.num_feature())
        p = float(booster.predict(x.reshape(1, -1), num_threads=1)[0])
        return MlResult(kind=kind, model=MODEL_FILES[kind].removesuffix(".model"), score=p)

    def severity(self, score: float) -> int:
        """1 (INFO, just show the score), 2 (LOW hint) or 3 (MED, suspicious on its own).

        Never higher: this is a statistical guess about files nobody has seen before, and no
        guess should call a file malicious by itself. Combined with other findings it still
        adds up like any other hint."""
        if score >= self.threshold:
            return 3
        if score >= max(0.5, self.threshold - 0.09):
            return 2
        return 1
