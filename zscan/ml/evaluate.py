"""Measure the ML check: on EMBER2024's test data and on files you trust.

    python -m zscan.ml.evaluate fetch DIR --kind elf        download test and challenge data (needs network)
    python -m zscan.ml.evaluate test --kind elf --data DIR/ELF_test.zip --challenge DIR/challenge.zip
    python -m zscan.ml.evaluate local --kind elf /usr/bin /usr/lib /opt

`test` answers "how well does the model separate malware from benign files it has not seen?".
EMBER2024's test set is the 12 weeks of files that came after the 52 weeks the models were trained
on, so it measures catching *newer* files. The challenge set holds malware that about 70 antivirus
engines missed when it first appeared. Both sets are balanced on purpose, so a good score there
does not mean few false alarms on a real machine: `local` measures that, by scoring your own
programs (which you presumably trust) with exactly the code `zscan --ml` runs.

Reading the numbers: the share of malware caught at a given false-alarm rate (TPR at FPR) is
what matters when you pick `--ml-threshold`. Real machines hold far more benign than malicious
files, so even 0.1% false alarms can outnumber the real finds.

Needs numpy and lightgbm; `fetch` also needs a network route to huggingface.co.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing
import os
import sys
import urllib.request
import zipfile
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path
from typing import Iterator

DATASET_URL = "https://huggingface.co/datasets/joyce8/EMBER2024/resolve/main/{name}"
KIND_FILES = {"elf": "ELF", "pdf": "PDF", "apk": "APK"}      # file_type spelling in the data
THRESHOLDS = (0.5, 0.9, 0.99, 0.999)
FPR_TARGETS = (0.01, 0.001)


# ---------------------------------------------------------------- reading the dataset

def iter_rows(path: Path) -> Iterator[dict]:
    """Rows of raw features from a zip of .jsonl files or from a folder with .jsonl files."""
    path = Path(path)
    if path.is_dir():
        for p in sorted(path.rglob("*.jsonl")):
            with p.open() as f:
                for line in f:
                    yield json.loads(line)
        return
    with zipfile.ZipFile(path) as zf:
        for name in sorted(n for n in zf.namelist() if n.endswith(".jsonl")):
            with zf.open(name) as f:
                for line in f:
                    yield json.loads(line)


def score_rows(rows: Iterator[dict], booster, kind: str, batch: int = 2048) -> dict:
    """Score dataset rows of one file type with a model. Returns arrays: y, score, date."""
    import numpy as np
    from . import features
    want = KIND_FILES[kind].lower()
    ys, scores, dates, seen, buf, bufmeta = [], [], [], {}, [], []

    def flush():
        if buf:
            x = np.vstack([features.pad_for_model(v, booster.num_feature()) for v in buf])
            scores.extend(booster.predict(x, num_threads=os.cpu_count() or 1).tolist())
            ys.extend(m[0] for m in bufmeta)
            dates.extend(m[1] for m in bufmeta)
            buf.clear()
            bufmeta.clear()

    for row in rows:
        ftype = str(row.get("file_type", "")).lower()
        seen[ftype] = seen.get(ftype, 0) + 1
        if ftype != want or row.get("label") not in (0, 1):
            continue
        buf.append(features.process_raw_features(row))
        bufmeta.append((int(row["label"]), str(row.get("first_submission_date", ""))))
        if len(buf) >= batch:
            flush()
    flush()
    return {"y": np.array(ys), "score": np.array(scores), "date": dates, "file_types_seen": seen}


# ---------------------------------------------------------------- metrics

def roc_auc(y, s) -> float:
    """Chance that a random malicious file outscores a random benign one (ties count half)."""
    import numpy as np
    pos, neg = s[y == 1], s[y == 0]
    if not len(pos) or not len(neg):
        return float("nan")
    uniq, inv, counts = np.unique(s, return_inverse=True, return_counts=True)
    ranks = (np.cumsum(counts) - (counts - 1) / 2.0)[inv]          # average rank of each score
    return float((ranks[y == 1].sum() - len(pos) * (len(pos) + 1) / 2.0) / (len(pos) * len(neg)))


def threshold_at_fpr(y, s, fpr: float) -> float:
    """Smallest cut-off with at most `fpr` of the benign files scoring above it."""
    import numpy as np
    neg = np.sort(s[y == 0])[::-1]
    k = int(fpr * len(neg))
    return float(neg[k]) if k < len(neg) else float("-inf")


def rates(y, s, threshold: float) -> tuple:
    """(true positive rate, false positive rate) when "score >= threshold" means flagged."""
    pos, neg = s[y == 1], s[y == 0]
    tpr = float((pos >= threshold).mean()) if len(pos) else float("nan")
    fpr = float((neg >= threshold).mean()) if len(neg) else float("nan")
    return tpr, fpr


def describe_test(res: dict, label: str) -> list:
    y, s = res["y"], res["score"]
    lines = [f"{label}: {len(y)} files ({int((y == 1).sum())} malicious, {int((y == 0).sum())} benign)"]
    if res["date"]:
        known = sorted(d for d in res["date"] if d)
        if known:
            lines.append(f"  first seen between {known[0][:10]} and {known[-1][:10]}")
    lines.append(f"  ROC AUC {roc_auc(y, s):.4f}")
    for fpr in FPR_TARGETS:
        t = threshold_at_fpr(y, s, fpr)
        tpr = float((s[y == 1] > t).mean()) if (y == 1).any() else float("nan")
        lines.append(f"  at {fpr:.1%} false alarms: score cut-off {t:.4f}, catches {tpr:.1%} of malware")
    for t in THRESHOLDS:
        tpr, fpr = rates(y, s, t)
        lines.append(f"  zscan threshold {t}: catches {tpr:.1%} of malware, flags {fpr:.2%} of benign files")
    return lines


# ---------------------------------------------------------------- local files

_SCORER = None


def _init_worker(directory: str) -> None:
    global _SCORER
    from .model import MlScorer
    _SCORER = MlScorer(directory=Path(directory))


def _score_file(args):
    path, kind, max_bytes = args
    from .. import analysis
    from .model import kind_for
    try:
        if os.path.getsize(path) > max_bytes:
            return None
        data = Path(path).read_bytes()
        if kind_for(analysis.detect_type(data), data) != kind:
            return None
        r = _SCORER.score(kind, data)
        return (path, r.score) if r else None
    except Exception:  # noqa: BLE001 - unreadable or odd files are simply not counted
        return None


def iter_files(roots) -> Iterator[str]:
    for root in roots:
        root = Path(root)
        if root.is_file():
            yield str(root)
            continue
        for d, dirs, files in os.walk(root):
            dirs.sort()
            for n in sorted(files):
                p = os.path.join(d, n)
                if os.path.isfile(p) and not os.path.islink(p):
                    yield p


def describe_local(scores: list, top: int) -> list:
    import numpy as np
    s = np.array([x[1] for x in scores])
    if not len(s):
        return ["no files of that type found"]
    lines = [f"{len(s)} files scored; median {np.median(s):.4f}, 99th percentile {np.quantile(s, 0.99):.4f}, "
             f"99.9th {np.quantile(s, 0.999):.4f}, highest {s.max():.4f}"]
    for t in THRESHOLDS:
        n = int((s >= t).sum())
        lines.append(f"  score >= {t}: {n} files ({n / len(s):.2%})")
    lines.append(f"  a threshold above {np.quantile(s, 0.999):.4f} would flag at most 0.1% of these files")
    lines.append(f"highest scoring {min(top, len(s))} (check whether these really are trustworthy):")
    for path, score in sorted(scores, key=lambda x: -x[1])[:top]:
        lines.append(f"  {score:.4f}  {path}")
    return lines


# ---------------------------------------------------------------- commands

def cmd_fetch(a) -> int:
    out = Path(a.dir)
    out.mkdir(parents=True, exist_ok=True)
    names = [f"{KIND_FILES[k]}_test.zip" for k in a.kind] + (["challenge.zip"] if a.challenge else [])
    for name in names:
        dest = out / name
        if dest.exists():
            print(f"{name}: already there")
            continue
        url = DATASET_URL.format(name=name)
        print(f"{name}: downloading {url}", flush=True)
        req = urllib.request.Request(url, headers={"User-Agent": "zscan"})
        tmp = dest.with_suffix(".part")
        with urllib.request.urlopen(req, timeout=120) as r, tmp.open("wb") as f:
            while chunk := r.read(1 << 20):
                f.write(chunk)
        tmp.replace(dest)
        print(f"{name}: {dest.stat().st_size / 1e6:.1f} MB")
    return 0


def _booster(a):
    import lightgbm as lgb
    from . import model
    path = Path(a.model) if a.model else model.models_dir() / model.MODEL_FILES[a.kind]
    if not path.is_file():
        raise SystemExit(f"error: no model at {path}; run `zscan --update-ml` or pass --model")
    return lgb.Booster(model_file=str(path))


def cmd_test(a) -> int:
    booster = _booster(a)
    res = score_rows(iter_rows(a.data), booster, a.kind)
    if not len(res["y"]):
        print(f"no {a.kind.upper()} rows found; file types in the data: {res['file_types_seen']}")
        return 3
    print("\n".join(describe_test(res, f"EMBER2024 {a.kind.upper()} test set")))
    if a.challenge:
        ch = score_rows(iter_rows(a.challenge), booster, a.kind)
        if len(ch["y"]):
            print(f"\nchallenge set ({len(ch['y'])} {a.kind.upper()} files, all malware that most antivirus missed):")
            for t in THRESHOLDS:
                print(f"  zscan threshold {t}: catches {(ch['score'] >= t).mean():.1%}")
    return 0


def cmd_local(a) -> int:
    from .model import MODEL_FILES, models_dir
    directory = Path(a.model_dir) if a.model_dir else models_dir()
    if not (directory / MODEL_FILES[a.kind]).is_file():
        raise SystemExit(f"error: no {a.kind} model in {directory}; run `zscan --update-ml`")
    jobs = a.jobs or os.cpu_count() or 1
    work = ((p, a.kind, a.max_size * 1024 * 1024) for p in iter_files(a.paths))
    with ProcessPoolExecutor(jobs, mp_context=multiprocessing.get_context("spawn"),
                             initializer=_init_worker, initargs=(str(directory),)) as pool:
        scores = [r for r in pool.map(_score_file, work, chunksize=16) if r]
    print("\n".join(describe_local(scores, a.top)))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m zscan.ml.evaluate", description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fetch", help="download EMBER2024 test data from Hugging Face")
    f.add_argument("dir")
    f.add_argument("--kind", nargs="+", choices=sorted(KIND_FILES), default=["elf"])
    f.add_argument("--no-challenge", dest="challenge", action="store_false")
    f.set_defaults(func=cmd_fetch)

    t = sub.add_parser("test", help="score EMBER2024 test data (a zip or folder of .jsonl files)")
    t.add_argument("--kind", choices=sorted(KIND_FILES), required=True)
    t.add_argument("--data", required=True)
    t.add_argument("--challenge")
    t.add_argument("--model", help="model file (default: the installed one)")
    t.set_defaults(func=cmd_test)

    loc = sub.add_parser("local", help="score files on this machine to see how many false alarms to expect")
    loc.add_argument("--kind", choices=sorted(KIND_FILES), default="elf")
    loc.add_argument("paths", nargs="+")
    loc.add_argument("--model-dir")
    loc.add_argument("--jobs", type=int, default=0)
    loc.add_argument("--max-size", type=int, default=64, help="skip files above N MiB (default 64)")
    loc.add_argument("--top", type=int, default=15)
    loc.set_defaults(func=cmd_local)

    a = ap.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
