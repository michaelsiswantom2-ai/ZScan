"""Check zscan's ML features against the official EMBER2024 extractor on real files.

    pip install git+https://github.com/FutureComputing4AI/EMBER2024.git
    python -m zscan.ml.verify /usr/bin /usr/lib --sample 500

Compares the four raw feature groups (general, histogram, byteentropy, strings) file by file
and expects them to be identical, not just close. Exit status 0 when every file matches.
"""
from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from . import features
from .evaluate import iter_files


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m zscan.ml.verify", description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--sample", type=int, default=200, metavar="N", help="check N random files (default 200)")
    ap.add_argument("--max-size", type=int, default=16, help="skip files above N MiB (default 16; the official code is slow)")
    a = ap.parse_args(argv)
    try:
        from thrember.features import ByteEntropyHistogram, ByteHistogram, GeneralFileInfo, StringExtractor
    except ImportError:
        print("error: needs the official extractor: "
              "pip install git+https://github.com/FutureComputing4AI/EMBER2024.git", file=sys.stderr)
        return 3
    official = {"general": GeneralFileInfo(), "histogram": ByteHistogram(),
                "byteentropy": ByteEntropyHistogram(), "strings": StringExtractor()}

    candidates = [p for p in iter_files(a.paths) if 0 < Path(p).stat().st_size <= a.max_size * 1024 * 1024]
    random.Random(0).shuffle(candidates)
    checked = skipped = 0
    bad = []
    for path in candidates:
        if checked >= a.sample:
            break
        data = Path(path).read_bytes()
        if data[:2] == b"MZ":     # Windows programs carry more feature groups than we compute
            skipped += 1
            continue
        mine = features.raw_features(data)
        wrong = [g for g, extractor in official.items() if extractor.raw_features(data, None) != mine[g]]
        checked += 1
        if wrong:
            bad.append((path, wrong))
    print(f"checked {checked} files ({skipped} Windows programs skipped): "
          f"{checked - len(bad)} identical, {len(bad)} different")
    for path, groups in bad[:20]:
        print(f"  DIFFERENT {path}: {', '.join(groups)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
