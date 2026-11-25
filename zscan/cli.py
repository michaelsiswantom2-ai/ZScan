"""Command-line interface: zscan PATH [PATH...]"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .scanner import Scanner
from .yara_engine import YaraEngine

SEV_LABEL = {1: "INFO", 2: "LOW", 3: "MED", 4: "HIGH", 5: "CRIT"}
COLORS = {"clean": "\033[32m", "suspicious": "\033[33m", "malicious": "\033[31m", "error": "\033[35m", "skipped": "\033[90m"}
RESET = "\033[0m"


def render_text(rep, verbose: bool, color: bool) -> str:
    v = rep.verdict
    tag = f"{COLORS[v]}{v.upper():10}{RESET}" if color else f"{v.upper():10}"
    lines = [f"{tag} score={rep.score:3d}  {rep.path}"]
    if rep.error:
        lines.append(f"    ! {rep.error}")
        return "\n".join(lines)
    if rep.skipped:
        lines.append(f"    - skipped: {rep.skipped}")
        return "\n".join(lines)
    if verbose or v != "clean":
        lines.append(f"    type={rep.file_type} size={rep.size} entropy={rep.entropy} "
                     f"sha256={rep.hashes.get('sha256', '')}")
        for f in rep.findings:
            if f.severity == 1 and not verbose:
                continue
            detail = f"  ({f.detail})" if f.detail else ""
            lines.append(f"    [{SEV_LABEL[f.severity]:4}] {f.title}{detail}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zscan", description="Prototype static malware scanner "
                                 "(YARA + heuristics). Never executes scanned files.")
    ap.add_argument("paths", nargs="+", type=Path, help="files or directories to scan")
    ap.add_argument("-r", "--rules", action="append", type=Path,
                    help="YARA rule file or directory (repeatable; default: bundled rules)")
    ap.add_argument("--json", action="store_true", help="emit JSON report")
    ap.add_argument("-v", "--verbose", action="store_true", help="show details for clean files too")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print non-clean files")
    ap.add_argument("--max-size", type=int, default=64, help="skip files larger than N MiB (default 64)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"zscan {__version__}")
    a = ap.parse_args(argv)

    engine = YaraEngine(a.rules)
    if engine.error:
        print(f"warning: {engine.error}", file=sys.stderr)
    scanner = Scanner(engine, max_bytes=a.max_size * 1024 * 1024)
    color = sys.stdout.isatty() and not a.no_color

    reports = []
    counts = {"clean": 0, "suspicious": 0, "malicious": 0, "skipped": 0, "error": 0}
    for target in a.paths:
        if not target.exists():
            print(f"error: {target} does not exist", file=sys.stderr)
            counts["error"] += 1
            continue
        for rep in scanner.scan(target):
            counts[rep.verdict] += 1
            if a.json:
                reports.append(rep)
            elif not (a.quiet and rep.verdict in ("clean", "skipped")):
                print(render_text(rep, a.verbose, color))

    if a.json:
        out = [dict(asdict(r), score=r.score, verdict=r.verdict) for r in reports]
        json.dump({"summary": counts, "files": out}, sys.stdout, indent=2)
        print()
    else:
        total = sum(counts.values())
        print(f"\nScanned {total} file(s): " + ", ".join(f"{v} {k}" for k, v in counts.items()))

    # Exit codes: 0 clean, 1 suspicious, 2 malicious found, 3 errors only
    if counts["malicious"]:
        return 2
    if counts["suspicious"]:
        return 1
    return 3 if counts["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
