"""Command-line interface: zscan PATH [PATH...]"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__, intel
from .config import cache_dir
from .ml.model import DEFAULT_THRESHOLD, MODEL_LABELS, MlScorer, MlUnavailable, update_models
from .scanner import Scanner, WorkerCrashed
from .yara_engine import FORGE_PACKS, YaraEngine, update_community

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
    if rep.unscanned:
        # Say so even for "clean" files: a gap in coverage should never be silent.
        shown = rep.unscanned[:3]
        more = len(rep.unscanned) - len(shown)
        lines.append("    ~ not fully scanned: " + "; ".join(shown) + (f" (+{more} more)" if more else ""))
    return "\n".join(lines)


def to_dict(rep) -> dict:
    d = asdict(rep)
    d.pop("children")
    d.update(score=rep.score, verdict=rep.verdict)
    if rep.children:
        d["members"] = [to_dict(c) for c in rep.children]
    return d


def run_update(pack: str) -> int:
    ok = True
    try:
        meta = update_community(pack)
        print(f"YARA-Forge '{meta['pack']}' rules: {meta['rules']} rules, "
              f"version {meta['version'] or '?'} ({meta['created'] or 'unknown date'})")
    except Exception as e:  # noqa: BLE001 - report any failure and carry on
        print(f"error: could not update YARA-Forge rules: {e}", file=sys.stderr)
        ok = False
    try:
        path, n = intel.update_bazaar_list()
        print(f"MalwareBazaar recent hashes: {n} saved to {path}")
    except Exception as e:  # noqa: BLE001
        print(f"warning: could not fetch MalwareBazaar hash list: {e}", file=sys.stderr)
    print(f"Cache folder: {cache_dir()}")
    return 0 if ok else 3


def run_update_ml() -> int:
    try:
        metas = update_models()
    except MlUnavailable as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except Exception as e:  # noqa: BLE001 - report any failure, e.g. no network
        print(f"error: could not download the ML models: {e}", file=sys.stderr)
        return 3
    for kind, m in metas.items():
        print(f"EMBER2024 {MODEL_LABELS[kind]} model: {m['trees']} trees, {m['bytes'] / 1e6:.1f} MB, "
              f"sha256 {m['sha256'][:16]}...")
    print(f"Cache folder: {cache_dir()}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zscan", description="Prototype static malware scanner "
                                 "(YARA + heuristics). Never executes scanned files.")
    ap.add_argument("paths", nargs="*", type=Path, help="files or directories to scan")
    ap.add_argument("-r", "--rules", action="append", type=Path,
                    help="YARA rule file or directory (repeatable; replaces the bundled rules)")
    ap.add_argument("--no-community", action="store_true",
                    help="don't load downloaded YARA-Forge rules")
    ap.add_argument("--update", action="store_true",
                    help="download community YARA rules (YARA-Forge) and the MalwareBazaar "
                         "recent-hash list into the cache, then exit unless paths are given")
    ap.add_argument("--rule-pack", choices=FORGE_PACKS, default="core",
                    help="YARA-Forge package for --update (default core; full is noisier)")
    ap.add_argument("--ml", action="store_true",
                    help="also score ELF, PDF and APK files with machine-learning models trained on the "
                         "EMBER2024 dataset (needs `pip install 'zscan[ml]'` and `zscan --update-ml`). "
                         "A statistical guess about unseen files: it adds hints, never a verdict on its own.")
    ap.add_argument("--ml-threshold", type=float, default=None, metavar="T",
                    help=f"model score from which a file is reported as suspicious (0.5 to 1, default "
                         f"{DEFAULT_THRESHOLD}); scores up to 0.09 below it are reported as a weak hint")
    ap.add_argument("--update-ml", action="store_true",
                    help="download the EMBER2024 ELF, PDF and APK models (about 11 MB, Hugging Face) "
                         "into the cache, then exit unless paths are given")
    ap.add_argument("--no-unpack", action="store_true", help="don't look inside zip/tar/gzip files")
    ap.add_argument("--hashlist", action="append", type=Path, default=[],
                    help="file of known-bad hashes, one per line (repeatable)")
    ap.add_argument("--intel", action="store_true",
                    help="look up SHA-256 hashes online: CIRCL hashlookup, plus MalwareBazaar "
                         "and VirusTotal when MALWAREBAZAAR_API_KEY / VT_API_KEY are set. "
                         "Only hashes are sent, never file contents.")
    ap.add_argument("-j", "--jobs", type=int, default=1, metavar="N",
                    help="scan with N worker processes (0 = one per CPU core; default 1)")
    ap.add_argument("--json", action="store_true", help="emit JSON report")
    ap.add_argument("-v", "--verbose", action="store_true", help="show details for clean files too")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print non-clean files")
    ap.add_argument("--max-size", type=int, default=64, help="skip files larger than N MiB (default 64)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"zscan {__version__}")
    a = ap.parse_args(argv)

    code = 0
    if a.update:
        code = run_update(a.rule_pack)
    if a.update_ml:
        code = max(code, run_update_ml())
    if (a.update or a.update_ml) and not a.paths:
        return code
    if not a.paths:
        ap.error("give at least one file or directory to scan (or --update / --update-ml)")
    if a.ml_threshold is not None and not a.ml:
        ap.error("--ml-threshold only makes sense together with --ml")

    engine = YaraEngine(a.rules, community=not a.no_community)
    if engine.error:
        print(f"warning: {engine.error}", file=sys.stderr)
    if engine.community is None and not a.no_community and not a.json:
        print("note: community YARA rules not installed; run `zscan --update` to add them",
              file=sys.stderr)

    hash_list = None
    lists = a.hashlist + intel.default_hash_lists()
    if lists:
        hash_list = intel.HashList(lists)
    online = intel.OnlineIntel() if a.intel else None
    if online and not a.json:
        print(f"intel: looking up hashes with {', '.join(online.sources)}", file=sys.stderr)

    scorer = None
    if a.ml:
        try:
            scorer = MlScorer(DEFAULT_THRESHOLD if a.ml_threshold is None else a.ml_threshold)
        except (MlUnavailable, ValueError) as e:
            print(f"error: --ml: {e}", file=sys.stderr)
            return 3
        if not a.json:
            print(f"ml: scoring {', '.join(MODEL_LABELS[k] for k in scorer.models)} files with EMBER2024 "
                  f"models (suspicious from {scorer.threshold:g})", file=sys.stderr)

    scanner = Scanner(engine, max_bytes=a.max_size * 1024 * 1024, unpack=not a.no_unpack,
                      hash_list=hash_list, online=online, ml=scorer)
    color = sys.stdout.isatty() and not a.no_color

    reports = []
    partial = 0
    counts = {"clean": 0, "suspicious": 0, "malicious": 0, "skipped": 0, "error": 0}
    paths = []
    for target in a.paths:
        if not target.exists():
            print(f"error: {target} does not exist", file=sys.stderr)
            counts["error"] += 1
        else:
            paths.append(target)
    jobs = (os.cpu_count() or 1) if a.jobs == 0 else max(1, a.jobs)
    if len(paths) == 1 and paths[0].is_file():
        jobs = 1    # starting workers for a single file only slows it down

    def all_files():
        for target in paths:
            yield from scanner.iter_paths(target)

    try:
        for rep in scanner.scan_many(all_files(), jobs):
            counts[rep.verdict] += 1
            partial += rep.partly_scanned
            if a.json:
                reports.append(rep)
                continue
            for node in rep.iter_tree():
                if node is not rep and node.verdict == "clean" and not a.verbose and not node.unscanned:
                    continue  # clean archive members stay quiet
                if a.quiet and node.verdict in ("clean", "skipped") and not node.unscanned:
                    continue
                print(render_text(node, a.verbose, color))
    except WorkerCrashed as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    if online:
        online.save_cache()
        for w in online.warnings:
            print(f"warning: {w}", file=sys.stderr)

    if a.json:
        json.dump({"summary": dict(counts, partly_scanned=partial), "files": [to_dict(r) for r in reports]}, sys.stdout, indent=2)
        print()
    else:
        total = sum(counts.values())
        print(f"\nScanned {total} file(s): " + ", ".join(f"{v} {k}" for k, v in counts.items())
              + (f"; {partial} not fully scanned" if partial else ""))

    # Exit codes: 0 clean, 1 suspicious, 2 malicious found, 3 errors only
    if counts["malicious"]:
        return 2
    if counts["suspicious"]:
        return 1
    return 3 if counts["error"] else 0


if __name__ == "__main__":
    sys.exit(main())
