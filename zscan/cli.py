"""Command-line interface: zscan PATH [PATH...]"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__, intel
from .config import cache_dir
from .scanner import Scanner
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
    ap.add_argument("--no-unpack", action="store_true", help="don't look inside zip/tar/gzip files")
    ap.add_argument("--hashlist", action="append", type=Path, default=[],
                    help="file of known-bad hashes, one per line (repeatable)")
    ap.add_argument("--intel", action="store_true",
                    help="look up SHA-256 hashes online: CIRCL hashlookup, plus MalwareBazaar "
                         "and VirusTotal when MALWAREBAZAAR_API_KEY / VT_API_KEY are set. "
                         "Only hashes are sent, never file contents.")
    ap.add_argument("--json", action="store_true", help="emit JSON report")
    ap.add_argument("-v", "--verbose", action="store_true", help="show details for clean files too")
    ap.add_argument("-q", "--quiet", action="store_true", help="only print non-clean files")
    ap.add_argument("--max-size", type=int, default=64, help="skip files larger than N MiB (default 64)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"zscan {__version__}")
    a = ap.parse_args(argv)

    if a.update:
        code = run_update(a.rule_pack)
        if not a.paths:
            return code
    if not a.paths:
        ap.error("give at least one file or directory to scan (or --update)")

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

    scanner = Scanner(engine, max_bytes=a.max_size * 1024 * 1024, unpack=not a.no_unpack,
                      hash_list=hash_list, online=online)
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
                continue
            for node in rep.iter_tree():
                if node is not rep and node.verdict == "clean" and not a.verbose:
                    continue  # clean archive members stay quiet
                if a.quiet and node.verdict in ("clean", "skipped"):
                    continue
                print(render_text(node, a.verbose, color))

    if online:
        online.save_cache()
        for w in online.warnings:
            print(f"warning: {w}", file=sys.stderr)

    if a.json:
        json.dump({"summary": counts, "files": [to_dict(r) for r in reports]}, sys.stdout, indent=2)
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
