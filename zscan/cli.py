"""Command-line interface: zscan PATH [PATH...]"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from . import __version__, intel
from .config import cache_dir
from .ml.model import DEFAULT_THRESHOLD, MODEL_LABELS, MlScorer, MlUnavailable, update_models
from .scanner import CLOUD_ONLY, CRASHED, OWN_FILE, Scanner, WorkerCrashed, remember_report
from .yara_engine import FORGE_PACKS, YaraEngine, update_community

SEV_LABEL = {1: "INFO", 2: "LOW", 3: "MED", 4: "HIGH", 5: "CRIT"}
COLORS = {"clean": "\033[32m", "suspicious": "\033[33m", "malicious": "\033[31m", "error": "\033[35m", "skipped": "\033[90m"}
RESET = "\033[0m"
PROGRESS_EVERY = 30.0       # seconds between --progress lines


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
        sig = rep.signature
        signed = ""
        if sig:
            signed = f" signature={sig['status']}" + (f" ({sig['signer']})" if sig.get("signer") else "")
        lines.append(f"    type={rep.file_type} size={rep.size} entropy={rep.entropy} "
                     f"sha256={rep.hashes.get('sha256', '')}{signed}")
        for f in rep.findings:
            if f.severity == 1 and not verbose:
                continue
            detail = f"  ({f.detail})" if f.detail else ""
            uncounted = f"  [not counted: {f.not_counted}]" if f.not_counted else ""
            lines.append(f"    [{SEV_LABEL[f.severity]:4}] {f.title}{detail}{uncounted}")
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
    except intel.NoAuthKey as e:
        print(f"note: skipped the MalwareBazaar hash list: {e}", file=sys.stderr)
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


def read_path_list(path: Path) -> list:
    """Paths listed one per line. PowerShell 5 writes UTF-16 with `>` and UTF-8 with a BOM with
    `Set-Content -Encoding utf8`, so both are read."""
    raw = path.read_bytes()
    text = raw.decode("utf-16" if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig")
    return [Path(line.strip()) for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="zscan", description="Prototype static malware scanner "
                                 "(YARA + heuristics). Never executes scanned files.")
    ap.add_argument("paths", nargs="*", type=Path, help="files or directories to scan")
    ap.add_argument("--files-from", type=Path, metavar="FILE",
                    help="also scan the files and directories listed in FILE, one per line "
                         "(UTF-8 or UTF-16; blank lines and lines starting with # are ignored)")
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
    ap.add_argument("--no-signatures", action="store_true",
                    help="don't check Windows signatures: signed programs then count like unsigned ones")
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
    ap.add_argument("-o", "--output", type=Path, metavar="FILE",
                    help="write the report to FILE (UTF-8) instead of the screen; the summary is shown too")
    ap.add_argument("--progress", action="store_true",
                    help=f"print a progress line to stderr every {PROGRESS_EVERY:g} seconds (for long scans)")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--version", action="version", version=f"zscan {__version__}")
    a = ap.parse_args(argv)
    _never_fail_on_odd_names()
    if a.files_from:
        try:
            a.paths += read_path_list(a.files_from)
        except (OSError, UnicodeError) as e:
            ap.error(f"--files-from: cannot read {a.files_from}: {getattr(e, 'strerror', None) or e}")

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
                      hash_list=hash_list, online=online, ml=scorer, signatures=not a.no_signatures)

    paths, missing = [], 0
    for target in a.paths:
        if not target.exists():
            print(f"error: {target} does not exist", file=sys.stderr)
            missing += 1
        else:
            paths.append(target)

    out = sys.stdout
    if a.output:
        try:
            out = open(a.output, "w", encoding="utf-8", errors="backslashreplace")
        except OSError as e:
            print(f"error: cannot write {a.output}: {e.strerror or e}", file=sys.stderr)
            return 3
    try:
        return _scan_and_report(a, scanner, paths, missing, out)
    finally:
        if out is not sys.stdout:
            out.close()
            remember_report(a.output)    # it quotes findings, so later scans would flag it


def _scan_and_report(a, scanner: Scanner, paths: list, missing: int, out) -> int:
    color = out.isatty() and not a.no_color
    reports = []
    partial = 0
    counts = {"clean": 0, "suspicious": 0, "malicious": 0, "skipped": 0, "error": missing}
    skipped_why: Counter = Counter()
    signed_quiet = 0            # validly signed programs not flagged only because of their signature
    unreadable: list = []       # folders that could not be opened, so their files went unscanned
    crashed: list = []          # files that crashed a scan worker, so they went unscanned
    own: list = []              # skipped as ZScan's own files: listed, so nothing hides there unseen
    cloud: Counter = Counter()  # cloud-only files per folder
    stopped = None              # why the scan ended early, if it did
    jobs = (os.cpu_count() or 1) if a.jobs == 0 else max(1, a.jobs)
    if len(paths) == 1 and paths[0].is_file():
        jobs = 1    # starting workers for a single file only slows it down
    # Don't scan the report while writing it.
    report_path = os.path.normcase(os.path.abspath(a.output)) if a.output else None

    def note_unreadable(e: OSError) -> None:
        unreadable.append(f"{e.filename}: {e.strerror or e}")

    def all_files():
        for target in paths:
            for p in scanner.iter_paths(target, on_error=note_unreadable):
                if report_path is None or os.path.normcase(os.path.abspath(p)) != report_path:
                    yield p

    started = last = time.monotonic()
    try:
        for rep in scanner.scan_many(all_files(), jobs):
            counts[rep.verdict] += 1
            partial += rep.partly_scanned
            if rep.verdict == "clean" and rep.verdict_if_all_counted != "clean":
                signed_quiet += 1
            if rep.skipped:
                skipped_why[rep.skipped] += 1
            if rep.error == CRASHED:
                crashed.append(rep.path)
            elif rep.skipped == OWN_FILE:
                own.append(rep.path)
            elif rep.skipped == CLOUD_ONLY:
                cloud[_top_folder(rep.path)] += 1
            if a.progress and time.monotonic() - last >= PROGRESS_EVERY:
                last = time.monotonic()
                print(f"progress: {sum(counts.values()):,} files in {_minutes(last - started)} "
                      f"({counts['malicious']} malicious, {counts['suspicious']} suspicious, "
                      f"{counts['error']} unreadable); now at {rep.path}", file=sys.stderr, flush=True)
            if a.json:
                reports.append(rep)
                continue
            for node in rep.iter_tree():
                if node is not rep and node.verdict == "clean" and not a.verbose and not node.unscanned:
                    continue  # clean archive members stay quiet
                if a.quiet and node.verdict in ("clean", "skipped") and not node.unscanned:
                    continue
                print(render_text(node, a.verbose, color), file=out)
    except WorkerCrashed as e:
        # Still write the summary: everything before this point was scanned properly.
        stopped = f"the scan stopped early: {e}"
        print(f"error: {stopped}", file=sys.stderr)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130

    if scanner.online:
        scanner.online.save_cache()
        for w in scanner.online.warnings:
            print(f"warning: {w}", file=sys.stderr)

    if a.json:
        summary = dict(counts, partly_scanned=partial, skipped_reasons=dict(skipped_why),
                       signed_not_flagged=signed_quiet,
                       unreadable_folders=len(unreadable), crashed=len(crashed), stopped_early=stopped)
        json.dump({"summary": summary, "files": [to_dict(r) for r in reports],
                   "unreadable_folders": unreadable, "crashed_files": crashed, "own_files": own,
                   "cloud_only_folders": dict(cloud.most_common())}, out, indent=2)
        print(file=out)
    else:
        if unreadable:
            print(f"\nFolders that could not be opened ({len(unreadable)}), so the files in them were not scanned:",
                  file=out)
            for line in unreadable[:20]:
                print(f"    {line}", file=out)
            if len(unreadable) > 20:
                print(f"    ... and {len(unreadable) - 20} more", file=out)
        if crashed:
            # Usually a bug in a native library (YARA, a decompressor) hit by an odd file.
            print(f"\nFiles that crashed a scan worker ({len(crashed)}), so they were not scanned:", file=out)
            for path in crashed:
                print(f"    {path}", file=out)
        if own:
            print(f"\nSkipped as ZScan's own files ({len(own)}), recognised by exact content:", file=out)
            for path in own[:20]:
                print(f"    {path}", file=out)
            if len(own) > 20:
                print(f"    ... and {len(own) - 20} more", file=out)
        if cloud:
            print("\nCloud-only files (not downloaded, so not scanned), by folder:", file=out)
            for folder, n in cloud.most_common(10):
                print(f"    {folder} ({n:,})", file=out)
            if len(cloud) > 10:
                print(f"    ... and {len(cloud) - 10} more folders", file=out)
        if stopped:
            print(f"\nNOTE: {stopped}. Files after the last one listed were not scanned.", file=out)
        total = sum(counts.values())
        line = (f"Scanned {total} file(s) in {_minutes(time.monotonic() - started)}: "
                + ", ".join(f"{v} {k}" for k, v in counts.items())
                + (f"; {partial} not fully scanned" if partial else "")
                + ("; skipped: " + ", ".join(f"{n} {why}" for why, n in skipped_why.most_common())
                   if skipped_why else "")
                + (f"; {signed_quiet} validly signed program(s) with only general warning signs "
                   "not flagged" if signed_quiet else "")
                + (f"; {len(unreadable)} folder(s) could not be opened" if unreadable else "")
                + (f"; {len(crashed)} file(s) crashed a scan worker" if crashed else "")
                + ("; STOPPED EARLY" if stopped else ""))
        print("\n" + line, file=out)
        if out is not sys.stdout:
            print(line + f"\nreport written to {a.output}", file=sys.stderr)

    # Exit codes: 0 clean, 1 suspicious, 2 malicious found, 3 errors only,
    # 4 the scan stopped early (what it reported is only part of the files)
    if stopped:
        return 4
    if counts["malicious"]:
        return 2
    if counts["suspicious"]:
        return 1
    return 3 if counts["error"] or unreadable else 0


def _top_folder(path: str, depth: int = 4) -> str:
    """The first few levels of a file's folder, e.g. C:\\Users\\name\\OneDrive."""
    parts = Path(path).parent.parts
    return str(Path(*parts[:depth])) if parts else path


def _minutes(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h}:{m:02d}:{s:02d}"


def _never_fail_on_odd_names() -> None:
    """A file name the console cannot show (say, Thai on an English Windows code page, or
    undecodable bytes on Linux) must not end a long scan: print such characters as escapes."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


if __name__ == "__main__":
    sys.exit(main())
