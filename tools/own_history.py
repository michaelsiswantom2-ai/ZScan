"""Write zscan/own-history.sha256: the SHA-256 of every file in ZScan's git history that ZScan
itself flags (old rule files, source code that lists what it looks for, test samples).

ZScan recognises the files of the version that is running by their content. This list adds the
older versions, so copies of them (wheels in pip's cache, old downloads or checkouts) are reported
as ZScan's own files instead of setting off alarms. Run it from the repository root before each
release, as the last step before committing, with the community rules installed so their
matches are covered too:

    python tools/own_history.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from zscan.archives import Budget  # noqa: E402
from zscan.scanner import OWN_HISTORY, Scanner  # noqa: E402
from zscan.yara_engine import YaraEngine  # noqa: E402


def git(*args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def main() -> int:
    blobs: dict = {}            # git blob id -> (path, commit) where it first appears
    for commit in git("rev-list", "--all", "--reverse").decode().split():
        for line in git("ls-tree", "-r", commit).decode("utf-8", "replace").splitlines():
            meta, path = line.split("\t", 1)
            _mode, kind, blob = meta.split()
            if kind == "blob" and blob not in blobs:
                blobs[blob] = (path, commit[:7])
    # The files as they are now, so the release being prepared is covered too: its tests and
    # docs are not running code, which is the only part recognised without this list.
    for path in git("ls-files").decode("utf-8", "replace").splitlines():
        f = ROOT / path
        if f.is_file() and f.resolve() != OWN_HISTORY.resolve():
            blobs.setdefault(("worktree", path), (path, "now"))
    scanner = Scanner(YaraEngine(), own_hashes=frozenset())    # scan ZScan's files like any others
    if scanner.yara.community is None:
        print("note: community rules not installed (zscan --update); their matches are not covered",
              file=sys.stderr)
    found = {}
    for blob, (path, commit) in blobs.items():
        data = (ROOT / path).read_bytes() if commit == "now" else git("cat-file", "blob", blob)
        if len(data) < 64:
            continue
        rep = scanner.finalize(scanner.analyze_bytes(data, path, Budget(scanner.limits), 0))
        if any(n.verdict in ("suspicious", "malicious") for n in rep.iter_tree()):
            found.setdefault(rep.hashes["sha256"], f"{path} @ {commit}")
    lines = ["# Files from ZScan's own git history that ZScan flags; written by tools/own_history.py.",
             "# sha256  path @ first commit"]
    lines += [f"{sha}  {where}" for sha, where in sorted(found.items(), key=lambda kv: kv[1])]
    OWN_HISTORY.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(found)} of {len(blobs)} files (history and working tree) are flagged; "
          f"wrote {OWN_HISTORY.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
