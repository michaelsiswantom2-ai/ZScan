"""Static analysis: hashing, entropy, file type, suspicious strings, PE heuristics.

Nothing here executes the scanned file. Files are only read as bytes.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field

try:
    import pefile  # optional
except ImportError:  # pragma: no cover
    pefile = None


# Sources of ZScan's own general warning signs (as opposed to malware rules, hash lists or the
# ML check). On a validly signed program they are reported but not counted.
HEURISTIC_SOURCES = {"pe", "entropy", "strings", "elf"}


@dataclass
class Finding:
    source: str        # "yara", "entropy", "pe", "strings", "signature", ...
    title: str
    severity: int      # 1 = info, 2 = low, 3 = medium, 4 = high, 5 = critical
    detail: str = ""
    group: str = ""    # findings that describe the same trait; only the strongest one counts
    heuristic: bool = False   # a general warning sign; set for HEURISTIC_SOURCES and heuristic YARA rules
    not_counted: str = ""     # why this finding does not count toward the score, if it doesn't

    def __post_init__(self):
        if self.source in HEURISTIC_SOURCES:
            self.heuristic = True


@dataclass
class FileReport:
    path: str
    size: int = 0
    file_type: str = "unknown"
    hashes: dict = field(default_factory=dict)
    entropy: float = 0.0
    findings: list = field(default_factory=list)
    error: str | None = None
    skipped: str | None = None
    children: list = field(default_factory=list)   # reports for archive members
    unscanned: list = field(default_factory=list)  # what could not be checked, in plain words
    ml: dict | None = None                         # ML check result: {"model": ..., "score": ...}
    signature: dict | None = None                  # Windows signature check: {"status", "kind", "signer", "reason"}

    def iter_tree(self):
        """This report, then every nested archive member, depth first."""
        yield self
        for c in self.children:
            yield from c.iter_tree()

    @property
    def partly_scanned(self) -> bool:
        """True if this file or anything inside it could not be fully checked."""
        return any(n.unscanned for n in self.iter_tree())

    @property
    def score(self) -> int:
        return score_of(f for f in self.findings if not f.not_counted)

    @property
    def verdict(self) -> str:
        return self._verdict([f for f in self.findings if not f.not_counted])

    @property
    def verdict_if_all_counted(self) -> str:
        """The verdict had nothing been left uncounted (for example because of a valid signature)."""
        return self._verdict(self.findings)

    def _verdict(self, findings: list) -> str:
        if self.error:
            return "error"
        if self.skipped:
            return "skipped"
        if any(f.severity >= 5 for f in findings) or score_of(findings) >= 70:
            return "malicious"
        if score_of(findings) >= 15:
            return "suspicious"
        return "clean"


def score_of(findings) -> int:
    weights = {1: 0, 2: 5, 3: 15, 4: 35, 5: 100}
    total, strongest = 0, {}
    for f in findings:
        w = weights.get(f.severity, 0)
        if f.group:
            strongest[f.group] = max(strongest.get(f.group, 0), w)
        else:
            total += w
    return min(100, total + sum(strongest.values()))


# ---------------------------------------------------------------- basics

def hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


MAGIC = [
    (b"\x7fELF", "elf"),
    (b"PK\x03\x04", "zip"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole"),
    (b"#!", "script"),
    (b"\xca\xfe\xba\xbe", "macho-fat"),
    (b"\xcf\xfa\xed\xfe", "macho"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"Rar!\x1a\x07", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
]
_BZIP2_LEVELS = {bytes([c]) for c in b"123456789"}


def detect_type(data: bytes) -> str:
    if data[:2] == b"MZ":
        if _has_pe_signature(data):
            return "pe"
        if not _looks_like_text(data):
            # Windows only runs an MZ file as a program if "PE\0\0" follows. The rest are DOS
            # and 16-bit programs (NE, LE, LX: .fon bitmap fonts, Win16 stubs in SysWOW64),
            # Windows update deltas and cut-off files. Calling them broken PE files was noise.
            return "dos"
    for magic, name in MAGIC:
        if data.startswith(magic):
            return name
    if data[:3] == b"BZh" and data[3:4] in _BZIP2_LEVELS and data[4:10] in (b"1AY&SY", b"\x17rE8P\x90"):
        return "bzip2"
    if data[257:262] == b"ustar":
        return "tar"
    if _looks_like_text(data):
        return "text"
    return "data"


def _has_pe_signature(data: bytes) -> bool:
    """The MZ header's e_lfanew field (at 0x3C) points at "PE\0\0", as the Windows loader requires."""
    if len(data) < 0x40:
        return False
    offset = int.from_bytes(data[0x3C:0x40], "little")
    return data[offset:offset + 4] == b"PE\0\0"


def _looks_like_text(data: bytes) -> bool:
    sample = data[:4096]
    return bool(sample) and all(32 <= b < 127 or b in (9, 10, 13) for b in sample)


# ---------------------------------------------------------------- strings

# (regex, title, severity). Patterns are matched against the lower-cased file
# (Python's case-insensitive regex is several times slower on big binaries),
# so write them in lower case. CASE_SENSITIVE ones run on the original bytes.
SUSPICIOUS_PATTERNS = [
    (rb"powershell(?:\.exe)?\s+.{0,40}-e(?:nc|ncodedcommand)?\s", "PowerShell encoded command", 4),
    # Lone mentions are common in docs, editors' syntax files and installers, so these
    # are weak; the classic download-and-run cradle is what carries the weight.
    (rb"\biex\s*\(|\binvoke-expression\b", "PowerShell Invoke-Expression", 2),
    (rb"net\.webclient\)?\s*\.\s*download(?:string|file|data)\s*\(", "PowerShell download cradle", 3),
    (rb"\.download(?:string|file)\s*\(", "Script download call", 2),
    (rb"vssadmin(?:\.exe)?\s+delete\s+shadows", "Shadow copy deletion (ransomware trait)", 4),
    (rb"bcdedit(?:\.exe)?\s+/set\s+.{0,20}recoveryenabled\s+no", "Disables Windows recovery", 4),
    (rb"wevtutil(?:\.exe)?\s+cl\s", "Event log clearing", 3),
    (rb"software\\microsoft\\windows\\currentversion\\run", "Registry Run-key persistence", 3),
    (rb"schtasks(?:\.exe)?\s+/create", "Scheduled task creation", 2),
    # Install instructions ("curl https://... | bash") are everywhere in READMEs, so the plain
    # form is weak; the same thing aimed at a bare IP address is how droppers look.
    (rb"(?:curl|wget)\s[^\n|]{1,200}\|\s*(?:ba)?sh\b", "Pipe-to-shell download", 2),
    (rb"(?:curl|wget)\s[^\n|]{0,100}https?://\d{1,3}(?:\.\d{1,3}){3}[^\n|]{0,100}\|\s*(?:ba)?sh\b",
     "Pipe-to-shell download from a raw IP address", 3),
    (rb"/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+", "Bash reverse shell", 4),
    (rb"\bnc(?:at)?\s+-[ec]\s", "Netcat command execution", 3),
    (rb"mimikatz|sekurlsa::", "Credential dumping tool reference", 4),
    (rb"stratum\+(?:tcp|ssl)://", "Crypto-miner pool URL", 3),
    (rb"your files (?:have been|are) encrypted", "Ransom note wording", 4),
    (rb"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?/", "URL with raw IP address", 2),
    # Ad-block filter lists, browser caches and chat apps mention .onion sites all the time.
    (rb"\b[a-z2-7]{16,56}\.onion\b", "Tor .onion address", 2),
]
CASE_SENSITIVE_PATTERNS = [
    (rb"(?:[A-Za-z0-9+/]{4}){60,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?", "Large base64 blob", 2),
]
_COMPILED = [(re.compile(r), t, s) for r, t, s in SUSPICIOUS_PATTERNS]
_COMPILED_CS = [(re.compile(r), t, s) for r, t, s in CASE_SENSITIVE_PATTERNS]


def _looks_like_base64(blob: bytes) -> bool:
    """Real base64 mixes upper and lower case letters and digits. Letter runs ("JJJJKKKK..."
    lookup tables) and word lists strung together match the pattern too, but are not."""
    chars = set(blob)
    return (len(chars) >= 20 and any(65 <= c <= 90 for c in chars)
            and any(97 <= c <= 122 for c in chars) and any(48 <= c <= 57 for c in chars))


def _first_match(rx, corpus: bytes, title: str):
    if title != "Large base64 blob":
        return rx.search(corpus)
    for i, m in enumerate(rx.finditer(corpus)):
        if _looks_like_base64(m.group()):
            return m
        if i >= 20:
            return None
    return None


def string_findings(data: bytes) -> list[Finding]:
    out = []
    lowered = data.lower()
    for corpus, patterns in ((lowered, _COMPILED), (data, _COMPILED_CS)):
        for rx, title, sev in patterns:
            if title == "Tor .onion address" and b".onion" not in corpus:
                continue  # cheap literal prefilter; the regex is slow on big files
            m = _first_match(rx, corpus, title)
            if m:
                snippet = data[m.start():m.start() + 80].decode("latin-1", "replace")
                out.append(Finding("strings", title, sev, f"e.g. {snippet!r}"))
    return out


# ---------------------------------------------------------------- PE

# Imports that are individually common but together suggest injection,
# keylogging, or anti-analysis. Grouped by behaviour.
SUSPICIOUS_IMPORTS = {
    "process injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                          "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext"},
    "keylogging": {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState",
                   "GetKeyState"},
    "anti-debugging": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                       "NtQueryInformationProcess", "OutputDebugStringA"},
    "dynamic API resolution": {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"},
    "privilege manipulation": {"AdjustTokenPrivileges", "OpenProcessToken",
                               "LookupPrivilegeValueA", "LookupPrivilegeValueW"},
}
PACKER_SECTIONS = {"UPX0", "UPX1", "UPX2", ".aspack", ".adata", ".petite", ".nsp0",
                   ".nsp1", "MPRESS1", "MPRESS2", ".themida", ".vmp0", ".vmp1"}


# Packers and protectors (UPX, Themida, VMProtect...) are common in ordinary commercial software,
# and one packed file shows several signs of it at once: packer section names, high-entropy and
# writable+executable sections, a stripped import table. They all describe a single trait, so they
# share this group and count once, at their strongest: a packed file is suspicious, never
# malicious on that alone.
PACKING = "packing"
# The import-table check and the bundled YARA rule Process_Injection_API_Strings see the same
# API names (they sit in the import table as plain text), so they share a group too.
INJECTION = "injection"


def certificate_table(data: bytes) -> tuple[int, int] | None:
    """File offset and size of a PE file's Authenticode signature (its certificate table),
    or None if it has none. Reads only the headers."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    pe = int.from_bytes(data[0x3C:0x40], "little")
    opt = pe + 24
    if data[pe:pe + 4] != b"PE\0\0" or len(data) < opt + 2:
        return None
    magic = int.from_bytes(data[opt:opt + 2], "little")
    directories = {0x10B: opt + 96, 0x20B: opt + 112}.get(magic)
    if directories is None:
        return None
    entry = directories + 4 * 8      # IMAGE_DIRECTORY_ENTRY_SECURITY
    if len(data) < entry + 8 or int.from_bytes(data[directories - 4:directories], "little") <= 4:
        return None                  # NumberOfRvaAndSizes says there is no such entry
    offset = int.from_bytes(data[entry:entry + 4], "little")
    size = int.from_bytes(data[entry + 4:entry + 8], "little")
    if not offset or not size or offset + size > len(data):
        return None
    return offset, size


def pe_findings(data: bytes) -> list[Finding]:
    if pefile is None:
        return [Finding("pe", "pefile not installed; PE checks skipped", 1)]
    try:
        return _pe_findings(data)
    except Exception as e:  # noqa: BLE001 - hostile files can trip odd errors inside pefile
        return [Finding("pe", "PE analysis failed", 2, f"{type(e).__name__}: {e}")]


def _pe_findings(data: bytes) -> list[Finding]:
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except pefile.PEFormatError as e:
        return [Finding("pe", "Malformed PE header", 3, str(e))]

    out: list[Finding] = []

    # Sections: entropy, W+X, packer names
    for s in pe.sections:
        name = s.Name.rstrip(b"\x00").decode("latin-1", "replace")
        ent = s.get_entropy()
        chars = s.Characteristics
        writable = bool(chars & 0x80000000)
        executable = bool(chars & 0x20000000)
        if name in PACKER_SECTIONS:
            out.append(Finding("pe", f"Packer section name '{name}'", 3, group=PACKING))
        # Only code counts: compressed icons in .rsrc, packed data and the compressed debug
        # sections of MinGW and Go programs ("/19", "/32") are high-entropy in normal programs.
        if ent > 7.2 and s.SizeOfRawData > 1024 and (executable or chars & 0x20):
            out.append(Finding("pe", f"High-entropy code section '{name}'", 3,
                               f"entropy {ent:.2f} (packed or encrypted code?)", group=PACKING))
        if writable and executable:
            out.append(Finding("pe", f"Section '{name}' is writable and executable", 3, group=PACKING))
        if s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0x10000 and executable:
            out.append(Finding("pe", f"Empty-on-disk executable section '{name}'", 2,
                               "typical of unpack-at-runtime stubs", group=PACKING))

    # Entry point outside any section, or in the last section
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_section = next((s for s in pe.sections if s.contains_rva(ep)), None)
    if ep and ep_section is None:
        out.append(Finding("pe", "Entry point outside all sections", 4))
    elif ep_section is not None and pe.sections and ep_section is pe.sections[-1] \
            and len(pe.sections) > 1:
        out.append(Finding("pe", "Entry point in last section", 2,
                           "common in packed or infected binaries", group=PACKING))

    # Imports
    imported = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                imported.add(imp.name.decode("latin-1", "replace"))
    if not imported:
        out.append(Finding("pe", "No import table", 2, "may resolve APIs at runtime", group=PACKING))
    for behaviour, names in SUSPICIOUS_IMPORTS.items():
        hit = sorted(imported & names)
        if len(hit) < 2:
            continue
        if behaviour == "dynamic API resolution":
            # Normal programs import these alongside many others; only flag a
            # tiny import table that is basically just a loader.
            if len(imported) > 10:
                continue
            sev = 2
        elif behaviour == "process injection":
            # Debuggers, game overlays, anti-cheat and accessibility tools import these too.
            sev = 3 if len(hit) >= 3 else 2
        else:
            sev = 2
        out.append(Finding("pe", f"Imports suggest {behaviour}", sev, ", ".join(hit),
                           group=INJECTION if behaviour == "process injection" else ""))

    # Timestamp sanity
    ts = pe.FILE_HEADER.TimeDateStamp
    if ts == 0 or ts > 0x7FFFFFFF:
        out.append(Finding("pe", "Zeroed or invalid compile timestamp", 1))

    # Overlay (data appended after the last section). A signed program's Authenticode signature
    # sits there too, but that is not appended data.
    overlay = pe.get_overlay_data_start_offset()
    if overlay is not None:
        extra = len(data) - overlay
        cert = certificate_table(data)
        if cert and cert[0] >= overlay:
            extra -= cert[1]
        if extra > 1024:
            out.append(Finding("pe", "Appended overlay data", 1, f"{extra} bytes after last section"))

    pe.close()
    return out
